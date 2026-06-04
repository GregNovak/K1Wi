#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "string_intel.h"
#include "opus_string_intel.h"
#include "cipher_io.h"

static opus_secret_confidence_t classify_secret_confidence(const char *type,
                                                           int score);
static void add_suspicious_hit(opus_string_report_t *report,
                               size_t offset,
                               const char *type,
                               const char *text,
                               opus_secret_confidence_t confidence,
                               int score);
                               
static int is_string_byte(uint8_t c)
{
    return (c >= 32 && c <= 126) || c == '\t';
}

static opus_secret_confidence_t classify_secret_confidence(const char *type,
                                                           int score)
{
    if (!type)
        return OPUS_SECRET_LOW;

    if (strstr(type, "AWS access key") ||
        strstr(type, "JWT token") ||
        strstr(type, "GitHub token") ||
        strstr(type, "OpenAI API key") ||
        strstr(type, "private key") ||
        strstr(type, "Private key") ||
        strstr(type, "Bearer token")) {
        return OPUS_SECRET_HIGH;
    }

    if (strstr(type, "SSH public key") ||
        strstr(type, "PEM certificate")) {
        return OPUS_SECRET_MEDIUM;
    }

    if (strstr(type, "Key/value secret")) {
       if (score >= 85)
	   return OPUS_SECRET_HIGH;
       if (score >= 60)
	   return OPUS_SECRET_MEDIUM;
       return OPUS_SECRET_LOW;
    }


    if (strstr(type, "Possible credential")) {
        if (score >= 85)
            return OPUS_SECRET_HIGH;
        if (score >= 60)
            return OPUS_SECRET_MEDIUM;
        return OPUS_SECRET_LOW;
    }
    
    if (strstr(type, "Secret phrase")) {
    if (score >= 85)
        return OPUS_SECRET_HIGH;
    if (score >= 60)
        return OPUS_SECRET_MEDIUM;
    return OPUS_SECRET_LOW;
}

    return OPUS_SECRET_LOW;
}
static void update_string_report(opus_string_report_t *report,
                                 const OpusStringIntelResult *r,
                                 size_t offset,
                                 const char *text)
{
    if (!report || !r) return;

    if (r->is_printable)
        report->ascii_count++;

    if (!r->detected_type)
        return;

    if (strcmp(r->detected_type, "UTF-8 text") == 0 ||
        strcmp(r->detected_type, "UTF-8 text") == 0) {
        report->utf8_count++;
    }
    else if (strcmp(r->detected_type, "Base64") == 0) {
        report->base64_count++;
    }
    else if (strcmp(r->detected_type, "URL") == 0 ||
             strcmp(r->detected_type, "URL encoded") == 0) {
        report->url_count++;
    }
    else if (strcmp(r->detected_type, "Email") == 0) {
        report->email_count++;
    }
    else if (strstr(r->detected_type, "private key") ||
		 strstr(r->detected_type, "Private key") ||
		 strstr(r->detected_type, "AWS access key") ||
		 strstr(r->detected_type, "JWT token") ||
		 strstr(r->detected_type, "GitHub token") ||
		 strstr(r->detected_type, "SSH public key")||
		 strstr(r->detected_type, "PEM certificate")||
		 strstr(r->detected_type, "OpenAI API key") ||
		 strstr(r->detected_type, "Bearer token") ||
		 strstr(r->detected_type, "Possible credential") ||
		 strstr(r->detected_type, "Key/value secret") ||
		 strstr(r->detected_type, "Secret phrase"))  {
	    report->suspicious_count++;
		add_suspicious_hit(report,
                   offset,
                   r->detected_type,
                   text,
                   classify_secret_confidence(r->detected_type,
                                              r->secret_score),
                   r->secret_score);
   }
	     
     
    if (r->decoded_output)
        free(r->decoded_output);
}
static void add_suspicious_hit(opus_string_report_t *report,
                               size_t offset,
                               const char *type,
                               const char *text,
                               opus_secret_confidence_t confidence,
                               int score)
{
    if (!report || !type || !text)
        return;

    if (report->suspicious_hit_count >= OPUS_MAX_STRING_HITS)
        return;

    opus_string_hit_t *hit =
        &report->suspicious_hits[report->suspicious_hit_count++];

    hit->offset = offset;
    hit->confidence = confidence;
    hit->score = score;

    snprintf(hit->type, sizeof(hit->type), "%s", type);
    snprintf(hit->text, sizeof(hit->text), "%s", text);
}

int opus_string_file(const char *path, opus_string_report_t *report)
{
    if (!path || !report)
        return -1;

    memset(report, 0, sizeof(*report));

    size_t size = 0;
    uint8_t *buf = opus_load_entire_file(path, &size);
    if (!buf)
        return -1;

    const size_t min_len = 4;

    size_t i = 0;
    while (i < size) {
        while (i < size && !is_string_byte(buf[i]))
            i++;

        size_t start = i;

        while (i < size && is_string_byte(buf[i]))
            i++;

        size_t len = i - start;

        if (len >= min_len) {
            char *s = malloc(len + 1);
            if (!s) {
                free(buf);
                return -1;
            }

            memcpy(s, buf + start, len);
            s[len] = '\0';

            OpusStringIntelResult r = opus_string_intel(s);
            update_string_report(report, &r, start, s);

            free(s);
        }
    }

    free(buf);
    return 0;
}
