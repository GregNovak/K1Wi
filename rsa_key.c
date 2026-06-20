#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex_line(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void print_ascii_safe(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];

        if (c == '\n' || c == '\r' || c == '\t') {
            putchar((int)c);
        } else if (isprint(c)) {
            putchar((int)c);
        } else {
            putchar('.');
        }
    }
    printf("\n");
}

static unsigned char *read_file_bytes(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("RSA-KEY: failed to open ciphertext file");
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        perror("RSA-KEY: fseek failed");
        return NULL;
    }

    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        perror("RSA-KEY: ftell failed");
        return NULL;
    }

    rewind(fp);

    if (sz == 0) {
        fclose(fp);
        fprintf(stderr, "RSA-KEY: ciphertext file is empty\n");
        return NULL;
    }

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "RSA-KEY: out of memory\n");
        return NULL;
    }

    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if (got != (size_t)sz) {
        free(buf);
        fprintf(stderr, "RSA-KEY: failed to read ciphertext file\n");
        return NULL;
    }

    *out_len = got;
    return buf;
}

static EVP_PKEY *load_private_key(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("RSA-KEY: failed to open private key");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "RSA-KEY: failed to parse PEM private key\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return pkey;
}

int cmd_rsa_key(int argc, char **argv)
{
    const char *key_path = NULL;
    const char *cipher_path = NULL;

    /*
     * Supports both call styles:
     *   CLI dispatcher:   argv[0]=key,     argv[1]=cipher
     *   Shell dispatcher: argv[0]=RSA-KEY, argv[1]=key, argv[2]=cipher
     */
    if (argc >= 3 && strcmp(argv[0], "RSA-KEY") == 0) {
        key_path = argv[1];
        cipher_path = argv[2];
    } else if (argc >= 2) {
        key_path = argv[0];
        cipher_path = argv[1];
    } else {
        fprintf(stderr, "Usage: RSA-KEY <private_key.pem> <ciphertext_file>\n");
        return 1;
    }

    printf("[*] RSA-KEY: loading private key\n");

    EVP_PKEY *pkey = load_private_key(key_path);
    if (!pkey) {
        return 1;
    }

    size_t cipher_len = 0;
    unsigned char *cipher = read_file_bytes(cipher_path, &cipher_len);
    if (!cipher) {
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("[*] RSA-KEY: loaded ciphertext (%zu bytes)\n", cipher_len);
    printf("[*] RSA-KEY: decrypting ciphertext file\n");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "RSA-KEY: failed to create EVP context\n");
        ERR_print_errors_fp(stderr);
        free(cipher);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "RSA-KEY: decrypt init failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        free(cipher);
        EVP_PKEY_free(pkey);
        return 1;
    }

    /*
     * CTF RSA files commonly use PKCS#1 v1.5 padding when generated
     * with openssl rsautl / pkeyutl defaults. This matches StegoRSA.
     */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "RSA-KEY: failed to set RSA PKCS#1 padding\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        free(cipher);
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t plain_len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &plain_len, cipher, cipher_len) <= 0) {
        fprintf(stderr, "RSA-KEY: decrypt sizing failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        free(cipher);
        EVP_PKEY_free(pkey);
        return 1;
    }

    unsigned char *plain = malloc(plain_len + 1);
    if (!plain) {
        fprintf(stderr, "RSA-KEY: out of memory\n");
        EVP_PKEY_CTX_free(ctx);
        free(cipher);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (EVP_PKEY_decrypt(ctx, plain, &plain_len, cipher, cipher_len) <= 0) {
        fprintf(stderr, "RSA-KEY: decrypt failed\n");
        ERR_print_errors_fp(stderr);
        free(plain);
        EVP_PKEY_CTX_free(ctx);
        free(cipher);
        EVP_PKEY_free(pkey);
        return 1;
    }

    plain[plain_len] = '\0';

    printf("[+] RSA-KEY: decrypt success\n");
    printf("Plaintext (hex): ");
    print_hex_line(plain, plain_len);

    printf("Plaintext (ASCII): ");
    print_ascii_safe(plain, plain_len);

    free(plain);
    EVP_PKEY_CTX_free(ctx);
    free(cipher);
    EVP_PKEY_free(pkey);

    return 0;
}
