// task_pool.c - minimal pthread worker pool
#define _POSIX_C_SOURCE 200809L
#include "task_pool.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct Task {
    task_fn fn;
    void *ctx;
    task_done_fn done;
    task_progress_fn progress;
    struct Task *next;
} Task;

static Task *head = NULL;
static Task *tail = NULL;
static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcond = PTHREAD_COND_INITIALIZER;
static int running = 0;
static int cancel_flag = 0;
static size_t worker_count = 0;
static pthread_t *workers = NULL;

static void *worker_main(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&qlock);
        while (!head && running) pthread_cond_wait(&qcond, &qlock);
        if (!running && !head) {
            pthread_mutex_unlock(&qlock);
            break;
        }
        Task *t = head;
        head = head->next;
        if (!head) tail = NULL;
        pthread_mutex_unlock(&qlock);

        if (cancel_flag) {
            if (t->done) t->done(t->ctx, 2); // cancelled
            free(t);
            continue;
        }

        t->fn(t->ctx);
        if (t->done) t->done(t->ctx, 0);
        free(t);
    }
    return NULL;
}

int pool_init(size_t num_workers) {
    if (num_workers == 0) return -1;
    pthread_mutex_lock(&qlock);
    if (running) { pthread_mutex_unlock(&qlock); return -1; }
    running = 1;
    cancel_flag = 0;
    worker_count = num_workers;
    workers = calloc(num_workers, sizeof(pthread_t));
    pthread_mutex_unlock(&qlock);

    for (size_t i = 0; i < num_workers; ++i) {
        if (pthread_create(&workers[i], NULL, worker_main, NULL) != 0) {
            pool_shutdown();
            return -1;
        }
    }
    return 0;
}

int pool_submit(task_fn fn, void *ctx, task_done_fn done, task_progress_fn progress) {
    if (!fn) return -1;
    Task *t = malloc(sizeof(Task));
    if (!t) return -1;
    t->fn = fn; t->ctx = ctx; t->done = done; t->progress = progress; t->next = NULL;

    pthread_mutex_lock(&qlock);
    if (!running) { pthread_mutex_unlock(&qlock); free(t); return -1; }
    if (tail) tail->next = t; else head = t;
    tail = t;
    pthread_cond_signal(&qcond);
    pthread_mutex_unlock(&qlock);
    return 0;
}

int pool_cancel_all(void) {
    pthread_mutex_lock(&qlock);
    cancel_flag = 1;
    int cancelled = 0;
    Task *t = head;
    while (t) { cancelled++; t = t->next; }
    while (head) { Task *tmp = head; head = head->next; free(tmp); }
    tail = NULL;
    pthread_mutex_unlock(&qlock);
    return cancelled;
}

void pool_shutdown(void) {
    pthread_mutex_lock(&qlock);
    running = 0;
    pthread_cond_broadcast(&qcond);
    pthread_mutex_unlock(&qlock);

    if (workers) {
        for (size_t i = 0; i < worker_count; ++i) pthread_join(workers[i], NULL);
        free(workers);
        workers = NULL;
    }

    pthread_mutex_lock(&qlock);
    while (head) { Task *tmp = head; head = head->next; free(tmp); }
    tail = NULL;
    pthread_mutex_unlock(&qlock);
}

