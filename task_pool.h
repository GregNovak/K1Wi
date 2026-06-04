// task_pool.h - simple thread pool for Opus
#ifndef TASK_POOL_H
#define TASK_POOL_H

#include <stddef.h>

typedef void (*task_fn)(void *ctx);
typedef void (*task_done_fn)(void *ctx, int result);
typedef void (*task_progress_fn)(void *ctx, const char *msg);

int pool_init(size_t num_workers);
int pool_submit(task_fn fn, void *ctx, task_done_fn done, task_progress_fn progress);
int pool_cancel_all(void);
void pool_shutdown(void);

#endif // TASK_POOL_H

