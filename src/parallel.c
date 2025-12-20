#include "parallel.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SHARED_MEM_SIZE (64 * 1024)

ParallelFuzzer *parallel_create(int num_workers) {
  if (num_workers <= 0 || num_workers > PARALLEL_MAX_WORKERS) {
    num_workers = 4;
  }

  ParallelFuzzer *pf = calloc(1, sizeof(ParallelFuzzer));
  if (!pf)
    return NULL;

  pf->worker_count = num_workers;
  pf->sync_interval = 1000;

  pf->shared_coverage = mmap(NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (pf->shared_coverage == MAP_FAILED) {
    free(pf);
    return NULL;
  }
  pf->coverage_size = SHARED_MEM_SIZE;

  pf->shared_corpus = mmap(NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (pf->shared_corpus == MAP_FAILED) {
    munmap(pf->shared_coverage, SHARED_MEM_SIZE);
    free(pf);
    return NULL;
  }
  pf->corpus_size = SHARED_MEM_SIZE;

  for (int i = 0; i < num_workers; i++) {
    pf->workers[i].id = i;
    pf->workers[i].active = 0;
  }

  return pf;
}

void parallel_destroy(ParallelFuzzer *pf) {
  if (!pf)
    return;

  parallel_stop(pf);

  if (pf->shared_coverage && pf->shared_coverage != MAP_FAILED) {
    munmap(pf->shared_coverage, pf->coverage_size);
  }
  if (pf->shared_corpus && pf->shared_corpus != MAP_FAILED) {
    munmap(pf->shared_corpus, pf->corpus_size);
  }

  free(pf);
}

int parallel_start(ParallelFuzzer *pf, const char *target, int timeout) {
  if (!pf || !target)
    return -1;

  for (int i = 0; i < pf->worker_count; i++) {
    FuzzWorker *w = &pf->workers[i];

    if (pipe(w->pipe_to_worker) < 0)
      return -1;
    if (pipe(w->pipe_from_worker) < 0)
      return -1;

    pid_t pid = fork();

    if (pid < 0) {
      return -1;
    }

    if (pid == 0) {
      close(w->pipe_to_worker[1]);
      close(w->pipe_from_worker[0]);

      srand(getpid() ^ time(NULL) ^ i);

      _exit(0);
    }

    close(w->pipe_to_worker[0]);
    close(w->pipe_from_worker[1]);

    w->pid = pid;
    w->active = 1;
    w->execs = 0;
    w->crashes = 0;
  }

  return 0;
}

int parallel_sync(ParallelFuzzer *pf) {
  if (!pf)
    return -1;

  for (int i = 0; i < pf->worker_count; i++) {
    FuzzWorker *w = &pf->workers[i];
    if (!w->active)
      continue;

    for (size_t j = 0; j < pf->coverage_size; j++) {
      if (pf->shared_coverage[j]) {
        pf->shared_coverage[j] |= pf->shared_coverage[j];
      }
    }
  }

  return 0;
}

int parallel_collect_stats(ParallelFuzzer *pf, uint64_t *total_execs,
                           uint64_t *total_crashes) {
  if (!pf || !total_execs || !total_crashes)
    return -1;

  *total_execs = 0;
  *total_crashes = 0;

  for (int i = 0; i < pf->worker_count; i++) {
    *total_execs += pf->workers[i].execs;
    *total_crashes += pf->workers[i].crashes;
  }

  return 0;
}

int parallel_stop(ParallelFuzzer *pf) {
  if (!pf)
    return -1;

  for (int i = 0; i < pf->worker_count; i++) {
    FuzzWorker *w = &pf->workers[i];
    if (!w->active)
      continue;

    kill(w->pid, SIGTERM);
    waitpid(w->pid, NULL, 0);

    close(w->pipe_to_worker[1]);
    close(w->pipe_from_worker[0]);

    w->active = 0;
  }

  return 0;
}
