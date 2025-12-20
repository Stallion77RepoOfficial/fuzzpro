#ifndef FUZZPRO_PARALLEL_H
#define FUZZPRO_PARALLEL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PARALLEL_MAX_WORKERS 16

typedef struct {
  int id;
  int pipe_to_worker[2];
  int pipe_from_worker[2];
  pid_t pid;
  uint64_t execs;
  uint64_t crashes;
  int active;
} FuzzWorker;

typedef struct {
  FuzzWorker workers[PARALLEL_MAX_WORKERS];
  int worker_count;
  uint8_t *shared_corpus;
  size_t corpus_size;
  uint8_t *shared_coverage;
  size_t coverage_size;
  int sync_interval;
} ParallelFuzzer;

ParallelFuzzer *parallel_create(int num_workers);
void parallel_destroy(ParallelFuzzer *pf);
int parallel_start(ParallelFuzzer *pf, const char *target, int timeout);
int parallel_sync(ParallelFuzzer *pf);
int parallel_collect_stats(ParallelFuzzer *pf, uint64_t *total_execs,
                           uint64_t *total_crashes);
int parallel_stop(ParallelFuzzer *pf);

#endif
