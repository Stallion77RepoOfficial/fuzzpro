#ifndef FUZZPRO_FORKSERVER_H
#define FUZZPRO_FORKSERVER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define FORKSERVER_MAP_SIZE (1 << 16)
#define FORKSERVER_SHM_ENV "__FUZZPRO_SHM_ID"

#define FORKSRV_FD_READ 198
#define FORKSRV_FD_WRITE 199

#define PERSISTENT_MAX_RUNS 1000
#define PERSISTENT_SIG "##SIG_FUZZPRO_PERSISTENT##"

typedef enum {
  FS_STATUS_NONE = 0,
  FS_STATUS_INITIALIZING,
  FS_STATUS_READY,
  FS_STATUS_RUNNING,
  FS_STATUS_STOPPED,
  FS_STATUS_ERROR
} ForkServerStatus;

typedef struct {
  const char *target_path;
  char **target_argv;
  char **target_envp;

  int timeout_ms;
  int mem_limit_mb;

  int use_persistent;
  int persistent_runs;

  int use_stdin;
  const char *input_file;

  uint8_t *trace_bits;
  size_t map_size;

  void (*on_crash)(int signal, uint64_t addr);
  void (*on_timeout)(void);

} ForkServerConfig;

typedef struct {
  ForkServerStatus status;

  pid_t child_pid;
  pid_t forksrv_pid;

  int ctrl_fd[2];
  int status_fd[2];

  int shm_id;
  uint8_t *trace_bits;

  uint64_t total_execs;
  uint64_t total_crashes;
  uint64_t total_timeouts;
  uint64_t execs_per_sec;

  uint64_t last_exec_us;
  uint64_t total_time_us;

  ForkServerConfig *config;

} ForkServer;

ForkServer *forkserver_create(ForkServerConfig *config);
int forkserver_start(ForkServer *fs);
int forkserver_run(ForkServer *fs, const uint8_t *input, size_t input_len,
                   int *exit_status);
int forkserver_check_crash(ForkServer *fs, int exit_status);
void forkserver_stop(ForkServer *fs);
void forkserver_destroy(ForkServer *fs);
uint8_t *forkserver_get_trace_bits(ForkServer *fs);
void forkserver_clear_trace(ForkServer *fs);
size_t forkserver_count_edges(ForkServer *fs);
void forkserver_get_stats(ForkServer *fs, uint64_t *execs, uint64_t *crashes,
                          uint64_t *timeouts, uint64_t *execs_per_sec);

void fs_coverage_classify_counts(uint8_t *trace_bits, size_t map_size);
int fs_coverage_has_new_bits(const uint8_t *trace_bits,
                             const uint8_t *virgin_bits, size_t map_size);
void fs_coverage_update_virgin(const uint8_t *trace_bits, uint8_t *virgin_bits,
                               size_t map_size);
uint32_t fs_coverage_hash(const uint8_t *trace_bits, size_t map_size);
double fs_coverage_percentage(const uint8_t *virgin_bits, size_t map_size);

#endif
