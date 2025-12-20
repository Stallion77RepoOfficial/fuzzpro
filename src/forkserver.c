#include "forkserver.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t get_time_us(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

static int setup_shm(ForkServer *fs) {
  fs->trace_bits = mmap(NULL, fs->config->map_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (fs->trace_bits == MAP_FAILED) {
    perror("[!] Failed to create shared memory");
    return -1;
  }
  memset(fs->trace_bits, 0, fs->config->map_size);
  fs->shm_id = 0;
  return 0;
}

static void cleanup_shm(ForkServer *fs) {
  if (fs->trace_bits && fs->trace_bits != MAP_FAILED) {
    munmap(fs->trace_bits, fs->config->map_size);
    fs->trace_bits = NULL;
  }
}

ForkServer *forkserver_create(ForkServerConfig *config) {
  if (!config || !config->target_path)
    return NULL;

  ForkServer *fs = calloc(1, sizeof(ForkServer));
  if (!fs)
    return NULL;

  fs->config = config;
  fs->status = FS_STATUS_NONE;
  fs->child_pid = -1;
  fs->forksrv_pid = -1;

  if (config->map_size == 0)
    config->map_size = FORKSERVER_MAP_SIZE;
  if (config->timeout_ms == 0)
    config->timeout_ms = 1000;
  if (config->mem_limit_mb == 0)
    config->mem_limit_mb = 256;
  if (config->persistent_runs == 0)
    config->persistent_runs = PERSISTENT_MAX_RUNS;

  if (setup_shm(fs) < 0) {
    free(fs);
    return NULL;
  }

  if (config->trace_bits == NULL)
    config->trace_bits = fs->trace_bits;

  fs->status = FS_STATUS_INITIALIZING;
  return fs;
}

void forkserver_destroy(ForkServer *fs) {
  if (!fs)
    return;
  forkserver_stop(fs);
  cleanup_shm(fs);
  free(fs);
}

int forkserver_start(ForkServer *fs) {
  if (!fs || fs->status == FS_STATUS_RUNNING)
    return -1;

  if (pipe(fs->ctrl_fd) < 0 || pipe(fs->status_fd) < 0) {
    perror("[!] Failed to create pipes");
    return -1;
  }

  fs->forksrv_pid = fork();
  if (fs->forksrv_pid < 0) {
    perror("[!] Fork failed");
    return -1;
  }

  if (fs->forksrv_pid == 0) {
    close(fs->ctrl_fd[1]);
    close(fs->status_fd[0]);

    if (dup2(fs->ctrl_fd[0], FORKSRV_FD_READ) < 0)
      _exit(1);
    if (dup2(fs->status_fd[1], FORKSRV_FD_WRITE) < 0)
      _exit(1);

    close(fs->ctrl_fd[0]);
    close(fs->status_fd[1]);

    struct rlimit r;
    r.rlim_cur = r.rlim_max = (rlim_t)fs->config->mem_limit_mb * 1024 * 1024;
    setrlimit(RLIMIT_AS, &r);

    execv(fs->config->target_path, fs->config->target_argv);
    _exit(1);
  }

  close(fs->ctrl_fd[0]);
  close(fs->status_fd[1]);

  int status = 0;
  struct timeval timeout;
  fd_set fds;

  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  FD_ZERO(&fds);
  FD_SET(fs->status_fd[0], &fds);

  int ret = select(fs->status_fd[0] + 1, &fds, NULL, NULL, &timeout);

  if (ret <= 0) {
    fprintf(stderr, "[!] Fork server handshake timeout\n");
    kill(fs->forksrv_pid, SIGKILL);
    waitpid(fs->forksrv_pid, NULL, 0);
    fs->forksrv_pid = -1;
    return -1;
  }

  if (read(fs->status_fd[0], &status, 4) != 4) {
    fprintf(stderr, "[!] Fork server handshake failed\n");
    kill(fs->forksrv_pid, SIGKILL);
    waitpid(fs->forksrv_pid, NULL, 0);
    fs->forksrv_pid = -1;
    return -1;
  }

  fs->status = FS_STATUS_READY;
  printf("[*] Fork server started (PID: %d)\n", fs->forksrv_pid);
  return 0;
}

void forkserver_stop(ForkServer *fs) {
  if (!fs)
    return;

  if (fs->child_pid > 0) {
    kill(fs->child_pid, SIGKILL);
    waitpid(fs->child_pid, NULL, 0);
    fs->child_pid = -1;
  }

  if (fs->forksrv_pid > 0) {
    kill(fs->forksrv_pid, SIGKILL);
    waitpid(fs->forksrv_pid, NULL, 0);
    fs->forksrv_pid = -1;
  }

  if (fs->ctrl_fd[1] >= 0) {
    close(fs->ctrl_fd[1]);
    fs->ctrl_fd[1] = -1;
  }
  if (fs->status_fd[0] >= 0) {
    close(fs->status_fd[0]);
    fs->status_fd[0] = -1;
  }

  fs->status = FS_STATUS_STOPPED;
}

int forkserver_run(ForkServer *fs, const uint8_t *input, size_t input_len,
                   int *exit_status) {
  if (!fs || !input || input_len == 0)
    return -1;

  uint64_t start_time = get_time_us();
  memset(fs->trace_bits, 0, fs->config->map_size);

  char input_file[] = "/tmp/fuzzpro_input_XXXXXX";
  int input_fd = mkstemp(input_file);
  if (input_fd < 0) {
    perror("[!] Failed to create input file");
    return -1;
  }

  write(input_fd, input, input_len);
  lseek(input_fd, 0, SEEK_SET);

  pid_t pid = fork();
  if (pid < 0) {
    close(input_fd);
    unlink(input_file);
    return -1;
  }

  if (pid == 0) {
    struct rlimit r;
    r.rlim_cur = r.rlim_max = (rlim_t)fs->config->mem_limit_mb * 1024 * 1024;
    setrlimit(RLIMIT_AS, &r);

    dup2(input_fd, STDIN_FILENO);
    close(input_fd);

    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    close(devnull);

    execv(fs->config->target_path, fs->config->target_argv);
    _exit(1);
  }

  close(input_fd);
  fs->child_pid = pid;

  int status = 0;
  int wait_result = 0;
  uint64_t timeout_us = (uint64_t)fs->config->timeout_ms * 1000;

  while ((get_time_us() - start_time) < timeout_us) {
    wait_result = waitpid(pid, &status, WNOHANG);
    if (wait_result > 0)
      break;
    else if (wait_result < 0) {
      unlink(input_file);
      return -1;
    }
    usleep(100);
  }

  if (wait_result == 0) {
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    fs->total_timeouts++;
    unlink(input_file);
    if (fs->config->on_timeout)
      fs->config->on_timeout();
    *exit_status = -1;
    return 1;
  }

  fs->total_execs++;
  fs->last_exec_us = get_time_us() - start_time;
  fs->total_time_us += fs->last_exec_us;

  if (fs->total_execs > 0) {
    fs->execs_per_sec = (fs->total_execs * 1000000ULL) / fs->total_time_us;
  }

  *exit_status = status;

  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    fs->total_crashes++;
    if (fs->config->on_crash)
      fs->config->on_crash(sig, 0);
  }

  unlink(input_file);
  fs->child_pid = -1;
  return 0;
}

int forkserver_check_crash(ForkServer *fs, int exit_status) {
  (void)fs;
  if (WIFSIGNALED(exit_status))
    return WTERMSIG(exit_status);
  return 0;
}

uint8_t *forkserver_get_trace_bits(ForkServer *fs) {
  return fs ? fs->trace_bits : NULL;
}

void forkserver_clear_trace(ForkServer *fs) {
  if (fs && fs->trace_bits)
    memset(fs->trace_bits, 0, fs->config->map_size);
}

size_t forkserver_count_edges(ForkServer *fs) {
  if (!fs || !fs->trace_bits)
    return 0;
  size_t count = 0;
  for (size_t i = 0; i < fs->config->map_size; i++) {
    if (fs->trace_bits[i])
      count++;
  }
  return count;
}

void forkserver_get_stats(ForkServer *fs, uint64_t *execs, uint64_t *crashes,
                          uint64_t *timeouts, uint64_t *execs_per_sec) {
  if (!fs)
    return;
  if (execs)
    *execs = fs->total_execs;
  if (crashes)
    *crashes = fs->total_crashes;
  if (timeouts)
    *timeouts = fs->total_timeouts;
  if (execs_per_sec)
    *execs_per_sec = fs->execs_per_sec;
}

static const uint8_t count_class_lookup[256] = {
    0,   1,   2,   4,   8,   8,   8,   8,   16,  16,  16,  16,  16,  16,  16,
    16,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128};

void fs_coverage_classify_counts(uint8_t *trace_bits, size_t map_size) {
  if (!trace_bits)
    return;
  for (size_t i = 0; i < map_size; i++) {
    trace_bits[i] = count_class_lookup[trace_bits[i]];
  }
}

int fs_coverage_has_new_bits(const uint8_t *trace_bits,
                             const uint8_t *virgin_bits, size_t map_size) {
  if (!trace_bits || !virgin_bits)
    return 0;
  int ret = 0;
  for (size_t i = 0; i < map_size; i++) {
    if (trace_bits[i] && (trace_bits[i] & virgin_bits[i])) {
      ret = (virgin_bits[i] == 0xFF) ? 2 : 1;
      if (ret == 2)
        break;
    }
  }
  return ret;
}

void fs_coverage_update_virgin(const uint8_t *trace_bits, uint8_t *virgin_bits,
                               size_t map_size) {
  if (!trace_bits || !virgin_bits)
    return;
  for (size_t i = 0; i < map_size; i++) {
    virgin_bits[i] &= ~trace_bits[i];
  }
}

uint32_t fs_coverage_hash(const uint8_t *trace_bits, size_t map_size) {
  if (!trace_bits)
    return 0;
  uint32_t hash = 0x811c9dc5;
  for (size_t i = 0; i < map_size; i++) {
    if (trace_bits[i]) {
      hash ^= trace_bits[i];
      hash *= 0x01000193;
    }
  }
  return hash;
}

double fs_coverage_percentage(const uint8_t *virgin_bits, size_t map_size) {
  if (!virgin_bits)
    return 0.0;
  size_t total_bits = map_size * 8;
  size_t covered = 0;
  for (size_t i = 0; i < map_size; i++) {
    uint8_t hit = ~virgin_bits[i];
    covered += __builtin_popcount(hit);
  }
  return (100.0 * covered) / total_bits;
}
