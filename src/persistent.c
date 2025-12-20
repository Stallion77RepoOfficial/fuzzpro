#include "persistent.h"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile int persistent_running = 0;

static void persistent_signal_handler(int sig) {
  (void)sig;
  persistent_running = 0;
}

int persistent_init(PersistentState *ps, int runs_per_fork, uint8_t *trace_bits,
                    size_t map_size) {
  if (!ps)
    return -1;

  memset(ps, 0, sizeof(*ps));
  ps->runs_per_fork =
      runs_per_fork > 0 ? runs_per_fork : PERSISTENT_DEFAULT_RUNS;
  ps->trace_bits = trace_bits;
  ps->map_size = map_size;

  ps->shm = mmap(NULL, sizeof(PersistentShm), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (ps->shm == MAP_FAILED) {
    perror("[!] persistent mmap failed");
    return -1;
  }

  memset((void *)ps->shm, 0, sizeof(PersistentShm));
  ps->shm->max_runs = ps->runs_per_fork;
  ps->enabled = 1;

  signal(SIGTERM, persistent_signal_handler);

  return 0;
}

void persistent_cleanup(PersistentState *ps) {
  if (!ps)
    return;
  if (ps->shm && ps->shm != MAP_FAILED) {
    munmap(ps->shm, sizeof(PersistentShm));
  }
  memset(ps, 0, sizeof(*ps));
}

void persistent_start_child(PersistentState *ps) {
  if (!ps || !ps->shm)
    return;
  persistent_running = 1;
  ps->current_run = 0;
}

int persistent_loop_start(PersistentState *ps, uint8_t **input,
                          size_t *input_len) {
  if (!ps || !ps->shm || !persistent_running)
    return 0;

  if (ps->current_run >= ps->runs_per_fork) {
    ps->shm->status = PERSISTENT_STATUS_DONE;
    return 0;
  }

  while (ps->shm->input_size == 0 && persistent_running) {
    usleep(10);
  }

  if (!persistent_running)
    return 0;

  if (input)
    *input = (uint8_t *)ps->shm->input_data;
  if (input_len)
    *input_len = ps->shm->input_size;

  if (ps->trace_bits && ps->map_size > 0) {
    memset(ps->trace_bits, 0, ps->map_size);
  }

  return 1;
}

void persistent_loop_end(PersistentState *ps) {
  if (!ps || !ps->shm)
    return;

  ps->current_run++;
  ps->shm->run_count = ps->current_run;
  ps->shm->input_size = 0;
  ps->shm->status = PERSISTENT_STATUS_OK;
}

int persistent_should_restart(PersistentState *ps) {
  if (!ps)
    return 1;
  return ps->current_run >= ps->runs_per_fork;
}

int persistent_run_target(PersistentState *ps, const uint8_t *input,
                          size_t input_len, int *status) {
  if (!ps || !ps->shm || !input)
    return -1;

  if (input_len > PERSISTENT_INPUT_MAX) {
    input_len = PERSISTENT_INPUT_MAX;
  }

  memcpy((void *)ps->shm->input_data, input, input_len);
  ps->shm->input_size = input_len;
  ps->shm->status = PERSISTENT_STATUS_OK;

  while (ps->shm->input_size != 0) {
    usleep(10);
    if (ps->shm->status == PERSISTENT_STATUS_CRASH) {
      if (status)
        *status = 1;
      return 1;
    }
    if (ps->shm->status == PERSISTENT_STATUS_DONE) {
      if (status)
        *status = 0;
      return 2;
    }
  }

  if (status)
    *status = 0;
  return 0;
}
