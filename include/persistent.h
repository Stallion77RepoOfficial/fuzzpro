#ifndef FUZZPRO_PERSISTENT_H
#define FUZZPRO_PERSISTENT_H

#include <stddef.h>
#include <stdint.h>

#define PERSISTENT_DEFAULT_RUNS 1000
#define PERSISTENT_SHM_SIZE (1 << 20)
#define PERSISTENT_INPUT_MAX (1 << 16)

#define PERSISTENT_STATUS_OK 0
#define PERSISTENT_STATUS_CRASH 1
#define PERSISTENT_STATUS_TIMEOUT 2
#define PERSISTENT_STATUS_DONE 3

typedef struct {
  volatile uint32_t status;
  volatile uint32_t input_size;
  volatile uint32_t run_count;
  volatile uint32_t max_runs;
  uint8_t input_data[PERSISTENT_INPUT_MAX];
} PersistentShm;

typedef struct {
  int enabled;
  int runs_per_fork;
  int current_run;
  PersistentShm *shm;
  int shm_fd;
  uint8_t *trace_bits;
  size_t map_size;
} PersistentState;

int persistent_init(PersistentState *ps, int runs_per_fork, uint8_t *trace_bits,
                    size_t map_size);
void persistent_cleanup(PersistentState *ps);
void persistent_start_child(PersistentState *ps);
int persistent_loop_start(PersistentState *ps, uint8_t **input,
                          size_t *input_len);
void persistent_loop_end(PersistentState *ps);
int persistent_should_restart(PersistentState *ps);

#ifdef FUZZPRO_PERSISTENT_HARNESS

#define FUZZPRO_LOOP_START()                                                   \
  static PersistentState __ps;                                                 \
  static int __ps_init = 0;                                                    \
  if (!__ps_init) {                                                            \
    persistent_init(&__ps, PERSISTENT_DEFAULT_RUNS, NULL, 0);                  \
    __ps_init = 1;                                                             \
  }                                                                            \
  uint8_t *__input;                                                            \
  size_t __input_len;                                                          \
  while (persistent_loop_start(&__ps, &__input, &__input_len))

#define FUZZPRO_LOOP_END() persistent_loop_end(&__ps)

#define FUZZPRO_INPUT (__input)
#define FUZZPRO_INPUT_LEN (__input_len)

#endif

#endif
