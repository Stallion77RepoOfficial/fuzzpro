#ifndef FUZZPRO_PATHEXPLORER_H
#define FUZZPRO_PATHEXPLORER_H

#include "symbolic.h"
#include <stddef.h>
#include <stdint.h>

#define PATH_MAX_STATES 256
#define PATH_MAX_DEPTH 100

typedef enum {
  PATH_ACTIVE = 0,
  PATH_DEADEND,
  PATH_FOUND,
  PATH_TIMEOUT
} PathStatus;

typedef struct {
  SymState *state;
  uint64_t pc;
  int depth;
  PathStatus status;
  uint8_t *input;
  size_t input_len;
} PathState;

typedef struct {
  PathState *states[PATH_MAX_STATES];
  size_t active_count;
  size_t explored_count;
  size_t found_count;
  const uint8_t *code;
  size_t code_len;
  uint64_t code_base;
  uint64_t target_addr;
  int max_depth;
} PathExplorer;

PathExplorer *pathexp_create(const uint8_t *code, size_t len, uint64_t base);
void pathexp_destroy(PathExplorer *pe);
int pathexp_set_target(PathExplorer *pe, uint64_t addr);
int pathexp_add_initial_state(PathExplorer *pe, uint8_t *input, size_t len);
int pathexp_step(PathExplorer *pe);
int pathexp_run(PathExplorer *pe, int max_steps);
PathState *pathexp_get_solution(PathExplorer *pe);
int pathexp_get_input_for_path(PathExplorer *pe, PathState *ps, uint8_t *out,
                               size_t max_len);

#endif
