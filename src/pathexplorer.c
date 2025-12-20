#include "pathexplorer.h"
#include "arm64dis.h"
#include <stdlib.h>
#include <string.h>

PathExplorer *pathexp_create(const uint8_t *code, size_t len, uint64_t base) {
  PathExplorer *pe = calloc(1, sizeof(PathExplorer));
  if (!pe)
    return NULL;

  pe->code = code;
  pe->code_len = len;
  pe->code_base = base;
  pe->max_depth = PATH_MAX_DEPTH;

  return pe;
}

void pathexp_destroy(PathExplorer *pe) {
  if (!pe)
    return;

  for (size_t i = 0; i < PATH_MAX_STATES; i++) {
    if (pe->states[i]) {
      sym_state_destroy(pe->states[i]->state);
      free(pe->states[i]->input);
      free(pe->states[i]);
    }
  }
  free(pe);
}

int pathexp_set_target(PathExplorer *pe, uint64_t addr) {
  if (!pe)
    return -1;
  pe->target_addr = addr;
  return 0;
}

int pathexp_add_initial_state(PathExplorer *pe, uint8_t *input, size_t len) {
  if (!pe || pe->active_count >= PATH_MAX_STATES)
    return -1;

  PathState *ps = calloc(1, sizeof(PathState));
  if (!ps)
    return -1;

  ps->state = sym_state_create();
  if (!ps->state) {
    free(ps);
    return -1;
  }

  ps->pc = pe->code_base;
  ps->depth = 0;
  ps->status = PATH_ACTIVE;

  if (input && len > 0) {
    ps->input = malloc(len);
    if (ps->input) {
      memcpy(ps->input, input, len);
      ps->input_len = len;
    }
  }

  for (size_t i = 0; i < PATH_MAX_STATES; i++) {
    if (!pe->states[i]) {
      pe->states[i] = ps;
      pe->active_count++;
      return 0;
    }
  }

  sym_state_destroy(ps->state);
  free(ps->input);
  free(ps);
  return -1;
}

static PathState *pathexp_fork_state(PathExplorer *pe, PathState *parent,
                                     uint64_t new_pc) {
  if (!pe || !parent || pe->active_count >= PATH_MAX_STATES)
    return NULL;

  PathState *ps = calloc(1, sizeof(PathState));
  if (!ps)
    return NULL;

  ps->state = sym_state_create();
  if (!ps->state) {
    free(ps);
    return NULL;
  }

  sym_state_clone(ps->state, parent->state);
  ps->pc = new_pc;
  ps->depth = parent->depth + 1;
  ps->status = PATH_ACTIVE;

  if (parent->input && parent->input_len > 0) {
    ps->input = malloc(parent->input_len);
    if (ps->input) {
      memcpy(ps->input, parent->input, parent->input_len);
      ps->input_len = parent->input_len;
    }
  }

  for (size_t i = 0; i < PATH_MAX_STATES; i++) {
    if (!pe->states[i]) {
      pe->states[i] = ps;
      pe->active_count++;
      return ps;
    }
  }

  sym_state_destroy(ps->state);
  free(ps->input);
  free(ps);
  return NULL;
}

int pathexp_step(PathExplorer *pe) {
  if (!pe)
    return -1;

  int stepped = 0;

  for (size_t i = 0; i < PATH_MAX_STATES; i++) {
    PathState *ps = pe->states[i];
    if (!ps || ps->status != PATH_ACTIVE)
      continue;

    if (ps->depth >= pe->max_depth) {
      ps->status = PATH_TIMEOUT;
      pe->active_count--;
      continue;
    }

    if (ps->pc == pe->target_addr) {
      ps->status = PATH_FOUND;
      pe->found_count++;
      pe->active_count--;
      continue;
    }

    if (ps->pc < pe->code_base || ps->pc >= pe->code_base + pe->code_len) {
      ps->status = PATH_DEADEND;
      pe->active_count--;
      continue;
    }

    size_t off = ps->pc - pe->code_base;
    uint32_t raw = *(uint32_t *)(pe->code + off);

    A64Instruction insn = {0};
    a64_decode(raw, ps->pc, &insn);

    if (insn.opcode == A64_B_COND || insn.opcode == A64_CBZ ||
        insn.opcode == A64_CBNZ) {
      uint64_t taken = ps->pc + insn.operands[0].imm;
      uint64_t not_taken = ps->pc + 4;

      pathexp_fork_state(pe, ps, taken);
      ps->pc = not_taken;
      ps->depth++;
    } else if (insn.opcode == A64_B) {
      ps->pc = ps->pc + insn.operands[0].imm;
      ps->depth++;
    } else if (insn.opcode == A64_RET) {
      ps->status = PATH_DEADEND;
      pe->active_count--;
    } else {
      ps->pc += 4;
      ps->depth++;
    }

    pe->explored_count++;
    stepped++;
  }

  return stepped;
}

int pathexp_run(PathExplorer *pe, int max_steps) {
  if (!pe)
    return -1;

  for (int i = 0; i < max_steps && pe->active_count > 0; i++) {
    if (pathexp_step(pe) <= 0 && pe->active_count == 0)
      break;

    if (pe->found_count > 0)
      break;
  }

  return (int)pe->found_count;
}

PathState *pathexp_get_solution(PathExplorer *pe) {
  if (!pe)
    return NULL;

  for (size_t i = 0; i < PATH_MAX_STATES; i++) {
    if (pe->states[i] && pe->states[i]->status == PATH_FOUND) {
      return pe->states[i];
    }
  }
  return NULL;
}

int pathexp_get_input_for_path(PathExplorer *pe, PathState *ps, uint8_t *out,
                               size_t max_len) {
  if (!pe || !ps || !out)
    return -1;

  SolverResult result;
  if (!sym_solve(&ps->state->constraints, &result)) {
    return -1;
  }

  if (!result.satisfiable) {
    return -1;
  }

  if (ps->input && ps->input_len > 0) {
    size_t copy_len = ps->input_len < max_len ? ps->input_len : max_len;
    memcpy(out, ps->input, copy_len);

    for (size_t i = 0; i < result.count; i++) {
      int var_id = result.solutions[i].var_id;
      uint64_t val = result.solutions[i].value;

      if ((size_t)var_id < copy_len) {
        out[var_id] = val & 0xFF;
      }
    }

    return (int)copy_len;
  }

  return 0;
}

void sym_state_clone(SymState *dst, SymState *src) {
  if (!dst || !src)
    return;

  for (int i = 0; i < 32; i++) {
    if (src->regs[i]) {
      if (sym_is_concrete(src->regs[i])) {
        dst->regs[i] = sym_const(sym_get_concrete(src->regs[i]), 64);
      } else {
        dst->regs[i] = src->regs[i];
      }
    }
  }

  dst->var_counter = src->var_counter;
  memcpy(dst->mem_concrete, src->mem_concrete, SYM_MAX_MEMORY);
}
