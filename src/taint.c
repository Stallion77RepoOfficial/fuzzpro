#include "taint.h"
#include <stdlib.h>
#include <string.h>

TaintState *taint_create(void) {
  TaintState *ts = calloc(1, sizeof(TaintState));
  return ts;
}

void taint_destroy(TaintState *ts) { free(ts); }

void taint_reset(TaintState *ts) {
  if (ts) {
    memset(ts->tainted, 0, TAINT_MAX_BYTES);
    memset(ts->reg_taint, 0, TAINT_MAX_REGS);
  }
}

void taint_mark_input(TaintState *ts, size_t offset, size_t len) {
  if (!ts)
    return;
  ts->input_offset = offset;
  ts->input_len = len;
  for (size_t i = 0; i < len && offset + i < TAINT_MAX_BYTES; i++) {
    ts->tainted[offset + i] = 1;
  }
}

int taint_is_tainted_mem(TaintState *ts, size_t offset) {
  if (!ts || offset >= TAINT_MAX_BYTES)
    return 0;
  return ts->tainted[offset];
}

int taint_is_tainted_reg(TaintState *ts, int reg) {
  if (!ts || reg < 0 || reg >= TAINT_MAX_REGS)
    return 0;
  return ts->reg_taint[reg];
}

void taint_propagate_load(TaintState *ts, int dst_reg, size_t mem_offset) {
  if (!ts || dst_reg < 0 || dst_reg >= TAINT_MAX_REGS)
    return;
  if (mem_offset < TAINT_MAX_BYTES) {
    ts->reg_taint[dst_reg] = ts->tainted[mem_offset];
  } else {
    ts->reg_taint[dst_reg] = 0;
  }
}

void taint_propagate_store(TaintState *ts, int src_reg, size_t mem_offset) {
  if (!ts || src_reg < 0 || src_reg >= TAINT_MAX_REGS)
    return;
  if (mem_offset < TAINT_MAX_BYTES) {
    ts->tainted[mem_offset] = ts->reg_taint[src_reg];
  }
}

void taint_propagate_mov(TaintState *ts, int dst_reg, int src_reg) {
  if (!ts)
    return;
  if (dst_reg < 0 || dst_reg >= TAINT_MAX_REGS)
    return;
  if (src_reg < 0 || src_reg >= TAINT_MAX_REGS) {
    ts->reg_taint[dst_reg] = 0;
    return;
  }
  ts->reg_taint[dst_reg] = ts->reg_taint[src_reg];
}

void taint_propagate_binop(TaintState *ts, int dst_reg, int src1, int src2) {
  if (!ts || dst_reg < 0 || dst_reg >= TAINT_MAX_REGS)
    return;

  int t1 = (src1 >= 0 && src1 < TAINT_MAX_REGS) ? ts->reg_taint[src1] : 0;
  int t2 = (src2 >= 0 && src2 < TAINT_MAX_REGS) ? ts->reg_taint[src2] : 0;

  ts->reg_taint[dst_reg] = t1 | t2;
}

void taint_clear_reg(TaintState *ts, int reg) {
  if (!ts || reg < 0 || reg >= TAINT_MAX_REGS)
    return;
  ts->reg_taint[reg] = 0;
}

TaintLog *taintlog_create(size_t capacity) {
  TaintLog *log = calloc(1, sizeof(TaintLog));
  if (!log)
    return NULL;
  log->flows = calloc(capacity, sizeof(TaintFlow));
  if (!log->flows) {
    free(log);
    return NULL;
  }
  log->capacity = capacity;
  return log;
}

void taintlog_destroy(TaintLog *log) {
  if (!log)
    return;
  free(log->flows);
  free(log);
}

void taintlog_add(TaintLog *log, uint64_t addr, int reg, size_t input_byte) {
  if (!log || log->count >= log->capacity)
    return;
  TaintFlow *f = &log->flows[log->count++];
  f->addr = addr;
  f->reg = reg;
  f->input_byte = input_byte;
  f->propagated = 1;
}
