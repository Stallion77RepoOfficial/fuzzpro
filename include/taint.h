#ifndef FUZZPRO_TAINT_H
#define FUZZPRO_TAINT_H

#include <stddef.h>
#include <stdint.h>

#define TAINT_MAX_BYTES 4096
#define TAINT_MAX_REGS 32

typedef struct {
  uint8_t tainted[TAINT_MAX_BYTES];
  uint8_t reg_taint[TAINT_MAX_REGS];
  size_t input_offset;
  size_t input_len;
} TaintState;

typedef struct {
  uint64_t addr;
  int reg;
  size_t input_byte;
  int propagated;
} TaintFlow;

typedef struct {
  TaintFlow *flows;
  size_t count;
  size_t capacity;
} TaintLog;

TaintState *taint_create(void);
void taint_destroy(TaintState *ts);
void taint_reset(TaintState *ts);
void taint_mark_input(TaintState *ts, size_t offset, size_t len);
int taint_is_tainted_mem(TaintState *ts, size_t offset);
int taint_is_tainted_reg(TaintState *ts, int reg);
void taint_propagate_load(TaintState *ts, int dst_reg, size_t mem_offset);
void taint_propagate_store(TaintState *ts, int src_reg, size_t mem_offset);
void taint_propagate_mov(TaintState *ts, int dst_reg, int src_reg);
void taint_propagate_binop(TaintState *ts, int dst_reg, int src1, int src2);
void taint_clear_reg(TaintState *ts, int reg);
TaintLog *taintlog_create(size_t capacity);
void taintlog_destroy(TaintLog *log);
void taintlog_add(TaintLog *log, uint64_t addr, int reg, size_t input_byte);

#endif
