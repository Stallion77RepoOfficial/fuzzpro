#ifndef FUZZPRO_DECOMPILE_H
#define FUZZPRO_DECOMPILE_H

#include <stddef.h>
#include <stdint.h>

#define IR_MAX_OPERANDS 4
#define IR_MAX_INSNS 4096
#define IR_MAX_VARS 256

typedef enum {
  IR_NOP = 0,
  IR_MOV,
  IR_ADD,
  IR_SUB,
  IR_MUL,
  IR_DIV,
  IR_MOD,
  IR_AND,
  IR_OR,
  IR_XOR,
  IR_NOT,
  IR_SHL,
  IR_SHR,
  IR_SAR,
  IR_LOAD8,
  IR_LOAD16,
  IR_LOAD32,
  IR_LOAD64,
  IR_STORE8,
  IR_STORE16,
  IR_STORE32,
  IR_STORE64,
  IR_CMP,
  IR_TEST,
  IR_JMP,
  IR_JCC,
  IR_CALL,
  IR_RET,
  IR_PHI,
  IR_ZEXT,
  IR_SEXT,
  IR_TRUNC
} IROp;

typedef enum { OP_NONE = 0, OP_REG, OP_IMM, OP_VAR, OP_MEM, OP_LABEL } OpType;

typedef struct {
  OpType type;
  union {
    int reg;
    int64_t imm;
    int var_id;
    uint64_t addr;
    int label;
  };
  int size;
} IROperand;

typedef struct {
  IROp op;
  IROperand dst;
  IROperand src[IR_MAX_OPERANDS - 1];
  int src_count;
  uint64_t addr;
  int bb_id;
} IRInsn;

typedef struct {
  int id;
  char name[32];
  int size;
  int is_param;
  int is_local;
  int stack_offset;
} IRVar;

typedef struct {
  int id;
  uint64_t start;
  uint64_t end;
  int *successors;
  int succ_count;
  int *predecessors;
  int pred_count;
} IRBB;

typedef struct {
  IRInsn insns[IR_MAX_INSNS];
  size_t insn_count;
  IRVar vars[IR_MAX_VARS];
  size_t var_count;
  IRBB *bbs;
  size_t bb_count;
  uint64_t func_start;
  uint64_t func_end;
  char func_name[64];
} IRFunction;

typedef struct {
  IRFunction *funcs;
  size_t func_count;
  size_t func_capacity;
} DecompileContext;

DecompileContext *decompile_create(void);
void decompile_destroy(DecompileContext *ctx);
int decompile_lift_function(DecompileContext *ctx, const uint8_t *code,
                            size_t len, uint64_t start, uint64_t end);
int decompile_to_c(DecompileContext *ctx, IRFunction *fn, char *output,
                   size_t max_len);
IRFunction *decompile_get_function(DecompileContext *ctx, uint64_t addr);

#endif
