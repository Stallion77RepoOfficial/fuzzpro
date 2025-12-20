#ifndef FUZZPRO_SSA_H
#define FUZZPRO_SSA_H

#include "arm64dis.h"
#include <stddef.h>
#include <stdint.h>

#define SSA_MAX_VARS 1024
#define SSA_MAX_BLOCKS 256
#define SSA_MAX_INSNS 4096
#define SSA_MAX_PHIS 64

typedef enum {
  SSA_NOP = 0,
  SSA_MOV,
  SSA_ADD,
  SSA_SUB,
  SSA_MUL,
  SSA_DIV,
  SSA_MOD,
  SSA_AND,
  SSA_OR,
  SSA_XOR,
  SSA_NOT,
  SSA_SHL,
  SSA_SHR,
  SSA_SAR,
  SSA_LOAD,
  SSA_STORE,
  SSA_CMP,
  SSA_BR,
  SSA_BR_COND,
  SSA_CALL,
  SSA_RET,
  SSA_PHI
} SSAOpcode;

typedef struct {
  int is_const;
  int var_id;
  int version;
  uint64_t const_val;
  int width;
} SSAOperand;

typedef struct {
  int var_id;
  int incoming_version[8];
  int incoming_block[8];
  int count;
} PhiNode;

typedef struct {
  SSAOpcode op;
  SSAOperand dst;
  SSAOperand src1;
  SSAOperand src2;
  int cond;
  int target_block;
  uint64_t address;
} SSAInsn;

typedef struct {
  int id;
  SSAInsn *insns;
  size_t insn_count;
  size_t insn_capacity;
  PhiNode phis[SSA_MAX_PHIS];
  size_t phi_count;
  int successors[2];
  int successor_count;
  int predecessors[8];
  int predecessor_count;
  int dominators;
  int idom;
  uint64_t start_addr;
  uint64_t end_addr;
} SSABlock;

typedef struct {
  SSABlock *blocks[SSA_MAX_BLOCKS];
  size_t block_count;
  int var_versions[SSA_MAX_VARS];
  int entry_block;
  int exit_block;
  const uint8_t *code;
  size_t code_len;
  uint64_t base_addr;
} SSAFunction;

SSAFunction *ssa_create(const uint8_t *code, size_t len, uint64_t base);
void ssa_destroy(SSAFunction *fn);
int ssa_build_cfg(SSAFunction *fn);
int ssa_convert_to_ssa(SSAFunction *fn);
int ssa_lift_arm64(SSAFunction *fn, A64Instruction *insn, SSABlock *blk);
void ssa_print(SSAFunction *fn, char *buf, size_t len);
SSAOperand ssa_use_var(SSAFunction *fn, int var_id);
SSAOperand ssa_def_var(SSAFunction *fn, int var_id);
SSAOperand ssa_const(uint64_t val, int width);

#endif
