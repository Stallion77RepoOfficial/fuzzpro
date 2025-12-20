#include "ssa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SSAFunction *ssa_create(const uint8_t *code, size_t len, uint64_t base) {
  SSAFunction *fn = calloc(1, sizeof(SSAFunction));
  if (!fn)
    return NULL;
  fn->code = code;
  fn->code_len = len;
  fn->base_addr = base;
  fn->entry_block = 0;
  fn->exit_block = -1;
  return fn;
}

void ssa_destroy(SSAFunction *fn) {
  if (!fn)
    return;
  for (size_t i = 0; i < fn->block_count; i++) {
    if (fn->blocks[i]) {
      free(fn->blocks[i]->insns);
      free(fn->blocks[i]);
    }
  }
  free(fn);
}

static SSABlock *create_block(SSAFunction *fn) {
  if (fn->block_count >= SSA_MAX_BLOCKS)
    return NULL;
  SSABlock *blk = calloc(1, sizeof(SSABlock));
  if (!blk)
    return NULL;
  blk->id = (int)fn->block_count;
  blk->insn_capacity = 64;
  blk->insns = calloc(blk->insn_capacity, sizeof(SSAInsn));
  blk->idom = -1;
  fn->blocks[fn->block_count++] = blk;
  return blk;
}

static void add_insn(SSABlock *blk, SSAInsn *insn) {
  if (!blk || !insn)
    return;
  if (blk->insn_count >= blk->insn_capacity) {
    blk->insn_capacity *= 2;
    blk->insns = realloc(blk->insns, blk->insn_capacity * sizeof(SSAInsn));
  }
  blk->insns[blk->insn_count++] = *insn;
}

SSAOperand ssa_const(uint64_t val, int width) {
  SSAOperand op = {0};
  op.is_const = 1;
  op.const_val = val;
  op.width = width;
  return op;
}

SSAOperand ssa_use_var(SSAFunction *fn, int var_id) {
  SSAOperand op = {0};
  op.is_const = 0;
  op.var_id = var_id;
  op.version = fn->var_versions[var_id];
  op.width = 64;
  return op;
}

SSAOperand ssa_def_var(SSAFunction *fn, int var_id) {
  SSAOperand op = {0};
  op.is_const = 0;
  op.var_id = var_id;
  op.version = ++fn->var_versions[var_id];
  op.width = 64;
  return op;
}

int ssa_lift_arm64(SSAFunction *fn, A64Instruction *insn, SSABlock *blk) {
  if (!fn || !insn || !blk)
    return 0;

  SSAInsn ssa = {0};
  ssa.address = insn->address;

  switch (insn->opcode) {
  case A64_ADD_IMM:
  case A64_ADD_REG:
    ssa.op = SSA_ADD;
    ssa.dst = ssa_def_var(fn, insn->operands[0].reg);
    ssa.src1 = ssa_use_var(fn, insn->operands[1].reg);
    if (insn->operands[2].type == A64_OP_IMM) {
      ssa.src2 = ssa_const(insn->operands[2].imm, 64);
    } else {
      ssa.src2 = ssa_use_var(fn, insn->operands[2].reg);
    }
    break;

  case A64_SUB_IMM:
  case A64_SUB_REG:
    ssa.op = SSA_SUB;
    ssa.dst = ssa_def_var(fn, insn->operands[0].reg);
    ssa.src1 = ssa_use_var(fn, insn->operands[1].reg);
    if (insn->operands[2].type == A64_OP_IMM) {
      ssa.src2 = ssa_const(insn->operands[2].imm, 64);
    } else {
      ssa.src2 = ssa_use_var(fn, insn->operands[2].reg);
    }
    break;

  case A64_AND_IMM:
  case A64_AND_REG:
    ssa.op = SSA_AND;
    ssa.dst = ssa_def_var(fn, insn->operands[0].reg);
    ssa.src1 = ssa_use_var(fn, insn->operands[1].reg);
    if (insn->operands[2].type == A64_OP_IMM) {
      ssa.src2 = ssa_const(insn->operands[2].imm, 64);
    } else {
      ssa.src2 = ssa_use_var(fn, insn->operands[2].reg);
    }
    break;

  case A64_ORR_IMM:
  case A64_ORR_REG:
    ssa.op = SSA_OR;
    ssa.dst = ssa_def_var(fn, insn->operands[0].reg);
    ssa.src1 = ssa_use_var(fn, insn->operands[1].reg);
    if (insn->operands[2].type == A64_OP_IMM) {
      ssa.src2 = ssa_const(insn->operands[2].imm, 64);
    } else {
      ssa.src2 = ssa_use_var(fn, insn->operands[2].reg);
    }
    break;

  case A64_MOVZ:
  case A64_MOV_IMM:
    ssa.op = SSA_MOV;
    ssa.dst = ssa_def_var(fn, insn->operands[0].reg);
    ssa.src1 = ssa_const(insn->operands[1].imm, 64);
    break;

  case A64_MOV_REG:
    ssa.op = SSA_MOV;
    ssa.dst = ssa_def_var(fn, insn->operands[0].reg);
    ssa.src1 = ssa_use_var(fn, insn->operands[1].reg);
    break;

  case A64_LDR_IMM:
    ssa.op = SSA_LOAD;
    ssa.dst = ssa_def_var(fn, insn->operands[0].reg);
    ssa.src1 = ssa_use_var(fn, insn->operands[1].reg);
    ssa.src2 = ssa_const(insn->operands[2].imm, 64);
    break;

  case A64_STR_IMM:
    ssa.op = SSA_STORE;
    ssa.src1 = ssa_use_var(fn, insn->operands[0].reg);
    ssa.dst.var_id = insn->operands[1].reg;
    ssa.src2 = ssa_const(insn->operands[2].imm, 64);
    break;

  case A64_CMP_IMM:
  case A64_CMP_REG:
    ssa.op = SSA_CMP;
    ssa.src1 = ssa_use_var(fn, insn->operands[0].reg);
    if (insn->operands[1].type == A64_OP_IMM) {
      ssa.src2 = ssa_const(insn->operands[1].imm, 64);
    } else {
      ssa.src2 = ssa_use_var(fn, insn->operands[1].reg);
    }
    break;

  case A64_B:
    ssa.op = SSA_BR;
    ssa.target_block = -1;
    break;

  case A64_B_COND:
  case A64_CBZ:
  case A64_CBNZ:
    ssa.op = SSA_BR_COND;
    ssa.cond = insn->operands[0].cond;
    break;

  case A64_BL:
  case A64_BLR:
    ssa.op = SSA_CALL;
    break;

  case A64_RET:
    ssa.op = SSA_RET;
    break;

  default:
    ssa.op = SSA_NOP;
    break;
  }

  add_insn(blk, &ssa);
  return 1;
}

int ssa_build_cfg(SSAFunction *fn) {
  if (!fn || !fn->code)
    return 0;

  SSABlock *current = create_block(fn);
  if (!current)
    return 0;
  current->start_addr = fn->base_addr;

  size_t offset = 0;
  while (offset + 4 <= fn->code_len) {
    uint32_t raw = *(uint32_t *)(fn->code + offset);
    uint64_t addr = fn->base_addr + offset;

    A64Instruction insn = {0};
    a64_decode(raw, addr, &insn);

    ssa_lift_arm64(fn, &insn, current);

    if (insn.is_branch || insn.is_return) {
      current->end_addr = addr;

      if (!insn.is_return && offset + 4 < fn->code_len) {
        SSABlock *next = create_block(fn);
        if (next) {
          next->start_addr = addr + 4;
          current->successors[current->successor_count++] = next->id;
          next->predecessors[next->predecessor_count++] = current->id;
          current = next;
        }
      }
    }

    offset += 4;
  }

  return (int)fn->block_count;
}

int ssa_convert_to_ssa(SSAFunction *fn) {
  if (!fn)
    return 0;
  return 1;
}

void ssa_print(SSAFunction *fn, char *buf, size_t len) {
  if (!fn || !buf || len == 0)
    return;

  size_t pos = 0;
  for (size_t b = 0; b < fn->block_count && pos < len; b++) {
    SSABlock *blk = fn->blocks[b];
    pos += snprintf(buf + pos, len - pos, "BB%d:\n", blk->id);

    for (size_t i = 0; i < blk->insn_count && pos < len; i++) {
      SSAInsn *insn = &blk->insns[i];
      const char *op_names[] = {
          "nop", "mov", "add",     "sub",  "mul", "div", "mod",  "and",
          "or",  "xor", "not",     "shl",  "shr", "sar", "load", "store",
          "cmp", "br",  "br.cond", "call", "ret", "phi"};
      pos += snprintf(buf + pos, len - pos, "  %s", op_names[insn->op]);

      if (insn->dst.var_id > 0 || insn->op == SSA_MOV) {
        pos += snprintf(buf + pos, len - pos, " v%d_%d", insn->dst.var_id,
                        insn->dst.version);
      }
      pos += snprintf(buf + pos, len - pos, "\n");
    }
  }
}
