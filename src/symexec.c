#include "arm64dis.h"
#include "autodict.h"
#include "symbolic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  SymState *state;
  const uint8_t *code;
  size_t code_len;
  uint64_t code_base;
  AutoDict *discovered;
  int max_depth;
  int current_depth;
} SymExec;

SymExec *symexec_create(const uint8_t *code, size_t len, uint64_t base) {
  SymExec *se = calloc(1, sizeof(SymExec));
  if (!se)
    return NULL;

  se->state = sym_state_create();
  se->code = code;
  se->code_len = len;
  se->code_base = base;
  se->discovered = autodict_create();
  se->max_depth = 100;

  return se;
}

void symexec_destroy(SymExec *se) {
  if (!se)
    return;
  sym_state_destroy(se->state);
  autodict_destroy(se->discovered);
  free(se);
}

void symexec_set_input_symbolic(SymExec *se, size_t offset, size_t len) {
  if (!se || !se->state)
    return;

  for (size_t i = 0; i < len && i + offset < SYM_MAX_MEMORY; i++) {
    se->state->mem_symbolic[offset + i] = sym_var(se->state, 8);
  }
}

static SymExpr *symexec_read_mem(SymExec *se, uint64_t addr, int bytes) {
  if (!se || !se->state)
    return sym_const(0, bytes * 8);

  size_t offset = addr - se->state->mem_base;
  if (offset >= SYM_MAX_MEMORY) {
    return sym_const(0, bytes * 8);
  }

  if (se->state->mem_symbolic[offset]) {
    SymExpr *result = se->state->mem_symbolic[offset];
    for (int i = 1; i < bytes && offset + i < SYM_MAX_MEMORY; i++) {
      if (se->state->mem_symbolic[offset + i]) {
        result =
            sym_binop(OP_OR, result,
                      sym_binop(OP_SHL, se->state->mem_symbolic[offset + i],
                                sym_const(i * 8, 8), bytes * 8),
                      bytes * 8);
      }
    }
    return result;
  }

  uint64_t val = 0;
  for (int i = 0; i < bytes && offset + i < SYM_MAX_MEMORY; i++) {
    val |= (uint64_t)se->state->mem_concrete[offset + i] << (i * 8);
  }
  return sym_const(val, bytes * 8);
}

static void symexec_write_mem(SymExec *se, uint64_t addr, SymExpr *val,
                              int bytes) {
  if (!se || !se->state)
    return;

  size_t offset = addr - se->state->mem_base;
  if (offset >= SYM_MAX_MEMORY)
    return;

  if (sym_is_concrete(val)) {
    uint64_t v = sym_get_concrete(val);
    for (int i = 0; i < bytes && offset + i < SYM_MAX_MEMORY; i++) {
      se->state->mem_concrete[offset + i] = (v >> (i * 8)) & 0xFF;
      se->state->mem_symbolic[offset + i] = NULL;
    }
  } else {
    se->state->mem_symbolic[offset] = val;
  }
}

static void symexec_record_compare(SymExec *se, SymExpr *left, SymExpr *right) {
  if (!se || !se->discovered)
    return;

  if (sym_is_concrete(right) && !sym_is_concrete(left)) {
    uint64_t val = sym_get_concrete(right);
    uint8_t buf[8];
    memcpy(buf, &val, 8);

    for (int len = 1; len <= 8; len++) {
      if (val >> (len * 8) == 0 || len == 8) {
        autodict_add_token(se->discovered, buf, len);
        break;
      }
    }
  }

  if (sym_is_concrete(left) && !sym_is_concrete(right)) {
    uint64_t val = sym_get_concrete(left);
    uint8_t buf[8];
    memcpy(buf, &val, 8);

    for (int len = 1; len <= 8; len++) {
      if (val >> (len * 8) == 0 || len == 8) {
        autodict_add_token(se->discovered, buf, len);
        break;
      }
    }
  }
}

static int symexec_step(SymExec *se, A64Instruction *insn) {
  if (!se || !se->state || !insn)
    return -1;

  SymState *st = se->state;

  switch (insn->opcode) {
  case A64_ADD_IMM: {
    int rd = insn->operands[0].reg;
    int rn = insn->operands[1].reg;
    uint64_t imm = insn->operands[2].imm;
    st->regs[rd] = sym_binop(OP_ADD, st->regs[rn], sym_const(imm, 64), 64);
    break;
  }

  case A64_SUB_IMM: {
    int rd = insn->operands[0].reg;
    int rn = insn->operands[1].reg;
    uint64_t imm = insn->operands[2].imm;
    st->regs[rd] = sym_binop(OP_SUB, st->regs[rn], sym_const(imm, 64), 64);
    break;
  }

  case A64_AND_IMM: {
    int rd = insn->operands[0].reg;
    int rn = insn->operands[1].reg;
    uint64_t imm = insn->operands[2].imm;
    st->regs[rd] = sym_binop(OP_AND, st->regs[rn], sym_const(imm, 64), 64);
    break;
  }

  case A64_ORR_IMM: {
    int rd = insn->operands[0].reg;
    int rn = insn->operands[1].reg;
    uint64_t imm = insn->operands[2].imm;
    st->regs[rd] = sym_binop(OP_OR, st->regs[rn], sym_const(imm, 64), 64);
    break;
  }

  case A64_MOVZ:
  case A64_MOV_IMM: {
    int rd = insn->operands[0].reg;
    uint64_t imm = insn->operands[1].imm;
    st->regs[rd] = sym_const(imm, 64);
    break;
  }

  case A64_MOV_REG: {
    int rd = insn->operands[0].reg;
    int rm = insn->operands[1].reg;
    st->regs[rd] = st->regs[rm];
    break;
  }

  case A64_LDR_IMM: {
    int rt = insn->operands[0].reg;
    int rn = insn->operands[1].reg;
    int64_t offset = insn->operands[2].imm;

    if (sym_is_concrete(st->regs[rn])) {
      uint64_t addr = sym_get_concrete(st->regs[rn]) + offset;
      st->regs[rt] = symexec_read_mem(se, addr, 8);
    }
    break;
  }

  case A64_LDRB_IMM: {
    int rt = insn->operands[0].reg;
    int rn = insn->operands[1].reg;
    int64_t offset = insn->operands[2].imm;

    if (sym_is_concrete(st->regs[rn])) {
      uint64_t addr = sym_get_concrete(st->regs[rn]) + offset;
      st->regs[rt] = symexec_read_mem(se, addr, 1);
    }
    break;
  }

  case A64_STR_IMM: {
    int rt = insn->operands[0].reg;
    int rn = insn->operands[1].reg;
    int64_t offset = insn->operands[2].imm;

    if (sym_is_concrete(st->regs[rn])) {
      uint64_t addr = sym_get_concrete(st->regs[rn]) + offset;
      symexec_write_mem(se, addr, st->regs[rt], 8);
    }
    break;
  }

  case A64_CMP_IMM: {
    int rn = insn->operands[0].reg;
    uint64_t imm = insn->operands[1].imm;

    symexec_record_compare(se, st->regs[rn], sym_const(imm, 64));

    SymExpr *cmp = sym_binop(OP_EQ, st->regs[rn], sym_const(imm, 64), 1);
    sym_add_constraint(st, cmp);
    break;
  }

  case A64_CMP_REG: {
    int rn = insn->operands[0].reg;
    int rm = insn->operands[1].reg;

    symexec_record_compare(se, st->regs[rn], st->regs[rm]);
    break;
  }

  case A64_B_COND:
  case A64_CBZ:
  case A64_CBNZ: {
    return 1;
  }

  case A64_RET:
    return -1;

  default:
    break;
  }

  return 0;
}

int symexec_run(SymExec *se, uint64_t start_addr, uint64_t end_addr) {
  if (!se)
    return -1;

  se->state->pc = sym_const(start_addr, 64);

  int steps = 0;
  while (steps < se->max_depth * 10) {
    uint64_t pc = sym_get_concrete(se->state->pc);

    if (pc < se->code_base || pc >= se->code_base + se->code_len)
      break;
    if (end_addr && pc >= end_addr)
      break;

    size_t off = pc - se->code_base;
    uint32_t raw = *(uint32_t *)(se->code + off);

    A64Instruction insn = {0};
    a64_decode(raw, pc, &insn);

    int result = symexec_step(se, &insn);
    if (result < 0)
      break;

    se->state->pc = sym_const(pc + 4, 64);
    steps++;
  }

  return (int)se->discovered->count;
}

AutoDict *symexec_get_discoveries(SymExec *se) {
  return se ? se->discovered : NULL;
}
