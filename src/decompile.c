#include "decompile.h"
#include "arm64dis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DecompileContext *decompile_create(void) {
  DecompileContext *ctx = calloc(1, sizeof(DecompileContext));
  if (!ctx)
    return NULL;
  ctx->func_capacity = 64;
  ctx->funcs = calloc(ctx->func_capacity, sizeof(IRFunction));
  return ctx;
}

void decompile_destroy(DecompileContext *ctx) {
  if (!ctx)
    return;
  for (size_t i = 0; i < ctx->func_count; i++) {
    if (ctx->funcs[i].bbs) {
      for (size_t j = 0; j < ctx->funcs[i].bb_count; j++) {
        free(ctx->funcs[i].bbs[j].successors);
        free(ctx->funcs[i].bbs[j].predecessors);
      }
      free(ctx->funcs[i].bbs);
    }
  }
  free(ctx->funcs);
  free(ctx);
}

static int alloc_var(IRFunction *fn, const char *name, int size, int is_param) {
  if (fn->var_count >= IR_MAX_VARS)
    return -1;
  IRVar *v = &fn->vars[fn->var_count];
  v->id = fn->var_count;
  snprintf(v->name, sizeof(v->name), "%s", name);
  v->size = size;
  v->is_param = is_param;
  return fn->var_count++;
}

static void emit_ir(IRFunction *fn, IROp op, IROperand dst, IROperand *srcs,
                    int src_count, uint64_t addr) {
  if (fn->insn_count >= IR_MAX_INSNS)
    return;
  IRInsn *insn = &fn->insns[fn->insn_count++];
  insn->op = op;
  insn->dst = dst;
  insn->src_count = src_count;
  for (int i = 0; i < src_count && i < IR_MAX_OPERANDS - 1; i++) {
    insn->src[i] = srcs[i];
  }
  insn->addr = addr;
}

static IROperand mk_reg(int reg, int size) {
  IROperand op = {.type = OP_REG, .reg = reg, .size = size};
  return op;
}

static IROperand mk_imm(int64_t val, int size) {
  IROperand op = {.type = OP_IMM, .imm = val, .size = size};
  return op;
}

static IROperand mk_var(int id, int size) {
  IROperand op = {.type = OP_VAR, .var_id = id, .size = size};
  return op;
}

static IROperand mk_label(int label) {
  IROperand op = {.type = OP_LABEL, .label = label, .size = 0};
  return op;
}

static void lift_instruction(IRFunction *fn, A64Instruction *insn) {
  uint64_t addr = insn->address;
  IROperand srcs[3];

  switch (insn->opcode) {
  case A64_ADD_IMM:
  case A64_ADD_REG:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    if (insn->opcode == A64_ADD_IMM) {
      srcs[1] = mk_imm(insn->operands[2].imm, 8);
    } else {
      srcs[1] = mk_reg(insn->operands[2].reg, 8);
    }
    emit_ir(fn, IR_ADD, mk_reg(insn->operands[0].reg, 8), srcs, 2, addr);
    break;

  case A64_SUB_IMM:
  case A64_SUB_REG:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    if (insn->opcode == A64_SUB_IMM) {
      srcs[1] = mk_imm(insn->operands[2].imm, 8);
    } else {
      srcs[1] = mk_reg(insn->operands[2].reg, 8);
    }
    emit_ir(fn, IR_SUB, mk_reg(insn->operands[0].reg, 8), srcs, 2, addr);
    break;

  case A64_AND_IMM:
  case A64_AND_REG:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    srcs[1] = (insn->opcode == A64_AND_IMM) ? mk_imm(insn->operands[2].imm, 8)
                                            : mk_reg(insn->operands[2].reg, 8);
    emit_ir(fn, IR_AND, mk_reg(insn->operands[0].reg, 8), srcs, 2, addr);
    break;

  case A64_ORR_IMM:
  case A64_ORR_REG:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    srcs[1] = (insn->opcode == A64_ORR_IMM) ? mk_imm(insn->operands[2].imm, 8)
                                            : mk_reg(insn->operands[2].reg, 8);
    emit_ir(fn, IR_OR, mk_reg(insn->operands[0].reg, 8), srcs, 2, addr);
    break;

  case A64_MOVZ:
  case A64_MOVK:
  case A64_MOV_IMM:
    srcs[0] = mk_imm(insn->operands[1].imm, 8);
    emit_ir(fn, IR_MOV, mk_reg(insn->operands[0].reg, 8), srcs, 1, addr);
    break;

  case A64_MOV_REG:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    emit_ir(fn, IR_MOV, mk_reg(insn->operands[0].reg, 8), srcs, 1, addr);
    break;

  case A64_LDR_IMM:
  case A64_LDR_LIT:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    srcs[1] = mk_imm(insn->operands[2].imm, 8);
    emit_ir(fn, IR_LOAD64, mk_reg(insn->operands[0].reg, 8), srcs, 2, addr);
    break;

  case A64_LDRB_IMM:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    srcs[1] = mk_imm(insn->operands[2].imm, 8);
    emit_ir(fn, IR_LOAD8, mk_reg(insn->operands[0].reg, 8), srcs, 2, addr);
    break;

  case A64_LDRH_IMM:
    srcs[0] = mk_reg(insn->operands[1].reg, 8);
    srcs[1] = mk_imm(insn->operands[2].imm, 8);
    emit_ir(fn, IR_LOAD16, mk_reg(insn->operands[0].reg, 8), srcs, 2, addr);
    break;

  case A64_STR_IMM:
    srcs[0] = mk_reg(insn->operands[0].reg, 8);
    srcs[1] = mk_reg(insn->operands[1].reg, 8);
    srcs[2] = mk_imm(insn->operands[2].imm, 8);
    emit_ir(fn, IR_STORE64, mk_reg(0, 0), srcs, 3, addr);
    break;

  case A64_STRB_IMM:
    srcs[0] = mk_reg(insn->operands[0].reg, 8);
    srcs[1] = mk_reg(insn->operands[1].reg, 8);
    srcs[2] = mk_imm(insn->operands[2].imm, 8);
    emit_ir(fn, IR_STORE8, mk_reg(0, 0), srcs, 3, addr);
    break;

  case A64_CMP_IMM:
  case A64_CMP_REG:
    srcs[0] = mk_reg(insn->operands[0].reg, 8);
    srcs[1] = (insn->opcode == A64_CMP_IMM) ? mk_imm(insn->operands[1].imm, 8)
                                            : mk_reg(insn->operands[1].reg, 8);
    emit_ir(fn, IR_CMP, mk_reg(0, 0), srcs, 2, addr);
    break;

  case A64_B:
    srcs[0] = mk_imm(insn->operands[0].imm, 8);
    emit_ir(fn, IR_JMP, mk_label(0), srcs, 1, addr);
    break;

  case A64_B_COND:
  case A64_CBZ:
  case A64_CBNZ:
    srcs[0] = mk_imm(insn->operands[0].imm, 8);
    emit_ir(fn, IR_JCC, mk_label(0), srcs, 1, addr);
    break;

  case A64_BL:
    srcs[0] = mk_imm(insn->operands[0].imm, 8);
    emit_ir(fn, IR_CALL, mk_reg(0, 8), srcs, 1, addr);
    break;

  case A64_BLR:
    srcs[0] = mk_reg(insn->operands[0].reg, 8);
    emit_ir(fn, IR_CALL, mk_reg(0, 8), srcs, 1, addr);
    break;

  case A64_RET:
    emit_ir(fn, IR_RET, mk_reg(0, 8), NULL, 0, addr);
    break;

  default:
    emit_ir(fn, IR_NOP, mk_reg(0, 0), NULL, 0, addr);
    break;
  }
}

int decompile_lift_function(DecompileContext *ctx, const uint8_t *code,
                            size_t len, uint64_t start, uint64_t end) {
  if (!ctx || !code || start >= end)
    return -1;

  if (ctx->func_count >= ctx->func_capacity) {
    ctx->func_capacity *= 2;
    ctx->funcs = realloc(ctx->funcs, ctx->func_capacity * sizeof(IRFunction));
  }

  IRFunction *fn = &ctx->funcs[ctx->func_count++];
  memset(fn, 0, sizeof(*fn));
  fn->func_start = start;
  fn->func_end = end;
  snprintf(fn->func_name, sizeof(fn->func_name), "sub_%llx",
           (unsigned long long)start);

  for (int i = 0; i < 8; i++) {
    char name[8];
    snprintf(name, sizeof(name), "arg%d", i);
    alloc_var(fn, name, 8, 1);
  }

  size_t func_off = 0;
  if (start >= (uint64_t)(uintptr_t)code) {
    func_off = start - (uint64_t)(uintptr_t)code;
  }

  size_t func_len = end - start;
  if (func_len > len - func_off)
    func_len = len - func_off;

  A64Instruction insns[256];
  int count = a64_disasm_buffer(code + func_off, func_len, start, insns, 256);

  for (int i = 0; i < count; i++) {
    lift_instruction(fn, &insns[i]);
  }

  return 0;
}

static const char *ir_op_name(IROp op) {
  static const char *names[] = {
      "nop",  "mov",  "add",  "sub",  "mul",  "div",  "mod",  "and",
      "or",   "xor",  "not",  "shl",  "shr",  "sar",  "ld8",  "ld16",
      "ld32", "ld64", "st8",  "st16", "st32", "st64", "cmp",  "test",
      "jmp",  "jcc",  "call", "ret",  "phi",  "zext", "sext", "trunc"};
  if (op >= 0 && op < sizeof(names) / sizeof(names[0]))
    return names[op];
  return "???";
}

static const char *reg_name(int reg) {
  static const char *names[] = {"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",
                                "x7",  "x8",  "x9",  "x10", "x11", "x12", "x13",
                                "x14", "x15", "x16", "x17", "x18", "x19", "x20",
                                "x21", "x22", "x23", "x24", "x25", "x26", "x27",
                                "x28", "x29", "x30", "sp"};
  if (reg >= 0 && reg < 32)
    return names[reg];
  return "?";
}

int decompile_to_c(DecompileContext *ctx, IRFunction *fn, char *output,
                   size_t max_len) {
  if (!ctx || !fn || !output)
    return -1;

  char *p = output;
  size_t remaining = max_len;
  int written;

  written =
      snprintf(p, remaining,
               "uint64_t %s(uint64_t arg0, uint64_t arg1, uint64_t arg2) {\n",
               fn->func_name);
  p += written;
  remaining -= written;

  written = snprintf(p, remaining,
                     "    uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8;\n");
  p += written;
  remaining -= written;

  written =
      snprintf(p, remaining, "    uint64_t x19, x20, x21, x22, x29, x30;\n\n");
  p += written;
  remaining -= written;

  for (size_t i = 0; i < fn->insn_count && remaining > 100; i++) {
    IRInsn *insn = &fn->insns[i];

    switch (insn->op) {
    case IR_MOV:
      if (insn->src[0].type == OP_IMM) {
        written = snprintf(p, remaining, "    %s = 0x%llx;\n",
                           reg_name(insn->dst.reg),
                           (unsigned long long)insn->src[0].imm);
      } else {
        written = snprintf(p, remaining, "    %s = %s;\n",
                           reg_name(insn->dst.reg), reg_name(insn->src[0].reg));
      }
      break;

    case IR_ADD:
      if (insn->src[1].type == OP_IMM) {
        written = snprintf(p, remaining, "    %s = %s + 0x%llx;\n",
                           reg_name(insn->dst.reg), reg_name(insn->src[0].reg),
                           (unsigned long long)insn->src[1].imm);
      } else {
        written = snprintf(p, remaining, "    %s = %s + %s;\n",
                           reg_name(insn->dst.reg), reg_name(insn->src[0].reg),
                           reg_name(insn->src[1].reg));
      }
      break;

    case IR_SUB:
      if (insn->src[1].type == OP_IMM) {
        written = snprintf(p, remaining, "    %s = %s - 0x%llx;\n",
                           reg_name(insn->dst.reg), reg_name(insn->src[0].reg),
                           (unsigned long long)insn->src[1].imm);
      } else {
        written = snprintf(p, remaining, "    %s = %s - %s;\n",
                           reg_name(insn->dst.reg), reg_name(insn->src[0].reg),
                           reg_name(insn->src[1].reg));
      }
      break;

    case IR_LOAD64:
      written = snprintf(p, remaining, "    %s = *(uint64_t*)(%s + 0x%llx);\n",
                         reg_name(insn->dst.reg), reg_name(insn->src[0].reg),
                         (unsigned long long)insn->src[1].imm);
      break;

    case IR_LOAD32:
      written = snprintf(p, remaining, "    %s = *(uint32_t*)(%s + 0x%llx);\n",
                         reg_name(insn->dst.reg), reg_name(insn->src[0].reg),
                         (unsigned long long)insn->src[1].imm);
      break;

    case IR_LOAD8:
      written = snprintf(p, remaining, "    %s = *(uint8_t*)(%s + 0x%llx);\n",
                         reg_name(insn->dst.reg), reg_name(insn->src[0].reg),
                         (unsigned long long)insn->src[1].imm);
      break;

    case IR_STORE64:
      written = snprintf(p, remaining, "    *(uint64_t*)(%s + 0x%llx) = %s;\n",
                         reg_name(insn->src[1].reg),
                         (unsigned long long)insn->src[2].imm,
                         reg_name(insn->src[0].reg));
      break;

    case IR_CMP:
      written = snprintf(p, remaining, "    /* cmp %s, 0x%llx */\n",
                         reg_name(insn->src[0].reg),
                         (unsigned long long)insn->src[1].imm);
      break;

    case IR_CALL:
      written = snprintf(p, remaining, "    x0 = sub_%llx(x0, x1, x2);\n",
                         (unsigned long long)(insn->addr + insn->src[0].imm));
      break;

    case IR_RET:
      written = snprintf(p, remaining, "    return x0;\n");
      break;

    case IR_JCC:
      written = snprintf(p, remaining, "    if (cond) goto L_%llx;\n",
                         (unsigned long long)(insn->addr + insn->src[0].imm));
      break;

    case IR_JMP:
      written = snprintf(p, remaining, "    goto L_%llx;\n",
                         (unsigned long long)(insn->addr + insn->src[0].imm));
      break;

    default:
      written = snprintf(p, remaining, "    /* %s */\n", ir_op_name(insn->op));
      break;
    }

    p += written;
    remaining -= written;
  }

  snprintf(p, remaining, "}\n");
  return 0;
}

IRFunction *decompile_get_function(DecompileContext *ctx, uint64_t addr) {
  if (!ctx)
    return NULL;
  for (size_t i = 0; i < ctx->func_count; i++) {
    if (ctx->funcs[i].func_start <= addr && addr < ctx->funcs[i].func_end) {
      return &ctx->funcs[i];
    }
  }
  return NULL;
}
