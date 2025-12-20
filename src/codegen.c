#include "codegen.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CodeGen *codegen_create(void) {
  CodeGen *cg = calloc(1, sizeof(CodeGen));
  if (cg) {
    cg->use_structured = 1;
  }
  return cg;
}

void codegen_destroy(CodeGen *cg) { free(cg); }

void codegen_set_structured(CodeGen *cg, int enable) {
  if (cg)
    cg->use_structured = enable;
}

const char *codegen_type_name(VarType t) {
  switch (t) {
  case TYPE_VOID:
    return "void";
  case TYPE_INT8:
    return "int8_t";
  case TYPE_UINT8:
    return "uint8_t";
  case TYPE_INT16:
    return "int16_t";
  case TYPE_UINT16:
    return "uint16_t";
  case TYPE_INT32:
    return "int32_t";
  case TYPE_UINT32:
    return "uint32_t";
  case TYPE_INT64:
    return "int64_t";
  case TYPE_UINT64:
    return "uint64_t";
  case TYPE_PTR:
    return "void*";
  default:
    return "uint64_t";
  }
}

VarType codegen_infer_type(CodeGen *cg, SSAOperand *op) {
  (void)cg;
  if (!op)
    return TYPE_UNKNOWN;
  if (op->is_const) {
    if (op->const_val <= 0xFF)
      return TYPE_UINT8;
    if (op->const_val <= 0xFFFF)
      return TYPE_UINT16;
    if (op->const_val <= 0xFFFFFFFF)
      return TYPE_UINT32;
    return TYPE_UINT64;
  }
  return TYPE_UINT64;
}

static void emit(CodeGen *cg, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  cg->output_len += vsnprintf(cg->output + cg->output_len,
                              CODEGEN_MAX_OUTPUT - cg->output_len, fmt, args);
  va_end(args);
}

static void emit_indent(CodeGen *cg) {
  for (int i = 0; i < cg->indent; i++) {
    emit(cg, "    ");
  }
}

static void emit_operand(CodeGen *cg, SSAOperand *op) {
  if (op->is_const) {
    if (op->const_val > 0xFFFF) {
      emit(cg, "0x%llxULL", (unsigned long long)op->const_val);
    } else {
      emit(cg, "%llu", (unsigned long long)op->const_val);
    }
  } else {
    if (op->var_id == 31) {
      emit(cg, "sp");
    } else {
      emit(cg, "r%d", op->var_id);
    }
  }
}

static void emit_insn(CodeGen *cg, SSAInsn *insn) {
  emit_indent(cg);

  switch (insn->op) {
  case SSA_NOP:
    break;

  case SSA_MOV:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, ";\n");
    break;

  case SSA_ADD:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " + ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_SUB:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " - ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_MUL:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " * ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_AND:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " & ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_OR:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " | ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_XOR:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " ^ ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_SHL:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " << ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_SHR:
    emit_operand(cg, &insn->dst);
    emit(cg, " = ");
    emit_operand(cg, &insn->src1);
    emit(cg, " >> ");
    emit_operand(cg, &insn->src2);
    emit(cg, ";\n");
    break;

  case SSA_LOAD:
    emit_operand(cg, &insn->dst);
    emit(cg, " = *(uint64_t*)(");
    emit_operand(cg, &insn->src1);
    if (insn->src2.const_val != 0) {
      emit(cg, " + ");
      emit_operand(cg, &insn->src2);
    }
    emit(cg, ");\n");
    break;

  case SSA_STORE:
    emit(cg, "*(uint64_t*)(");
    emit(cg, "r%d", insn->dst.var_id);
    if (insn->src2.const_val != 0) {
      emit(cg, " + ");
      emit_operand(cg, &insn->src2);
    }
    emit(cg, ") = ");
    emit_operand(cg, &insn->src1);
    emit(cg, ";\n");
    break;

  case SSA_CMP:
    emit(cg, "cmp_result = (");
    emit_operand(cg, &insn->src1);
    emit(cg, " - ");
    emit_operand(cg, &insn->src2);
    emit(cg, ");\n");
    break;

  case SSA_BR:
    emit(cg, "goto label_%d;\n", insn->target_block);
    break;

  case SSA_BR_COND:
    emit(cg, "if (cmp_result) goto label_taken;\n");
    break;

  case SSA_CALL:
    emit(cg, "r0 = func_%llx();\n", (unsigned long long)insn->address);
    break;

  case SSA_RET:
    emit(cg, "return r0;\n");
    break;

  default:
    break;
  }
}

int codegen_from_ssa(CodeGen *cg, SSAFunction *fn) {
  if (!cg || !fn)
    return 0;

  cg->output_len = 0;
  cg->indent = 0;

  emit(cg,
       "uint64_t decompiled_func(uint64_t r0, uint64_t r1, uint64_t r2) {\n");
  cg->indent = 1;

  emit_indent(cg);
  emit(cg, "uint64_t r3, r4, r5, r6, r7, r8;\n");
  emit_indent(cg);
  emit(cg, "uint64_t sp = 0x7FFFFFF0;\n");
  emit_indent(cg);
  emit(cg, "int64_t cmp_result = 0;\n\n");

  for (size_t b = 0; b < fn->block_count; b++) {
    SSABlock *blk = fn->blocks[b];

    emit(cg, "label_%d:\n", blk->id);

    for (size_t i = 0; i < blk->insn_count; i++) {
      emit_insn(cg, &blk->insns[i]);
    }
    emit(cg, "\n");
  }

  cg->indent = 0;
  emit(cg, "}\n");

  return 1;
}

const char *codegen_get_output(CodeGen *cg) { return cg ? cg->output : ""; }
