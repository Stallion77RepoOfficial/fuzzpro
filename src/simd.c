#include "simd.h"
#include <stdio.h>
#include <string.h>

#define BITS(v, hi, lo) (((v) >> (lo)) & ((1U << ((hi) - (lo) + 1)) - 1))
#define BIT(v, n) (((v) >> (n)) & 1)

static const char *fp_reg_names_s[] = {
    "s0",  "s1",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",  "s8",  "s9",  "s10",
    "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21",
    "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31"};

static const char *fp_reg_names_d[] = {
    "d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",  "d8",  "d9",  "d10",
    "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21",
    "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"};

static const char *fp_reg_names_h[] = {
    "h0",  "h1",  "h2",  "h3",  "h4",  "h5",  "h6",  "h7",  "h8",  "h9",  "h10",
    "h11", "h12", "h13", "h14", "h15", "h16", "h17", "h18", "h19", "h20", "h21",
    "h22", "h23", "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31"};

static const char *fp_reg_names_b[] = {
    "b0",  "b1",  "b2",  "b3",  "b4",  "b5",  "b6",  "b7",  "b8",  "b9",  "b10",
    "b11", "b12", "b13", "b14", "b15", "b16", "b17", "b18", "b19", "b20", "b21",
    "b22", "b23", "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31"};

static const char *fp_reg_names_q[] = {
    "q0",  "q1",  "q2",  "q3",  "q4",  "q5",  "q6",  "q7",  "q8",  "q9",  "q10",
    "q11", "q12", "q13", "q14", "q15", "q16", "q17", "q18", "q19", "q20", "q21",
    "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31"};

static const char *get_fp_reg(int reg, int type) {
  if (reg < 0 || reg > 31)
    return "?";
  switch (type) {
  case 0:
    return fp_reg_names_b[reg];
  case 1:
    return fp_reg_names_h[reg];
  case 2:
    return fp_reg_names_s[reg];
  case 3:
    return fp_reg_names_d[reg];
  case 4:
    return fp_reg_names_q[reg];
  default:
    return fp_reg_names_d[reg];
  }
}

int decode_fp_simd(uint32_t insn, uint64_t addr, A64Instruction *out) {
  (void)addr;

  if ((insn & 0x5F200000) == 0x1E200000) {
    int M = BIT(insn, 31);
    int S = BIT(insn, 29);
    int ptype = BITS(insn, 23, 22);
    int opcode = BITS(insn, 20, 15);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    if (M == 0 && S == 0) {
      const char *mnem = NULL;
      int type = (ptype == 0) ? 2 : 3;

      switch (opcode) {
      case 0:
        mnem = "fmov";
        out->opcode = A64_FMOV;
        break;
      case 1:
        mnem = "fabs";
        out->opcode = A64_FABS;
        break;
      case 2:
        mnem = "fneg";
        out->opcode = A64_FNEG;
        break;
      case 3:
        mnem = "fsqrt";
        out->opcode = A64_FSQRT;
        break;
      default:
        return -1;
      }

      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s",
               get_fp_reg(rd, type), get_fp_reg(rn, type));
      return 0;
    }
  }

  if ((insn & 0x5F200800) == 0x1E200800) {
    int ptype = BITS(insn, 23, 22);
    int rm = BITS(insn, 20, 16);
    int opcode = BITS(insn, 15, 12);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    int type = (ptype == 0) ? 2 : 3;
    const char *mnem = NULL;

    switch (opcode) {
    case 0:
      mnem = "fmul";
      out->opcode = A64_FMUL;
      break;
    case 1:
      mnem = "fdiv";
      out->opcode = A64_FDIV;
      break;
    case 2:
      mnem = "fadd";
      out->opcode = A64_FADD;
      break;
    case 3:
      mnem = "fsub";
      out->opcode = A64_FSUB;
      break;
    case 4:
      mnem = "fmax";
      out->opcode = A64_FMAX;
      break;
    case 5:
      mnem = "fmin";
      out->opcode = A64_FMIN;
      break;
    default:
      return -1;
    }

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s",
             get_fp_reg(rd, type), get_fp_reg(rn, type), get_fp_reg(rm, type));
    return 0;
  }

  if ((insn & 0x5F200C00) == 0x1E200000) {
    int ptype = BITS(insn, 23, 22);
    int rm = BITS(insn, 20, 16);
    int opc = BITS(insn, 4, 3);
    int rn = BITS(insn, 9, 5);

    int type = (ptype == 0) ? 2 : 3;
    const char *mnem = (opc & 1) ? "fcmpe" : "fcmp";
    out->opcode = (opc & 1) ? A64_FCMPE : A64_FCMP;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (rm == 0 && (opc & 2)) {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, #0.0",
               get_fp_reg(rn, type));
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s",
               get_fp_reg(rn, type), get_fp_reg(rm, type));
    }
    return 0;
  }

  if ((insn & 0x7F3FFC00) == 0x1E220000) {
    int sf = BIT(insn, 31);
    int S = BIT(insn, 29);
    int ptype = BITS(insn, 23, 22);
    int rmode = BITS(insn, 20, 19);
    int opcode = BITS(insn, 18, 16);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    if (S == 0) {
      const char *mnem = NULL;
      int fp_type = (ptype == 0) ? 2 : 3;
      int to_fp = opcode & 1;

      if (opcode == 0 || opcode == 1) {
        if (to_fp) {
          mnem = "scvtf";
          out->opcode = A64_SCVTF;
          snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
          snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s",
                   get_fp_reg(rd, fp_type), sf ? "x" : "w");
        } else {
          mnem = "fcvtzs";
          out->opcode = A64_FCVTZS;
          snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
          snprintf(out->operands_str, sizeof(out->operands_str), "%s%d, %s",
                   sf ? "x" : "w", rd, get_fp_reg(rn, fp_type));
        }
        return 0;
      }
      if (opcode == 4 || opcode == 5) {
        if (to_fp) {
          mnem = "ucvtf";
          out->opcode = A64_UCVTF;
        } else {
          mnem = "fcvtzu";
          out->opcode = A64_FCVTZU;
        }
        snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
        snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s",
                 to_fp ? get_fp_reg(rd, fp_type) : (sf ? "x" : "w"),
                 to_fp ? (sf ? "x" : "w") : get_fp_reg(rn, fp_type));
        return 0;
      }
      if (opcode == 6 || opcode == 7) {
        out->opcode = A64_FMOV_GEN;
        snprintf(out->mnemonic, sizeof(out->mnemonic), "fmov");
        if (opcode == 7) {
          snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s%d",
                   get_fp_reg(rd, fp_type), sf ? "x" : "w", rn);
        } else {
          snprintf(out->operands_str, sizeof(out->operands_str), "%s%d, %s",
                   sf ? "x" : "w", rd, get_fp_reg(rn, fp_type));
        }
        return 0;
      }
    }
  }

  if ((insn & 0x3F800000) == 0x0C000000) {
    int Q = BIT(insn, 30);
    int L = BIT(insn, 22);
    int opcode = BITS(insn, 15, 12);
    int size = BITS(insn, 11, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    int regs = 0;
    switch (opcode) {
    case 7:
      regs = 1;
      break;
    case 10:
      regs = 2;
      break;
    case 6:
      regs = 3;
      break;
    case 2:
      regs = 4;
      break;
    default:
      return -1;
    }

    const char *arr = Q ? (size == 0   ? ".16b"
                           : size == 1 ? ".8h"
                           : size == 2 ? ".4s"
                                       : ".2d")
                        : (size == 0   ? ".8b"
                           : size == 1 ? ".4h"
                           : size == 2 ? ".2s"
                                       : ".1d");

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s%d", L ? "ld" : "st",
             regs);
    out->opcode = L ? A64_LD1 : A64_ST1;

    char regs_str[64] = "";
    for (int i = 0; i < regs; i++) {
      char tmp[16];
      snprintf(tmp, sizeof(tmp), "%sv%d%s", i > 0 ? ", " : "", (rt + i) & 31,
               arr);
      strcat(regs_str, tmp);
    }

    snprintf(out->operands_str, sizeof(out->operands_str), "{%s}, [x%d]",
             regs_str, rn);
    return 0;
  }

  return -1;
}
