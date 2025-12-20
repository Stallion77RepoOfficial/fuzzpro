#include "atomic.h"
#include <stdio.h>
#include <string.h>

#define BITS(v, hi, lo) (((v) >> (lo)) & ((1U << ((hi) - (lo) + 1)) - 1))
#define BIT(v, n) (((v) >> (n)) & 1)
#define SEXT(v, bits) ((int64_t)((v) << (64 - (bits))) >> (64 - (bits)))

static const char *gp_reg_64[] = {
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",  "x10",
    "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21",
    "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr"};

static const char *gp_reg_32[] = {
    "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",  "w8",  "w9",  "w10",
    "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21",
    "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr"};

static const char *get_reg(int reg, int is64) {
  if (reg < 0 || reg > 31)
    return "?";
  return is64 ? gp_reg_64[reg] : gp_reg_32[reg];
}

int decode_atomics(uint32_t insn, uint64_t addr, A64Instruction *out) {
  (void)addr;

  if ((insn & 0x3F000000) == 0x08000000) {
    int size = BITS(insn, 31, 30);
    int o2 = BIT(insn, 23);
    int L = BIT(insn, 22);
    int o1 = BIT(insn, 21);
    int rs = BITS(insn, 20, 16);
    int o0 = BIT(insn, 15);
    int rt2 = BITS(insn, 14, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    int is64 = (size == 3) || (size == 2);
    const char *mnem = NULL;

    if (o2 == 0 && L == 1 && o1 == 0 && o0 == 0) {
      mnem = size == 0 ? "ldxrb" : size == 1 ? "ldxrh" : "ldxr";
      out->opcode = size == 0 ? A64_LDXRB : size == 1 ? A64_LDXRH : A64_LDXR;
      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, [%s]",
               get_reg(rt, is64), gp_reg_64[rn]);
      return 0;
    }

    if (o2 == 0 && L == 0 && o1 == 0 && o0 == 0) {
      mnem = size == 0 ? "stxrb" : size == 1 ? "stxrh" : "stxr";
      out->opcode = size == 0 ? A64_STXRB : size == 1 ? A64_STXRH : A64_STXR;
      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, [%s]",
               gp_reg_32[rs], get_reg(rt, is64), gp_reg_64[rn]);
      return 0;
    }

    if (o2 == 0 && L == 1 && o1 == 1 && o0 == 0 && (size & 2)) {
      out->opcode = A64_LDXP;
      snprintf(out->mnemonic, sizeof(out->mnemonic), "ldxp");
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, [%s]",
               get_reg(rt, is64), get_reg(rt2, is64), gp_reg_64[rn]);
      return 0;
    }

    if (o2 == 0 && L == 0 && o1 == 1 && o0 == 0 && (size & 2)) {
      out->opcode = A64_STXP;
      snprintf(out->mnemonic, sizeof(out->mnemonic), "stxp");
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s, [%s]",
               gp_reg_32[rs], get_reg(rt, is64), get_reg(rt2, is64),
               gp_reg_64[rn]);
      return 0;
    }

    if (o2 == 1 && o1 == 0 && o0 == 1) {
      if (L) {
        mnem = size == 0 ? "ldarb" : size == 1 ? "ldarh" : "ldar";
        out->opcode = A64_LDAR;
      } else {
        mnem = size == 0 ? "stlrb" : size == 1 ? "stlrh" : "stlr";
        out->opcode = A64_STLR;
      }
      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, [%s]",
               get_reg(rt, is64), gp_reg_64[rn]);
      return 0;
    }

    if (o2 == 0 && o0 == 1) {
      if (L) {
        mnem = size == 0 ? "ldaxrb" : size == 1 ? "ldaxrh" : "ldaxr";
        out->opcode = A64_LDAXR;
      } else {
        mnem = size == 0 ? "stlxrb" : size == 1 ? "stlxrh" : "stlxr";
        out->opcode = A64_STLXR;
      }
      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
      if (L) {
        snprintf(out->operands_str, sizeof(out->operands_str), "%s, [%s]",
                 get_reg(rt, is64), gp_reg_64[rn]);
      } else {
        snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, [%s]",
                 gp_reg_32[rs], get_reg(rt, is64), gp_reg_64[rn]);
      }
      return 0;
    }
  }

  if ((insn & 0x3B200C00) == 0x38200000) {
    int size = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int A = BIT(insn, 23);
    int R = BIT(insn, 22);
    int rs = BITS(insn, 20, 16);
    int opc = BITS(insn, 14, 12);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    if (V == 0) {
      int is64 = (size == 3);
      const char *base = NULL;

      switch (opc) {
      case 0:
        base = "ldadd";
        out->opcode = A64_LDADD;
        break;
      case 1:
        base = "ldclr";
        out->opcode = A64_LDCLR;
        break;
      case 2:
        base = "ldeor";
        out->opcode = A64_LDEOR;
        break;
      case 3:
        base = "ldset";
        out->opcode = A64_LDSET;
        break;
      case 4:
        base = "ldsmax";
        out->opcode = A64_LDSMAX;
        break;
      case 5:
        base = "ldsmin";
        out->opcode = A64_LDSMIN;
        break;
      case 6:
        base = "ldumax";
        out->opcode = A64_LDUMAX;
        break;
      case 7:
        base = "ldumin";
        out->opcode = A64_LDUMIN;
        break;
      default:
        return -1;
      }

      char suffix[8] = "";
      if (A)
        strcat(suffix, "a");
      if (R)
        strcat(suffix, "l");
      if (size == 0)
        strcat(suffix, "b");
      else if (size == 1)
        strcat(suffix, "h");

      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s%s", base, suffix);
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, [%s]",
               get_reg(rs, is64), get_reg(rt, is64), gp_reg_64[rn]);
      return 0;
    }
  }

  if ((insn & 0x3FE00C00) == 0x08A00000 || (insn & 0x3FE00C00) == 0x48A00000) {
    int size = BITS(insn, 31, 30);
    int o2 = BIT(insn, 23);
    int L = BIT(insn, 22);
    int o1 = BIT(insn, 21);
    int rs = BITS(insn, 20, 16);
    int o0 = BIT(insn, 15);
    int rt2 = BITS(insn, 14, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    int is64 = (size == 3) || (size == 2);

    out->opcode = o0 ? A64_CASAL : (o1 ? A64_CASL : (L ? A64_CASA : A64_CAS));

    char mnem[16] = "cas";
    if (L)
      strcat(mnem, "a");
    if (o0)
      strcat(mnem, "l");
    if (size == 0)
      strcat(mnem, "b");
    else if (size == 1)
      strcat(mnem, "h");

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, [%s]",
             get_reg(rs, is64), get_reg(rt, is64), gp_reg_64[rn]);
    return 0;
  }

  if ((insn & 0x3FE00C00) == 0x08200C00 || (insn & 0x3FE00C00) == 0x48200C00) {
    int size = BITS(insn, 31, 30);
    int A = BIT(insn, 23);
    int R = BIT(insn, 22);
    int rs = BITS(insn, 20, 16);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    int is64 = (size >= 2);
    out->opcode = A64_SWP;

    char mnem[16] = "swp";
    if (A)
      strcat(mnem, "a");
    if (R)
      strcat(mnem, "l");
    if (size == 0)
      strcat(mnem, "b");
    else if (size == 1)
      strcat(mnem, "h");

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, [%s]",
             get_reg(rs, is64), get_reg(rt, is64), gp_reg_64[rn]);
    return 0;
  }

  return -1;
}

int decode_ldst_extended(uint32_t insn, uint64_t addr, A64Instruction *out) {
  (void)addr;

  if ((insn & 0x3B200C00) == 0x38200800) {
    int size = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int opc = BITS(insn, 23, 22);
    int rm = BITS(insn, 20, 16);
    int option = BITS(insn, 15, 13);
    int S = BIT(insn, 12);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    if (V == 0) {
      int is_store = (opc == 0);
      int is_signed = (opc >= 2);
      int is64 = (size >= 2) || (is_signed && opc == 2);

      const char *mnem;
      if (is_store) {
        mnem = size == 0 ? "strb" : size == 1 ? "strh" : "str";
        out->opcode = A64_STR_REG;
      } else {
        if (is_signed) {
          mnem = size == 0 ? "ldrsb" : size == 1 ? "ldrsh" : "ldrsw";
        } else {
          mnem = size == 0 ? "ldrb" : size == 1 ? "ldrh" : "ldr";
        }
        out->opcode = A64_LDR_REG;
      }

      const char *ext_names[] = {"uxtb", "uxth", "uxtw", "uxtx",
                                 "sxtb", "sxth", "sxtw", "sxtx"};

      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);

      if (option == 3 && S == 0) {
        snprintf(out->operands_str, sizeof(out->operands_str), "%s, [%s, %s]",
                 get_reg(rt, is64), gp_reg_64[rn], gp_reg_64[rm]);
      } else if (option == 3) {
        snprintf(out->operands_str, sizeof(out->operands_str),
                 "%s, [%s, %s, lsl #%d]", get_reg(rt, is64), gp_reg_64[rn],
                 gp_reg_64[rm], size);
      } else {
        snprintf(out->operands_str, sizeof(out->operands_str),
                 "%s, [%s, %s, %s]", get_reg(rt, is64), gp_reg_64[rn],
                 (option & 4) ? gp_reg_64[rm] : gp_reg_32[rm],
                 ext_names[option]);
      }
      return 0;
    }
  }

  if ((insn & 0x3B200C00) == 0x38000000) {
    int size = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int opc = BITS(insn, 23, 22);
    int64_t imm9 = SEXT(BITS(insn, 20, 12), 9);
    int op2 = BITS(insn, 11, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    if (V == 0 && op2 == 0) {
      int is_store = (opc == 0);
      int is64 = (size >= 2);

      const char *mnem;
      if (is_store) {
        mnem = size == 0 ? "sturb" : size == 1 ? "sturh" : "stur";
        out->opcode = A64_STUR;
      } else {
        mnem = size == 0 ? "ldurb" : size == 1 ? "ldurh" : "ldur";
        out->opcode = A64_LDUR;
      }

      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
      if (imm9 == 0) {
        snprintf(out->operands_str, sizeof(out->operands_str), "%s, [%s]",
                 get_reg(rt, is64), gp_reg_64[rn]);
      } else {
        snprintf(out->operands_str, sizeof(out->operands_str),
                 "%s, [%s, #%lld]", get_reg(rt, is64), gp_reg_64[rn],
                 (long long)imm9);
      }
      return 0;
    }

    if (V == 0 && (op2 == 1 || op2 == 3)) {
      int is_store = (opc == 0);
      int is_pre = (op2 == 3);
      int is64 = (size >= 2);

      const char *mnem = is_store ? "str" : "ldr";
      out->opcode = is_pre ? (is_store ? A64_STR_PRE : A64_LDR_PRE)
                           : (is_store ? A64_STR_POST : A64_LDR_POST);

      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
      if (is_pre) {
        snprintf(out->operands_str, sizeof(out->operands_str),
                 "%s, [%s, #%lld]!", get_reg(rt, is64), gp_reg_64[rn],
                 (long long)imm9);
      } else {
        snprintf(out->operands_str, sizeof(out->operands_str),
                 "%s, [%s], #%lld", get_reg(rt, is64), gp_reg_64[rn],
                 (long long)imm9);
      }
      return 0;
    }
  }

  return -1;
}
