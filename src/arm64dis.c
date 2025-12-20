#include "arm64dis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BITS(v, hi, lo) (((v) >> (lo)) & ((1U << ((hi) - (lo) + 1)) - 1))
#define BIT(v, n) (((v) >> (n)) & 1)
#define SEXT(v, bits) ((int64_t)((v) << (64 - (bits))) >> (64 - (bits)))

#define BITS(v, hi, lo) (((v) >> (lo)) & ((1U << ((hi) - (lo) + 1)) - 1))
#define BIT(v, n) (((v) >> (n)) & 1)
#define SEXT(v, bits) ((int64_t)((v) << (64 - (bits))) >> (64 - (bits)))

static const char *gp_reg_names_64[] = {
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",  "x10",
    "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21",
    "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr"};
static const char *gp_reg_names_32[] = {
    "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",  "w8",  "w9",  "w10",
    "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21",
    "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr"};
static const char *cond_names[] = {"eq", "ne", "cs", "cc", "mi", "pl",
                                   "vs", "vc", "hi", "ls", "ge", "lt",
                                   "gt", "le", "al", "nv"};
static const char *shift_names[] = {"lsl", "lsr", "asr", "ror"};
static const char *extend_names[] = {"uxtb", "uxth", "uxtw", "uxtx",
                                     "sxtb", "sxth", "sxtw", "sxtx"};
static const char *barrier_names[] = {
    "#0", "oshld", "oshst", "osh", "#4",  "nshld", "nshst", "nsh",
    "#8", "ishld", "ishst", "ish", "#12", "ld",    "st",    "sy"};

const char *a64_reg_name(int reg, int is_64bit, int is_sp) {
  if (reg < 0 || reg > 31)
    return "???";
  if (reg == 31 && is_sp) {
    return is_64bit ? "sp" : "wsp";
  }
  return is_64bit ? gp_reg_names_64[reg] : gp_reg_names_32[reg];
}
const char *a64_cond_name(A64Condition cond) {
  if (cond > 15)
    return "???";
  return cond_names[cond];
}
const char *a64_shift_name(A64ShiftType shift) {
  if (shift > 3)
    return "???";
  return shift_names[shift];
}
const char *a64_extend_name(A64ExtendType extend) {
  if (extend > 7)
    return "???";
  return extend_names[extend];
}
const char *a64_vreg_name(int reg, A64SIMDArrangement arr) {
  static char buf[32];
  const char *suffixes[] = {"",    ".8b", ".16b", ".4h", ".8h", ".2s", ".4s",
                            ".1d", ".2d", ".b",   ".h",  ".s",  ".d"};
  if (arr >= sizeof(suffixes) / sizeof(suffixes[0]))
    arr = 0;
  snprintf(buf, sizeof(buf), "v%d%s", reg, suffixes[arr]);
  return buf;
}

static int decode_dp_imm(uint32_t insn, uint64_t addr, A64Instruction *out) {
  int op0 = BITS(insn, 25, 23);
  int sf = BIT(insn, 31);
  switch (op0) {
  case 0:
  case 1: 
  {
    int op = BIT(insn, 31);
    int rd = BITS(insn, 4, 0);
    int64_t immlo = BITS(insn, 30, 29);
    int64_t immhi = SEXT(BITS(insn, 23, 5), 19);
    int64_t imm = (immhi << 2) | immlo;
    out->opcode = op ? A64_ADRP : A64_ADR;
    out->operand_count = 2;
    out->operands[0].type = A64_OP_REG;
    out->operands[0].reg = rd;
    out->operands[0].is_64bit = 1;
    out->operands[1].type = A64_OP_LABEL;
    if (op) { 
      imm <<= 12;
      out->operands[1].imm = (addr & ~0xFFFULL) + imm;
    } else { 
      out->operands[1].imm = addr + imm;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", op ? "adrp" : "adr");
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, #0x%llx",
             a64_reg_name(rd, 1, 0), (unsigned long long)out->operands[1].imm);
    return 0;
  }
  case 2: 
  {
    int op = BIT(insn, 30);
    int S = BIT(insn, 29);
    int sh = BIT(insn, 22);
    int imm12 = BITS(insn, 21, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    int64_t imm = sh ? (imm12 << 12) : imm12;
    
    if (op == 0 && S == 0)
      out->opcode = A64_ADD_IMM;
    else if (op == 0 && S == 1)
      out->opcode = A64_ADDS_IMM;
    else if (op == 1 && S == 0)
      out->opcode = A64_SUB_IMM;
    else
      out->opcode = A64_SUBS_IMM;
    
    const char *mnem = NULL;
    if (S && rd == 31) {
      mnem = op ? "cmp" : "cmn";
      out->opcode = op ? A64_CMP_IMM : A64_CMN_IMM;
    } else if (!S && !op && rn == 31 && rd == 31) {
      mnem = "mov";
      out->opcode = A64_MOV_IMM;
    }
    if (!mnem) {
      mnem = op ? (S ? "subs" : "sub") : (S ? "adds" : "add");
    }
    out->operand_count = (mnem[0] == 'c') ? 2 : 3; 
    out->operands[0].type = A64_OP_REG_SP;
    out->operands[0].reg = rd;
    out->operands[0].is_64bit = sf;
    out->operands[0].is_sp = (rd == 31 && !S);
    int idx = (mnem[0] == 'c') ? 0 : 1;
    out->operands[idx].type = A64_OP_REG_SP;
    out->operands[idx].reg = rn;
    out->operands[idx].is_64bit = sf;
    out->operands[idx].is_sp = (rn == 31);
    out->operands[idx + 1].type = A64_OP_IMM;
    out->operands[idx + 1].imm = imm;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (sh && (imm12 != 0)) {
      snprintf(out->operands_str, sizeof(out->operands_str),
               "%s, %s, #0x%x, lsl #12", a64_reg_name(rd, sf, rd == 31 && !S),
               a64_reg_name(rn, sf, rn == 31), imm12);
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, #0x%llx",
               a64_reg_name(rd, sf, rd == 31 && !S),
               a64_reg_name(rn, sf, rn == 31), (unsigned long long)imm);
    }
    return 0;
  }
  case 4: 
  {
    int opc = BITS(insn, 30, 29);
    int N = BIT(insn, 22);
    int immr = BITS(insn, 21, 16);
    int imms = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    
    uint64_t imm = 0;
    int len = 0;
    if (N) {
      len = 6;
    } else {
      len = 31 - __builtin_clz((imms ^ 0x3F) & 0x3F);
      if (len < 1)
        return -1;
    }
    int levels = (1 << len) - 1;
    int s = imms & levels;
    int r = immr & levels;
    int diff = s - r;
    int esize = 1 << len;
    uint64_t welem = ((1ULL << (s + 1)) - 1);
    uint64_t wmask = 0;
    for (int i = 0; i < 64; i += esize) {
      wmask |= ((welem >> r) | (welem << (esize - r))) << i;
      wmask &= sf ? ~0ULL : 0xFFFFFFFFULL;
    }
    imm = wmask & (sf ? ~0ULL : 0xFFFFFFFFULL);
    const char *mnem;
    switch (opc) {
    case 0:
      out->opcode = A64_AND_IMM;
      mnem = "and";
      break;
    case 1:
      out->opcode = A64_ORR_IMM;
      mnem = "orr";
      break;
    case 2:
      out->opcode = A64_EOR_IMM;
      mnem = "eor";
      break;
    case 3:
      out->opcode = A64_ANDS_IMM;
      mnem = "ands";
      break;
    default:
      return -1;
    }
    
    if (opc == 3 && rd == 31) {
      mnem = "tst";
      out->opcode = A64_TST_IMM;
    } else if (opc == 1 && rn == 31) {
      mnem = "mov";
      out->opcode = A64_MOV_IMM;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, #0x%llx",
             a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0),
             (unsigned long long)imm);
    return 0;
  }
  case 5: 
  {
    int opc = BITS(insn, 30, 29);
    int hw = BITS(insn, 22, 21);
    int imm16 = BITS(insn, 20, 5);
    int rd = BITS(insn, 4, 0);
    if (!sf && hw >= 2)
      return -1; 
    const char *mnem;
    switch (opc) {
    case 0:
      out->opcode = A64_MOVN;
      mnem = "movn";
      break;
    case 2:
      out->opcode = A64_MOVZ;
      mnem = "movz";
      break;
    case 3:
      out->opcode = A64_MOVK;
      mnem = "movk";
      break;
    default:
      return -1;
    }
    
    uint64_t imm = (uint64_t)imm16 << (hw * 16);
    if (opc == 2 && hw == 0 && imm16 != 0) {
      
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (hw == 0) {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, #0x%x",
               a64_reg_name(rd, sf, 0), imm16);
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str),
               "%s, #0x%x, lsl #%d", a64_reg_name(rd, sf, 0), imm16, hw * 16);
    }
    return 0;
  }
  case 6: 
  {
    int opc = BITS(insn, 30, 29);
    int N = BIT(insn, 22);
    int immr = BITS(insn, 21, 16);
    int imms = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    if (sf != N)
      return -1;
    const char *mnem;
    switch (opc) {
    case 0:
      out->opcode = A64_SBFM;
      mnem = "sbfm";
      break;
    case 1:
      out->opcode = A64_BFM;
      mnem = "bfm";
      break;
    case 2:
      out->opcode = A64_UBFM;
      mnem = "ubfm";
      break;
    default:
      return -1;
    }
    
    int bits = sf ? 64 : 32;
    if (opc == 2 && imms == bits - 1) { 
      mnem = "lsr";
      out->opcode = A64_LSR_IMM;
    } else if (opc == 2 && imms + 1 == immr) { 
      mnem = "lsl";
      out->opcode = A64_LSL_IMM;
    } else if (opc == 0 && imms == bits - 1) { 
      mnem = "asr";
      out->opcode = A64_ASR_IMM;
    } else if (opc == 0 && immr == 0 && imms == 7) { 
      mnem = "sxtb";
      out->opcode = A64_SXTB;
    } else if (opc == 0 && immr == 0 && imms == 15) { 
      mnem = "sxth";
      out->opcode = A64_SXTH;
    } else if (opc == 0 && immr == 0 && imms == 31) { 
      mnem = "sxtw";
      out->opcode = A64_SXTW;
    } else if (opc == 2 && immr == 0 && imms == 7) { 
      mnem = "uxtb";
      out->opcode = A64_UXTB;
    } else if (opc == 2 && immr == 0 && imms == 15) { 
      mnem = "uxth";
      out->opcode = A64_UXTH;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, #%d, #%d",
             a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0), immr, imms);
    return 0;
  }
  case 7: 
  {
    int op21 = BITS(insn, 30, 29);
    int N = BIT(insn, 22);
    int o0 = BIT(insn, 21);
    int rm = BITS(insn, 20, 16);
    int imms = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    if (op21 != 0 || o0 != 0 || sf != N)
      return -1;
    out->opcode = A64_EXTR;
    const char *mnem = "extr";
    
    if (rn == rm) {
      mnem = "ror";
      out->opcode = A64_ROR_IMM;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s, #%d",
             a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0),
             a64_reg_name(rm, sf, 0), imms);
    return 0;
  }
  }
  return -1;
}

static int decode_branches(uint32_t insn, uint64_t addr, A64Instruction *out) {
  int op0 = BITS(insn, 31, 29);
  int op1 = BITS(insn, 25, 22);
  
  if ((insn & 0x7C000000) == 0x14000000) {
    int op = BIT(insn, 31);
    int64_t imm26 = SEXT(BITS(insn, 25, 0), 26);
    uint64_t target = addr + (imm26 << 2);
    out->opcode = op ? A64_BL : A64_B;
    out->is_branch = 1;
    out->is_call = op;
    out->branch_target = target;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", op ? "bl" : "b");
    snprintf(out->operands_str, sizeof(out->operands_str), "#0x%llx",
             (unsigned long long)target);
    return 0;
  }
  
  if ((insn & 0xFE000000) == 0x54000000) {
    int o1 = BIT(insn, 24);
    int64_t imm19 = SEXT(BITS(insn, 23, 5), 19);
    int o0 = BIT(insn, 4);
    int cond = BITS(insn, 3, 0);
    if (o1 || o0)
      return -1;
    uint64_t target = addr + (imm19 << 2);
    out->opcode = A64_B_COND;
    out->is_branch = 1;
    out->is_conditional = 1;
    out->branch_target = target;
    out->operands[0].cond = cond;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "b.%s", a64_cond_name(cond));
    snprintf(out->operands_str, sizeof(out->operands_str), "#0x%llx",
             (unsigned long long)target);
    return 0;
  }
  
  if ((insn & 0x7E000000) == 0x34000000) {
    int sf = BIT(insn, 31);
    int op = BIT(insn, 24);
    int64_t imm19 = SEXT(BITS(insn, 23, 5), 19);
    int rt = BITS(insn, 4, 0);
    uint64_t target = addr + (imm19 << 2);
    out->opcode = op ? A64_CBNZ : A64_CBZ;
    out->is_branch = 1;
    out->is_conditional = 1;
    out->branch_target = target;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", op ? "cbnz" : "cbz");
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, #0x%llx",
             a64_reg_name(rt, sf, 0), (unsigned long long)target);
    return 0;
  }
  
  if ((insn & 0x7E000000) == 0x36000000) {
    int b5 = BIT(insn, 31);
    int op = BIT(insn, 24);
    int b40 = BITS(insn, 23, 19);
    int64_t imm14 = SEXT(BITS(insn, 18, 5), 14);
    int rt = BITS(insn, 4, 0);
    int bit = (b5 << 5) | b40;
    uint64_t target = addr + (imm14 << 2);
    out->opcode = op ? A64_TBNZ : A64_TBZ;
    out->is_branch = 1;
    out->is_conditional = 1;
    out->branch_target = target;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", op ? "tbnz" : "tbz");
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, #%d, #0x%llx",
             a64_reg_name(rt, bit >= 32, 0), bit, (unsigned long long)target);
    return 0;
  }
  
  if ((insn & 0xFE000000) == 0xD6000000) {
    int opc = BITS(insn, 24, 21);
    int op2 = BITS(insn, 20, 16);
    int op3 = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int op4 = BITS(insn, 4, 0);
    if (op2 != 0x1F || op3 != 0 || op4 != 0)
      return -1;
    const char *mnem;
    switch (opc) {
    case 0:
      out->opcode = A64_BR;
      mnem = "br";
      out->is_branch = 1;
      out->is_indirect = 1;
      break;
    case 1:
      out->opcode = A64_BLR;
      mnem = "blr";
      out->is_branch = 1;
      out->is_call = 1;
      out->is_indirect = 1;
      break;
    case 2:
      out->opcode = A64_RET;
      mnem = "ret";
      out->is_branch = 1;
      out->is_return = 1;
      break;
    case 4:
      out->opcode = A64_ERET;
      mnem = "eret";
      out->is_branch = 1;
      out->is_return = 1;
      break;
    case 5:
      out->opcode = A64_DRPS;
      mnem = "drps";
      out->is_branch = 1;
      break;
    default:
      return -1;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (opc <= 2) {
      if (opc == 2 && rn == 30) {
        out->operands_str[0] = '\0'; 
      } else {
        snprintf(out->operands_str, sizeof(out->operands_str), "%s",
                 a64_reg_name(rn, 1, 0));
      }
    }
    return 0;
  }
  return -1;
}

static int decode_ldst(uint32_t insn, uint64_t addr, A64Instruction *out) {
  int op0 = BITS(insn, 31, 28);
  int op1 = BIT(insn, 26);
  int op2 = BITS(insn, 24, 23);
  int op3 = BITS(insn, 21, 16);
  int op4 = BITS(insn, 11, 10);
  
  if ((insn & 0x3B000000) == 0x39000000) {
    int size = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int opc = BITS(insn, 23, 22);
    int imm12 = BITS(insn, 21, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);
    int scale = size;
    if (V)
      scale = (opc >> 1) ? 4 : size;
    int64_t offset = imm12 << scale;
    const char *mnem;
    int is_store = (opc == 0);
    int is_signed = (opc >= 2);
    if (!V) {
      switch (size) {
      case 0:
        mnem = is_store ? "strb"
                        : (is_signed ? (opc == 2 ? "ldrsb" : "ldrsb") : "ldrb");
        break;
      case 1:
        mnem = is_store ? "strh"
                        : (is_signed ? (opc == 2 ? "ldrsh" : "ldrsh") : "ldrh");
        break;
      case 2:
        mnem = is_store ? "str" : (is_signed ? "ldrsw" : "ldr");
        break;
      case 3:
        mnem = is_store ? "str" : "ldr";
        break;
      default:
        return -1;
      }
      out->opcode = is_store ? A64_STR_IMM : A64_LDR_IMM;
    } else {
      mnem = is_store ? "str" : "ldr";
      out->opcode = is_store ? A64_STR_SIMD : A64_LDR_SIMD;
    }
    out->is_load = !is_store;
    out->is_store = is_store;
    out->access_size = 1 << size;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (offset == 0) {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, [%s]",
               a64_reg_name(rt, size >= 2, 0), a64_reg_name(rn, 1, 1));
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, [%s, #%lld]",
               a64_reg_name(rt, size >= 2, 0), a64_reg_name(rn, 1, 1),
               (long long)offset);
    }
    return 0;
  }
  
  if ((insn & 0x3A000000) == 0x28000000) {
    int opc = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int type = BITS(insn, 24, 23);
    int L = BIT(insn, 22);
    int64_t imm7 = SEXT(BITS(insn, 21, 15), 7);
    int rt2 = BITS(insn, 14, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);
    int sf = (opc >> 1);
    int scale = 2 + sf;
    if (V)
      scale = 2 + opc;
    int64_t offset = imm7 << scale;
    const char *mnem;
    if (L) {
      out->opcode =
          (type == 1) ? A64_LDP_POST : ((type == 3) ? A64_LDP_PRE : A64_LDP);
      mnem = (type == 2) ? "ldnp" : "ldp";
    } else {
      out->opcode =
          (type == 1) ? A64_STP_POST : ((type == 3) ? A64_STP_PRE : A64_STP);
      mnem = (type == 2) ? "stnp" : "stp";
    }
    out->is_load = L;
    out->is_store = !L;
    out->access_size = 2 << scale;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (type == 1) { 
      snprintf(out->operands_str, sizeof(out->operands_str),
               "%s, %s, [%s], #%lld", a64_reg_name(rt, sf, 0),
               a64_reg_name(rt2, sf, 0), a64_reg_name(rn, 1, 1),
               (long long)offset);
    } else if (type == 3) { 
      snprintf(out->operands_str, sizeof(out->operands_str),
               "%s, %s, [%s, #%lld]!", a64_reg_name(rt, sf, 0),
               a64_reg_name(rt2, sf, 0), a64_reg_name(rn, 1, 1),
               (long long)offset);
    } else { 
      if (offset == 0) {
        snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, [%s]",
                 a64_reg_name(rt, sf, 0), a64_reg_name(rt2, sf, 0),
                 a64_reg_name(rn, 1, 1));
      } else {
        snprintf(out->operands_str, sizeof(out->operands_str),
                 "%s, %s, [%s, #%lld]", a64_reg_name(rt, sf, 0),
                 a64_reg_name(rt2, sf, 0), a64_reg_name(rn, 1, 1),
                 (long long)offset);
      }
    }
    return 0;
  }
  
  if ((insn & 0x3B000000) == 0x18000000) {
    int opc = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int64_t imm19 = SEXT(BITS(insn, 23, 5), 19);
    int rt = BITS(insn, 4, 0);
    uint64_t target = addr + (imm19 << 2);
    out->opcode = A64_LDR_LIT;
    out->is_load = 1;
    out->access_size = 4 << opc;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s",
             opc == 1 ? "ldrsw" : "ldr");
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, #0x%llx",
             a64_reg_name(rt, opc != 0, 0), (unsigned long long)target);
    return 0;
  }
  return -1;
}

static int decode_system(uint32_t insn, uint64_t addr, A64Instruction *out) {
  
  if ((insn & 0xFF000000) == 0xD4000000) {
    int opc = BITS(insn, 23, 21);
    int imm16 = BITS(insn, 20, 5);
    int op2 = BITS(insn, 4, 2);
    int LL = BITS(insn, 1, 0);
    const char *mnem;
    switch ((opc << 2) | LL) {
    case 1:
      out->opcode = A64_SVC;
      mnem = "svc";
      break;
    case 2:
      out->opcode = A64_HVC;
      mnem = "hvc";
      break;
    case 3:
      out->opcode = A64_SMC;
      mnem = "smc";
      break;
    case 0:
      out->opcode = A64_BRK;
      mnem = "brk";
      break;
    case 8:
      out->opcode = A64_HLT;
      mnem = "hlt";
      break;
    default:
      return -1;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "#0x%x", imm16);
    return 0;
  }
  
  if ((insn & 0xFFFFF01F) == 0xD503201F) {
    int CRm = BITS(insn, 11, 8);
    int op2 = BITS(insn, 7, 5);
    const char *mnem;
    switch (op2) {
    case 0:
      out->opcode = A64_NOP;
      mnem = "nop";
      break;
    case 1:
      out->opcode = A64_YIELD;
      mnem = "yield";
      break;
    case 2:
      out->opcode = A64_WFE;
      mnem = "wfe";
      break;
    case 3:
      out->opcode = A64_WFI;
      mnem = "wfi";
      break;
    case 4:
      out->opcode = A64_SEV;
      mnem = "sev";
      break;
    case 5:
      out->opcode = A64_SEVL;
      mnem = "sevl";
      break;
    default:
      out->opcode = A64_HINT;
      mnem = "hint";
      break;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    out->operands_str[0] = '\0';
    return 0;
  }
  return -1;
}

static int decode_dp_reg(uint32_t insn, uint64_t addr, A64Instruction *out) {
  int sf = BIT(insn, 31);
  int op0 = BIT(insn, 30);
  int op1 = BIT(insn, 28);
  int op2 = BITS(insn, 24, 21);
  int op3 = BITS(insn, 15, 10);
  
  if ((insn & 0x1F000000) == 0x0A000000) {
    int opc = BITS(insn, 30, 29);
    int shift = BITS(insn, 23, 22);
    int N = BIT(insn, 21);
    int rm = BITS(insn, 20, 16);
    int imm6 = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    const char *mnem;
    switch ((opc << 1) | N) {
    case 0:
      out->opcode = A64_AND_REG;
      mnem = "and";
      break;
    case 1:
      out->opcode = A64_BIC;
      mnem = "bic";
      break;
    case 2:
      out->opcode = A64_ORR_REG;
      mnem = "orr";
      break;
    case 3:
      out->opcode = A64_ORN;
      mnem = "orn";
      break;
    case 4:
      out->opcode = A64_EOR_REG;
      mnem = "eor";
      break;
    case 5:
      out->opcode = A64_EON;
      mnem = "eon";
      break;
    case 6:
      out->opcode = A64_ANDS_REG;
      mnem = "ands";
      break;
    case 7:
      out->opcode = A64_BICS;
      mnem = "bics";
      break;
    default:
      return -1;
    }
    
    if (opc == 1 && N == 0 && rn == 31) {
      mnem = "mov";
      out->opcode = A64_MOV_REG;
    } else if (opc == 1 && N == 1 && rn == 31) {
      mnem = "mvn";
      out->opcode = A64_MVN;
    } else if (opc == 3 && N == 0 && rd == 31) {
      mnem = "tst";
      out->opcode = A64_TST_REG;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (imm6 == 0) {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s",
               a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0),
               a64_reg_name(rm, sf, 0));
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str),
               "%s, %s, %s, %s #%d", a64_reg_name(rd, sf, 0),
               a64_reg_name(rn, sf, 0), a64_reg_name(rm, sf, 0),
               shift_names[shift], imm6);
    }
    return 0;
  }
  
  if ((insn & 0x1F200000) == 0x0B000000) {
    int op = BIT(insn, 30);
    int S = BIT(insn, 29);
    int shift = BITS(insn, 23, 22);
    int rm = BITS(insn, 20, 16);
    int imm6 = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    if (shift == 3)
      return -1; 
    const char *mnem;
    if (op == 0 && S == 0) {
      out->opcode = A64_ADD_REG;
      mnem = "add";
    } else if (op == 0 && S == 1) {
      out->opcode = A64_ADDS_REG;
      mnem = "adds";
    } else if (op == 1 && S == 0) {
      out->opcode = A64_SUB_REG;
      mnem = "sub";
    } else {
      out->opcode = A64_SUBS_REG;
      mnem = "subs";
    }
    
    if (S && rd == 31) {
      mnem = op ? "cmp" : "cmn";
      out->opcode = op ? A64_CMP_REG : A64_CMN_REG;
    } else if (op && !S && rn == 31) {
      mnem = "neg";
      out->opcode = A64_NEG;
    } else if (op && S && rn == 31) {
      mnem = "negs";
      out->opcode = A64_NEGS;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (imm6 == 0 && shift == 0) {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s",
               a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0),
               a64_reg_name(rm, sf, 0));
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str),
               "%s, %s, %s, %s #%d", a64_reg_name(rd, sf, 0),
               a64_reg_name(rn, sf, 0), a64_reg_name(rm, sf, 0),
               shift_names[shift], imm6);
    }
    return 0;
  }
  
  if ((insn & 0x1FE00000) == 0x0B200000) {
    int op = BIT(insn, 30);
    int S = BIT(insn, 29);
    int rm = BITS(insn, 20, 16);
    int option = BITS(insn, 15, 13);
    int imm3 = BITS(insn, 12, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    const char *mnem;
    if (op == 0 && S == 0) {
      out->opcode = A64_ADD_EXT;
      mnem = "add";
    } else if (op == 0 && S == 1) {
      out->opcode = A64_ADDS_EXT;
      mnem = "adds";
    } else if (op == 1 && S == 0) {
      out->opcode = A64_SUB_EXT;
      mnem = "sub";
    } else {
      out->opcode = A64_SUBS_EXT;
      mnem = "subs";
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (imm3 == 0) {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s, %s",
               a64_reg_name(rd, sf, rd == 31), a64_reg_name(rn, sf, rn == 31),
               a64_reg_name(rm, option >= 3, 0), extend_names[option]);
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str),
               "%s, %s, %s, %s #%d", a64_reg_name(rd, sf, rd == 31),
               a64_reg_name(rn, sf, rn == 31), a64_reg_name(rm, option >= 3, 0),
               extend_names[option], imm3);
    }
    return 0;
  }
  
  if ((insn & 0x1F800000) == 0x1B000000) {
    int op54 = BITS(insn, 30, 29);
    int op31 = BITS(insn, 23, 21);
    int rm = BITS(insn, 20, 16);
    int o0 = BIT(insn, 15);
    int ra = BITS(insn, 14, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    if (op54 != 0)
      return -1;
    const char *mnem;
    if (op31 == 0 && o0 == 0) {
      out->opcode = (ra == 31) ? A64_MUL : A64_MADD;
      mnem = (ra == 31) ? "mul" : "madd";
    } else if (op31 == 0 && o0 == 1) {
      out->opcode = (ra == 31) ? A64_MNEG : A64_MSUB;
      mnem = (ra == 31) ? "mneg" : "msub";
    } else if (op31 == 1 && o0 == 0) {
      out->opcode = (ra == 31) ? A64_SMULL : A64_SMADDL;
      mnem = (ra == 31) ? "smull" : "smaddl";
    } else if (op31 == 1 && o0 == 1) {
      out->opcode = (ra == 31) ? A64_SMNEGL : A64_SMSUBL;
      mnem = (ra == 31) ? "smnegl" : "smsubl";
    } else if (op31 == 2 && o0 == 0) {
      out->opcode = A64_SMULH;
      mnem = "smulh";
    } else if (op31 == 5 && o0 == 0) {
      out->opcode = (ra == 31) ? A64_UMULL : A64_UMADDL;
      mnem = (ra == 31) ? "umull" : "umaddl";
    } else if (op31 == 5 && o0 == 1) {
      out->opcode = (ra == 31) ? A64_UMNEGL : A64_UMSUBL;
      mnem = (ra == 31) ? "umnegl" : "umsubl";
    } else if (op31 == 6 && o0 == 0) {
      out->opcode = A64_UMULH;
      mnem = "umulh";
    } else {
      return -1;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    if (ra == 31 || op31 == 2 || op31 == 6) {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s",
               a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf || op31 >= 1, 0),
               a64_reg_name(rm, sf || op31 >= 1, 0));
    } else {
      snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s, %s",
               a64_reg_name(rd, sf, 0), a64_reg_name(rn, op31 >= 1 ? 0 : sf, 0),
               a64_reg_name(rm, op31 >= 1 ? 0 : sf, 0),
               a64_reg_name(ra, sf, 0));
    }
    return 0;
  }
  
  if ((insn & 0x1FE0FC00) == 0x1AC00800) {
    int rm = BITS(insn, 20, 16);
    int o1 = BIT(insn, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    out->opcode = o1 ? A64_SDIV : A64_UDIV;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", o1 ? "sdiv" : "udiv");
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s",
             a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0),
             a64_reg_name(rm, sf, 0));
    return 0;
  }
  
  if ((insn & 0x1FE0F000) == 0x1AC02000) {
    int rm = BITS(insn, 20, 16);
    int op2 = BITS(insn, 11, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    const char *mnem;
    switch (op2) {
    case 0:
      out->opcode = A64_LSLV;
      mnem = "lsl";
      break;
    case 1:
      out->opcode = A64_LSRV;
      mnem = "lsr";
      break;
    case 2:
      out->opcode = A64_ASRV;
      mnem = "asr";
      break;
    case 3:
      out->opcode = A64_RORV;
      mnem = "ror";
      break;
    default:
      return -1;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s",
             a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0),
             a64_reg_name(rm, sf, 0));
    return 0;
  }
  
  if ((insn & 0x1FE00000) == 0x1A800000) {
    int op = BIT(insn, 30);
    int S = BIT(insn, 29);
    int rm = BITS(insn, 20, 16);
    int cond = BITS(insn, 15, 12);
    int op2 = BITS(insn, 11, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);
    if (S)
      return -1;
    const char *mnem;
    switch ((op << 2) | op2) {
    case 0:
      out->opcode = A64_CSEL;
      mnem = "csel";
      break;
    case 1:
      out->opcode = A64_CSINC;
      mnem = "csinc";
      break;
    case 4:
      out->opcode = A64_CSINV;
      mnem = "csinv";
      break;
    case 5:
      out->opcode = A64_CSNEG;
      mnem = "csneg";
      break;
    default:
      return -1;
    }
    
    if (op2 == 1 && rn == 31 && rm == 31) {
      mnem = op ? "csetm" : "cset";
      out->opcode = op ? A64_CSETM : A64_CSET;
    } else if (op2 == 1 && rn == rm && rn != 31) {
      mnem = op ? "cinv" : "cinc";
      out->opcode = op ? A64_CINV : A64_CINC;
    } else if (op2 == 1 && op && rn == rm) {
      mnem = "cneg";
      out->opcode = A64_CNEG;
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mnem);
    snprintf(out->operands_str, sizeof(out->operands_str), "%s, %s, %s, %s",
             a64_reg_name(rd, sf, 0), a64_reg_name(rn, sf, 0),
             a64_reg_name(rm, sf, 0), a64_cond_name(cond));
    return 0;
  }
  return -1;
}


static int decode_dp_imm(uint32_t insn, uint64_t addr, A64Instruction *out);
int a64_decode(uint32_t insn, uint64_t addr, A64Instruction *out) {
  if (!out)
    return -1;
  memset(out, 0, sizeof(A64Instruction));
  out->address = addr;
  out->raw = insn;
  
  int op0 = BITS(insn, 28, 25);
  
  
  if (decode_branches(insn, addr, out) == 0)
    return 0;
  
  if (decode_system(insn, addr, out) == 0)
    return 0;
  
  if (op0 == 0x8 || op0 == 0x9) {
    if (decode_dp_imm(insn, addr, out) == 0)
      return 0;
  }
  
  if (decode_ldst(insn, addr, out) == 0)
    return 0;
  
  if (decode_dp_reg(insn, addr, out) == 0)
    return 0;
  
  out->opcode = A64_INVALID;
  snprintf(out->mnemonic, sizeof(out->mnemonic), ".word");
  snprintf(out->operands_str, sizeof(out->operands_str), "0x%08x", insn);
  return -1;
}
int a64_disasm_buffer(const uint8_t *buf, size_t len, uint64_t base_addr,
                      A64Instruction *out, size_t max_insns) {
  if (!buf || !out || len < 4)
    return 0;
  size_t count = 0;
  size_t offset = 0;
  while (offset + 4 <= len && count < max_insns) {
    uint32_t insn = *(uint32_t *)(buf + offset);
    a64_decode(insn, base_addr + offset, &out[count]);
    count++;
    offset += 4;
  }
  return (int)count;
}
void a64_format(const A64Instruction *insn, char *buf, size_t buflen) {
  if (!insn || !buf || buflen == 0)
    return;
  if (insn->operands_str[0]) {
    snprintf(buf, buflen, "%-8s %s", insn->mnemonic, insn->operands_str);
  } else {
    snprintf(buf, buflen, "%s", insn->mnemonic);
  }
}
