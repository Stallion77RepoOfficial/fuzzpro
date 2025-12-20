#include "crypto.h"
#include <stdio.h>
#include <string.h>

#define BITS(v, hi, lo) (((v) >> (lo)) & ((1U << ((hi) - (lo) + 1)) - 1))

int decode_crypto_aes(uint32_t insn, uint64_t addr, A64Instruction *out) {
  if ((insn & 0xFF3E0C00) != 0x4E280800)
    return 0;

  int op = BITS(insn, 13, 12);
  int rd = BITS(insn, 4, 0);
  int rn = BITS(insn, 9, 5);

  out->opcode = A64_AESE + op;
  out->address = addr;
  out->raw = insn;
  out->operand_count = 2;
  out->operands[0].type = A64_OP_VREG;
  out->operands[0].reg = rd;
  out->operands[1].type = A64_OP_VREG;
  out->operands[1].reg = rn;

  const char *names[] = {"aese", "aesd", "aesmc", "aesimc"};
  if (op < 4) {
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", names[op]);
  }
  snprintf(out->operands_str, sizeof(out->operands_str), "v%d.16b, v%d.16b", rd,
           rn);

  return 1;
}

int decode_crypto_sha(uint32_t insn, uint64_t addr, A64Instruction *out) {
  if ((insn & 0xFF208C00) == 0x5E000000) {
    int op = BITS(insn, 14, 12);
    int rd = BITS(insn, 4, 0);
    int rn = BITS(insn, 9, 5);
    int rm = BITS(insn, 20, 16);

    out->opcode = A64_SHA1C + op;
    out->address = addr;
    out->raw = insn;
    out->operand_count = 3;
    out->operands[0].type = A64_OP_VREG;
    out->operands[0].reg = rd;
    out->operands[1].type = A64_OP_VREG;
    out->operands[1].reg = rn;
    out->operands[2].type = A64_OP_VREG;
    out->operands[2].reg = rm;

    const char *names[] = {"sha1c",   "sha1p",    "sha1m",    "sha1su0",
                           "sha256h", "sha256h2", "sha256su1"};
    if (op < 7) {
      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", names[op]);
    }
    snprintf(out->operands_str, sizeof(out->operands_str), "q%d, s%d, v%d.4s",
             rd, rn, rm);
    return 1;
  }

  if ((insn & 0xFF3E0C00) == 0x5E280800) {
    int op = BITS(insn, 13, 12);
    int rd = BITS(insn, 4, 0);
    int rn = BITS(insn, 9, 5);

    out->opcode = A64_SHA1H + op;
    out->address = addr;
    out->raw = insn;
    out->operand_count = 2;
    out->operands[0].type = A64_OP_VREG;
    out->operands[0].reg = rd;
    out->operands[1].type = A64_OP_VREG;
    out->operands[1].reg = rn;

    const char *names[] = {"sha1h", "sha1su1", "sha256su0"};
    if (op < 3) {
      snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", names[op]);
    }
    snprintf(out->operands_str, sizeof(out->operands_str), "s%d, s%d", rd, rn);
    return 1;
  }

  return 0;
}

int decode_crypto_sm3(uint32_t insn, uint64_t addr, A64Instruction *out) {
  if ((insn & 0xFFE0FC00) == 0xCE60C000) {
    int rd = BITS(insn, 4, 0);
    int rn = BITS(insn, 9, 5);
    int rm = BITS(insn, 20, 16);

    out->opcode = A64_SM3SS1;
    out->address = addr;
    out->raw = insn;
    out->operand_count = 3;
    out->operands[0].type = A64_OP_VREG;
    out->operands[0].reg = rd;
    out->operands[1].type = A64_OP_VREG;
    out->operands[1].reg = rn;
    out->operands[2].type = A64_OP_VREG;
    out->operands[2].reg = rm;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "sm3ss1");
    snprintf(out->operands_str, sizeof(out->operands_str),
             "v%d.4s, v%d.4s, v%d.4s", rd, rn, rm);
    return 1;
  }

  return 0;
}

int decode_crypto_sm4(uint32_t insn, uint64_t addr, A64Instruction *out) {
  if ((insn & 0xFFFFFC00) == 0xCEC08400) {
    int rd = BITS(insn, 4, 0);
    int rn = BITS(insn, 9, 5);

    out->opcode = A64_SM4E;
    out->address = addr;
    out->raw = insn;
    out->operand_count = 2;
    out->operands[0].type = A64_OP_VREG;
    out->operands[0].reg = rd;
    out->operands[1].type = A64_OP_VREG;
    out->operands[1].reg = rn;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "sm4e");
    snprintf(out->operands_str, sizeof(out->operands_str), "v%d.4s, v%d.4s", rd,
             rn);
    return 1;
  }

  if ((insn & 0xFFE0FC00) == 0xCE60C800) {
    int rd = BITS(insn, 4, 0);
    int rn = BITS(insn, 9, 5);
    int rm = BITS(insn, 20, 16);

    out->opcode = A64_SM4EKEY;
    out->address = addr;
    out->raw = insn;
    out->operand_count = 3;
    out->operands[0].type = A64_OP_VREG;
    out->operands[0].reg = rd;
    out->operands[1].type = A64_OP_VREG;
    out->operands[1].reg = rn;
    out->operands[2].type = A64_OP_VREG;
    out->operands[2].reg = rm;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "sm4ekey");
    snprintf(out->operands_str, sizeof(out->operands_str),
             "v%d.4s, v%d.4s, v%d.4s", rd, rn, rm);
    return 1;
  }

  return 0;
}
