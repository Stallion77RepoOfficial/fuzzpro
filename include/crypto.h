#ifndef FUZZPRO_CRYPTO_H
#define FUZZPRO_CRYPTO_H

#include "arm64dis.h"

int decode_crypto_aes(uint32_t insn, uint64_t addr, A64Instruction *out);
int decode_crypto_sha(uint32_t insn, uint64_t addr, A64Instruction *out);
int decode_crypto_sm3(uint32_t insn, uint64_t addr, A64Instruction *out);
int decode_crypto_sm4(uint32_t insn, uint64_t addr, A64Instruction *out);

#endif
