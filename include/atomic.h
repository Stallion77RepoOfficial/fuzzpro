#ifndef FUZZPRO_ATOMIC_H
#define FUZZPRO_ATOMIC_H

#include "arm64dis.h"
#include <stdint.h>

int decode_atomics(uint32_t insn, uint64_t addr, A64Instruction *out);
int decode_ldst_extended(uint32_t insn, uint64_t addr, A64Instruction *out);

#endif
