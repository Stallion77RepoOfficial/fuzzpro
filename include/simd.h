#ifndef FUZZPRO_SIMD_H
#define FUZZPRO_SIMD_H

#include "arm64dis.h"
#include <stdint.h>

int decode_fp_simd(uint32_t insn, uint64_t addr, A64Instruction *out);

#endif
