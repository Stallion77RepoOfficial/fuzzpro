#include "instrument.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static const uint8_t count_class[256] = {
    0,   1,   2,   4,   8,   8,   8,   8,   16,  16,  16,  16,  16,  16,  16,
    16,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128};

int instrument_init(InstrumentState *state) {
  if (!state)
    return -1;

  state->trace_bits = mmap(NULL, FUZZPRO_MAP_SIZE, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (state->trace_bits == MAP_FAILED)
    return -1;

  state->virgin_bits = malloc(FUZZPRO_MAP_SIZE);
  if (!state->virgin_bits) {
    munmap(state->trace_bits, FUZZPRO_MAP_SIZE);
    return -1;
  }

  memset(state->trace_bits, 0, FUZZPRO_MAP_SIZE);
  memset(state->virgin_bits, 0xFF, FUZZPRO_MAP_SIZE);
  state->prev_loc = 0;
  state->map_size = FUZZPRO_MAP_SIZE;
  state->initialized = 1;

  return 0;
}

void instrument_cleanup(InstrumentState *state) {
  if (!state)
    return;
  if (state->trace_bits && state->trace_bits != MAP_FAILED) {
    munmap(state->trace_bits, state->map_size);
  }
  free(state->virgin_bits);
  memset(state, 0, sizeof(*state));
}

void instrument_reset(InstrumentState *state) {
  if (state && state->trace_bits) {
    memset(state->trace_bits, 0, state->map_size);
    state->prev_loc = 0;
  }
}

void instrument_classify_counts(InstrumentState *state) {
  if (!state || !state->trace_bits)
    return;
  for (size_t i = 0; i < state->map_size; i++) {
    state->trace_bits[i] = count_class[state->trace_bits[i]];
  }
}

int instrument_has_new_bits(InstrumentState *state) {
  if (!state || !state->trace_bits || !state->virgin_bits)
    return 0;

  int ret = 0;
  uint64_t *trace64 = (uint64_t *)state->trace_bits;
  uint64_t *virgin64 = (uint64_t *)state->virgin_bits;
  size_t len64 = state->map_size / 8;

  for (size_t i = 0; i < len64; i++) {
    if (trace64[i] && (trace64[i] & virgin64[i])) {
      uint8_t *t = (uint8_t *)&trace64[i];
      uint8_t *v = (uint8_t *)&virgin64[i];
      for (int j = 0; j < 8; j++) {
        if (t[j] && (t[j] & v[j])) {
          if (v[j] == 0xFF) {
            ret = 2;
            break;
          } else if (ret < 1)
            ret = 1;
        }
      }
      if (ret == 2)
        break;
    }
  }
  return ret;
}

void instrument_update_virgin(InstrumentState *state) {
  if (!state || !state->trace_bits || !state->virgin_bits)
    return;

  uint64_t *trace64 = (uint64_t *)state->trace_bits;
  uint64_t *virgin64 = (uint64_t *)state->virgin_bits;
  size_t len64 = state->map_size / 8;

  for (size_t i = 0; i < len64; i++) {
    virgin64[i] &= ~trace64[i];
  }
}

uint64_t instrument_count_bits(InstrumentState *state) {
  if (!state || !state->trace_bits)
    return 0;

  uint64_t count = 0;
  uint64_t *trace64 = (uint64_t *)state->trace_bits;
  size_t len64 = state->map_size / 8;

  for (size_t i = 0; i < len64; i++) {
    if (trace64[i])
      count += __builtin_popcountll(trace64[i]);
  }
  return count;
}
