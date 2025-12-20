#ifndef FUZZPRO_INSTRUMENT_H
#define FUZZPRO_INSTRUMENT_H

#include <stddef.h>
#include <stdint.h>

#define FUZZPRO_SHM_ENV "__FUZZPRO_SHM_ID"
#define FUZZPRO_MAP_SIZE_POW2 16
#define FUZZPRO_MAP_SIZE (1U << FUZZPRO_MAP_SIZE_POW2)
#define FUZZPRO_FORKSRV_FD 198

typedef struct {
  uint8_t *trace_bits;
  uint8_t *virgin_bits;
  uint32_t prev_loc;
  size_t map_size;
  int shm_id;
  int initialized;
} InstrumentState;

int instrument_init(InstrumentState *state);
void instrument_cleanup(InstrumentState *state);
void instrument_reset(InstrumentState *state);
int instrument_has_new_bits(InstrumentState *state);
void instrument_update_virgin(InstrumentState *state);
uint64_t instrument_count_bits(InstrumentState *state);
void instrument_classify_counts(InstrumentState *state);

#define INSTRUMENT_EDGE(state, cur_loc)                                        \
  do {                                                                         \
    uint32_t __idx = (state)->prev_loc ^ (cur_loc);                            \
    (state)->trace_bits[__idx % FUZZPRO_MAP_SIZE]++;                           \
    (state)->prev_loc = ((cur_loc) >> 1);                                      \
  } while (0)

#endif
