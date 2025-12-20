#ifndef FUZZPRO_LAFINTEL_H
#define FUZZPRO_LAFINTEL_H

#include <stddef.h>
#include <stdint.h>

#define LAF_MAX_SPLITS 256
#define LAF_SPLIT_SIZE 1

typedef struct {
  uint64_t addr;
  uint64_t target_val;
  int size;
  int byte_idx;
  int matched;
} LafSplit;

typedef struct {
  LafSplit splits[LAF_MAX_SPLITS];
  size_t count;
  uint8_t *current_input;
  size_t input_len;
} LafState;

LafState *laf_create(void);
void laf_destroy(LafState *laf);
void laf_reset(LafState *laf);

int laf_analyze_compare(LafState *laf, uint64_t val1, uint64_t val2, int size);
int laf_get_next_byte_to_fix(LafState *laf, int *byte_pos,
                             uint8_t *target_byte);
int laf_apply_split_mutation(LafState *laf, uint8_t *input, size_t *len,
                             size_t max_len);

int laf_split_cmp32(uint32_t input_val, uint32_t target_val, uint8_t *mutations,
                    int *count);
int laf_split_cmp64(uint64_t input_val, uint64_t target_val, uint8_t *mutations,
                    int *count);

#endif
