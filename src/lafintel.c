#include "lafintel.h"
#include <stdlib.h>
#include <string.h>

LafState *laf_create(void) {
  LafState *laf = calloc(1, sizeof(LafState));
  return laf;
}

void laf_destroy(LafState *laf) { free(laf); }

void laf_reset(LafState *laf) {
  if (laf) {
    laf->count = 0;
  }
}

int laf_analyze_compare(LafState *laf, uint64_t val1, uint64_t val2, int size) {
  if (!laf || laf->count >= LAF_MAX_SPLITS)
    return 0;

  int added = 0;

  for (int i = 0; i < size; i++) {
    uint8_t b1 = (val1 >> (i * 8)) & 0xFF;
    uint8_t b2 = (val2 >> (i * 8)) & 0xFF;

    if (b1 != b2) {
      LafSplit *split = &laf->splits[laf->count++];
      split->target_val = val2;
      split->size = size;
      split->byte_idx = i;
      split->matched = 0;
      added++;

      if (laf->count >= LAF_MAX_SPLITS)
        break;
    }
  }

  return added;
}

int laf_get_next_byte_to_fix(LafState *laf, int *byte_pos,
                             uint8_t *target_byte) {
  if (!laf)
    return 0;

  for (size_t i = 0; i < laf->count; i++) {
    if (!laf->splits[i].matched) {
      *byte_pos = laf->splits[i].byte_idx;
      *target_byte =
          (laf->splits[i].target_val >> (laf->splits[i].byte_idx * 8)) & 0xFF;
      return 1;
    }
  }

  return 0;
}

int laf_split_cmp32(uint32_t input_val, uint32_t target_val, uint8_t *mutations,
                    int *count) {
  *count = 0;

  for (int i = 0; i < 4; i++) {
    uint8_t ib = (input_val >> (i * 8)) & 0xFF;
    uint8_t tb = (target_val >> (i * 8)) & 0xFF;

    if (ib != tb) {
      mutations[(*count)++] = tb;
    } else {
      break;
    }
  }

  return *count;
}

int laf_split_cmp64(uint64_t input_val, uint64_t target_val, uint8_t *mutations,
                    int *count) {
  *count = 0;

  for (int i = 0; i < 8; i++) {
    uint8_t ib = (input_val >> (i * 8)) & 0xFF;
    uint8_t tb = (target_val >> (i * 8)) & 0xFF;

    if (ib != tb) {
      mutations[(*count)++] = tb;
    } else {
      break;
    }
  }

  return *count;
}

int laf_apply_split_mutation(LafState *laf, uint8_t *input, size_t *len,
                             size_t max_len) {
  if (!laf || !input || !len || laf->count == 0)
    return 0;

  int mutations_applied = 0;

  for (size_t i = 0; i < laf->count && i < 8; i++) {
    LafSplit *split = &laf->splits[i];
    if (split->matched)
      continue;

    for (size_t pos = 0; pos + split->size <= *len; pos++) {
      uint64_t val = 0;
      for (int b = 0; b < split->size; b++) {
        val |= (uint64_t)input[pos + b] << (b * 8);
      }

      uint8_t target_byte = (split->target_val >> (split->byte_idx * 8)) & 0xFF;
      input[pos + split->byte_idx] = target_byte;
      mutations_applied++;
      break;
    }
  }

  return mutations_applied;
}
