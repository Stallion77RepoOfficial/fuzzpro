#include "redqueen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rq_init(RQState *rq) {
  if (!rq)
    return;
  memset(rq, 0, sizeof(*rq));
}

void rq_reset(RQState *rq) {
  if (!rq)
    return;
  rq->count = 0;
  memset(rq->colorized, 0, sizeof(rq->colorized));
  rq->input_len = 0;
}

void rq_add_cmp(RQState *rq, uint64_t addr, uint64_t v1, uint64_t v2,
                int size) {
  if (!rq || rq->count >= RQ_MAX_ENTRIES)
    return;
  if (v1 == v2)
    return;

  for (size_t i = 0; i < rq->count; i++) {
    if (rq->entries[i].addr == addr && rq->entries[i].val1 == v1 &&
        rq->entries[i].val2 == v2) {
      return;
    }
  }

  RQEntry *e = &rq->entries[rq->count++];
  e->addr = addr;
  e->val1 = v1;
  e->val2 = v2;
  e->size = size;
  e->found_in_input = 0;
  e->input_offset = -1;
}

int rq_colorize(RQState *rq, const uint8_t *input, size_t len) {
  if (!rq || !input || len == 0)
    return -1;
  if (len > RQ_MAX_INPUT_SIZE)
    len = RQ_MAX_INPUT_SIZE;

  rq->input_len = len;
  memset(rq->colorized, 0, len);

  uint8_t *test = malloc(len);
  if (!test)
    return -1;
  memcpy(test, input, len);

  int colored = 0;
  for (size_t i = 0; i < len; i++) {
    uint8_t orig = test[i];
    test[i] = orig ^ 0xFF;
    rq->colorized[i] = 1;
    colored++;
    test[i] = orig;
  }

  free(test);
  return colored;
}

static int find_value_in_input(const uint8_t *input, size_t len, uint64_t val,
                               int size, int *offset) {
  if (size > (int)len)
    return 0;

  for (size_t i = 0; i <= len - size; i++) {
    uint64_t found = 0;
    memcpy(&found, input + i, size);
    if (found == val) {
      *offset = (int)i;
      return 1;
    }
  }

  if (size >= 2) {
    uint64_t swapped = 0;
    for (int b = 0; b < size; b++) {
      swapped |= ((val >> (b * 8)) & 0xFF) << ((size - 1 - b) * 8);
    }

    for (size_t i = 0; i <= len - size; i++) {
      uint64_t found = 0;
      memcpy(&found, input + i, size);
      if (found == swapped) {
        *offset = (int)i;
        return 2;
      }
    }
  }

  return 0;
}

int rq_find_matches(RQState *rq, const uint8_t *input, size_t len) {
  if (!rq || !input)
    return 0;

  int matches = 0;

  for (size_t i = 0; i < rq->count; i++) {
    RQEntry *e = &rq->entries[i];
    int offset = -1;

    if (find_value_in_input(input, len, e->val1, e->size, &offset)) {
      e->found_in_input = 1;
      e->input_offset = offset;
      matches++;
    }
  }

  return matches;
}

int rq_apply_mutations(RQState *rq, uint8_t *input, size_t len) {
  if (!rq || !input)
    return 0;

  int applied = 0;

  for (size_t i = 0; i < rq->count; i++) {
    RQEntry *e = &rq->entries[i];

    if (e->found_in_input && e->input_offset >= 0) {
      if (e->input_offset + e->size <= len) {
        memcpy(input + e->input_offset, &e->val2, e->size);
        applied++;
      }
    }
  }

  return applied;
}
