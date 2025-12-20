#ifndef FUZZPRO_REDQUEEN_H
#define FUZZPRO_REDQUEEN_H

#include <stddef.h>
#include <stdint.h>

#define RQ_MAX_ENTRIES 256
#define RQ_MAX_INPUT_SIZE 65536

typedef struct {
  uint64_t addr;
  uint64_t val1;
  uint64_t val2;
  uint8_t size;
  uint8_t found_in_input;
  int32_t input_offset;
} RQEntry;

typedef struct {
  RQEntry entries[RQ_MAX_ENTRIES];
  size_t count;
  uint8_t colorized[RQ_MAX_INPUT_SIZE];
  size_t input_len;
} RQState;

void rq_init(RQState *rq);
void rq_reset(RQState *rq);
void rq_add_cmp(RQState *rq, uint64_t addr, uint64_t v1, uint64_t v2, int size);
int rq_colorize(RQState *rq, const uint8_t *input, size_t len);
int rq_find_matches(RQState *rq, const uint8_t *input, size_t len);
int rq_apply_mutations(RQState *rq, uint8_t *input, size_t len);

#endif
