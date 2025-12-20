#ifndef FUZZPRO_AUTODICT_H
#define FUZZPRO_AUTODICT_H

#include <stddef.h>
#include <stdint.h>

#define AUTODICT_MAX_TOKENS 1024
#define AUTODICT_MAX_TOKEN_LEN 64

typedef struct {
  uint8_t data[AUTODICT_MAX_TOKEN_LEN];
  size_t len;
  uint32_t score;
} DictToken;

typedef struct {
  DictToken tokens[AUTODICT_MAX_TOKENS];
  size_t count;
  uint64_t text_base;
  size_t text_size;
} AutoDict;

AutoDict *autodict_create(void);
void autodict_destroy(AutoDict *ad);
int autodict_extract_from_binary(AutoDict *ad, const char *binary_path);
int autodict_extract_cmp_operands(AutoDict *ad, const uint8_t *code, size_t len,
                                  uint64_t base);
int autodict_extract_strings(AutoDict *ad, const uint8_t *data, size_t len);
int autodict_add_token(AutoDict *ad, const uint8_t *data, size_t len);
const DictToken *autodict_get_token(AutoDict *ad, size_t index);
int autodict_apply_to_input(AutoDict *ad, uint8_t *input, size_t *len,
                            size_t max_len);

#endif
