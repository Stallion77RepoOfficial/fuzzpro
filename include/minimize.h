#ifndef FUZZPRO_MINIMIZE_H
#define FUZZPRO_MINIMIZE_H

#include <stddef.h>
#include <stdint.h>

typedef int (*MinimizeTestFn)(const uint8_t *input, size_t size, void *ctx);

typedef struct {
  size_t min_size;
  size_t max_iterations;
  int keep_behavior;
} MinimizeConfig;

int minimize_input(uint8_t *input, size_t *size, MinimizeTestFn test_fn,
                   void *ctx, MinimizeConfig *config);

int minimize_crash(uint8_t *input, size_t *size, MinimizeTestFn test_fn,
                   void *ctx);

int trim_input(uint8_t *input, size_t *size, MinimizeTestFn test_fn, void *ctx);

#endif
