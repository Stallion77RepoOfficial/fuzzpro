#include "minimize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int minimize_input(uint8_t *input, size_t *size, MinimizeTestFn test_fn,
                   void *ctx, MinimizeConfig *config) {
  if (!input || !size || !test_fn || *size == 0)
    return -1;

  size_t min_size = config ? config->min_size : 1;
  size_t max_iter = config ? config->max_iterations : 1000;
  int keep_behavior = config ? config->keep_behavior : 1;

  int baseline = test_fn(input, *size, ctx);

  uint8_t *buf = malloc(*size);
  if (!buf)
    return -1;
  memcpy(buf, input, *size);

  size_t cur_size = *size;
  size_t iter = 0;
  int changed = 1;

  while (changed && cur_size > min_size && iter < max_iter) {
    changed = 0;
    iter++;

    size_t chunk = cur_size / 2;
    if (chunk < 1)
      chunk = 1;

    while (chunk >= 1 && cur_size > min_size) {
      for (size_t pos = 0; pos + chunk <= cur_size;) {
        size_t new_size = cur_size - chunk;
        if (new_size < min_size)
          break;

        uint8_t *tmp = malloc(new_size);
        if (!tmp)
          break;

        memcpy(tmp, buf, pos);
        memcpy(tmp + pos, buf + pos + chunk, cur_size - pos - chunk);

        int result = test_fn(tmp, new_size, ctx);

        if ((keep_behavior && result == baseline) ||
            (!keep_behavior && result != 0)) {
          free(buf);
          buf = tmp;
          cur_size = new_size;
          changed = 1;
        } else {
          free(tmp);
          pos += chunk;
        }
      }
      chunk /= 2;
    }
  }

  memcpy(input, buf, cur_size);
  *size = cur_size;
  free(buf);

  return 0;
}

int minimize_crash(uint8_t *input, size_t *size, MinimizeTestFn test_fn,
                   void *ctx) {
  MinimizeConfig config = {
      .min_size = 1, .max_iterations = 500, .keep_behavior = 0};
  return minimize_input(input, size, test_fn, ctx, &config);
}

int trim_input(uint8_t *input, size_t *size, MinimizeTestFn test_fn,
               void *ctx) {
  if (!input || !size || !test_fn || *size < 4)
    return -1;

  size_t original_size = *size;
  uint8_t *buf = malloc(*size);
  if (!buf)
    return -1;
  memcpy(buf, input, *size);

  size_t cur_size = *size;

  size_t steps[] = {16, 8, 4, 2, 1};
  int num_steps = sizeof(steps) / sizeof(steps[0]);

  for (int s = 0; s < num_steps; s++) {
    size_t step = steps[s];
    if (step > cur_size / 4)
      continue;

    for (size_t pos = 0; pos + step <= cur_size;) {
      size_t new_size = cur_size - step;
      if (new_size < 1)
        break;

      uint8_t *tmp = malloc(new_size);
      if (!tmp)
        break;

      memcpy(tmp, buf, pos);
      memcpy(tmp + pos, buf + pos + step, cur_size - pos - step);

      if (test_fn(tmp, new_size, ctx) != 0) {
        free(buf);
        buf = tmp;
        cur_size = new_size;
      } else {
        free(tmp);
        pos += step;
      }
    }
  }

  if (cur_size < original_size) {
    memcpy(input, buf, cur_size);
    *size = cur_size;
  }

  free(buf);
  return 0;
}
