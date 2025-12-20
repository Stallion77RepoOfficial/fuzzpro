#include "calibrate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static uint64_t get_time_us(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

static uint32_t hash_bitmap(const uint8_t *bits, size_t size) {
  uint32_t hash = 0x811c9dc5;
  for (size_t i = 0; i < size; i++) {
    if (bits[i]) {
      hash ^= bits[i];
      hash *= 0x01000193;
    }
  }
  return hash;
}

static uint64_t count_bitmap(const uint8_t *bits, size_t size) {
  uint64_t count = 0;
  for (size_t i = 0; i < size; i++) {
    if (bits[i])
      count++;
  }
  return count;
}

int calibrate_input(const uint8_t *input, size_t input_len,
                    int (*run_fn)(const uint8_t *, size_t, uint8_t *, size_t),
                    uint8_t *trace_bits, size_t map_size,
                    CalibrationResult *result) {

  if (!input || !run_fn || !trace_bits || !result)
    return -1;

  memset(result, 0, sizeof(*result));

  uint32_t first_hash = 0;
  uint64_t total_exec_us = 0;
  uint64_t total_bitmap = 0;
  int variable = 0;

  for (int i = 0; i < CALIBRATE_CYCLES; i++) {
    memset(trace_bits, 0, map_size);

    uint64_t start = get_time_us();
    int ret = run_fn(input, input_len, trace_bits, map_size);
    uint64_t elapsed = get_time_us() - start;

    if (ret < 0) {
      result->handicap++;
      continue;
    }

    uint32_t hash = hash_bitmap(trace_bits, map_size);
    uint64_t bits = count_bitmap(trace_bits, map_size);

    if (i == 0) {
      first_hash = hash;
    } else if (hash != first_hash) {
      variable = 1;
    }

    total_exec_us += elapsed;
    total_bitmap += bits;
  }

  result->exec_us = total_exec_us / CALIBRATE_CYCLES;
  result->bitmap_size = total_bitmap / CALIBRATE_CYCLES;
  result->bitmap_hash = first_hash;
  result->variable = variable;

  return 0;
}

double calculate_perf_score(CalibrationResult *cal, QueueStats *stats) {
  if (!cal)
    return 100.0;

  double perf = 100.0;

  if (stats && stats->avg_exec_us > 0) {
    double speed_factor = stats->avg_exec_us / (double)cal->exec_us;
    if (speed_factor > 2.0)
      speed_factor = 2.0;
    if (speed_factor < 0.5)
      speed_factor = 0.5;
    perf *= speed_factor;
  }

  if (stats && stats->avg_bitmap_size > 0) {
    double cov_factor = (double)cal->bitmap_size / stats->avg_bitmap_size;
    if (cov_factor > 2.0)
      cov_factor = 2.0;
    if (cov_factor < 0.5)
      cov_factor = 0.5;
    perf *= cov_factor;
  }

  if (cal->variable)
    perf *= 0.5;
  if (cal->has_new_bits)
    perf *= 2.0;

  if (perf < 10.0)
    perf = 10.0;
  if (perf > 400.0)
    perf = 400.0;

  cal->perf_score = perf;
  return perf;
}

double power_schedule_factor(PowerSchedule schedule, uint64_t fuzz_level,
                             uint64_t exec_count, QueueStats *stats) {

  double factor = 1.0;

  switch (schedule) {
  case POWER_EXPLORE:
    factor = 1.0;
    break;

  case POWER_EXPLOIT:
    if (fuzz_level > 16)
      factor = 0.25;
    else
      factor = 1.0 / (1.0 + fuzz_level * 0.05);
    break;

  case POWER_COE:
    if (stats && stats->pending_favored > 0) {
      factor = 0.1;
    } else {
      factor = 1.0;
    }
    break;

  case POWER_FAST:
    if (fuzz_level < 16) {
      factor = (double)(1ULL << fuzz_level);
    } else {
      factor = (double)(1ULL << 15);
    }
    factor = factor / (1.0 + exec_count);
    break;

  case POWER_LIN:
    factor = 1.0 + fuzz_level * 0.1;
    break;

  case POWER_QUAD:
    factor = 1.0 + fuzz_level * fuzz_level * 0.01;
    break;
  }

  if (factor < 0.01)
    factor = 0.01;
  if (factor > 100.0)
    factor = 100.0;

  return factor;
}
