#ifndef FUZZPRO_CALIBRATE_H
#define FUZZPRO_CALIBRATE_H

#include <stddef.h>
#include <stdint.h>

#define CALIBRATE_CYCLES 8
#define CALIBRATE_MAX_MULT 4

typedef struct {
  uint64_t exec_us;
  uint64_t bitmap_size;
  uint64_t bitmap_hash;
  int has_new_bits;
  int variable;
  int handicap;
  double perf_score;
} CalibrationResult;

typedef struct {
  uint64_t total_bitmap_size;
  uint64_t total_bitmap_entries;
  double avg_exec_us;
  double avg_bitmap_size;
  uint32_t queue_cycle;
  uint32_t cycles_wo_finds;
  int pending_favored;
  int pending_not_fuzzed;
} QueueStats;

int calibrate_input(const uint8_t *input, size_t input_len,
                    int (*run_fn)(const uint8_t *, size_t, uint8_t *, size_t),
                    uint8_t *trace_bits, size_t map_size,
                    CalibrationResult *result);

double calculate_perf_score(CalibrationResult *cal, QueueStats *stats);

typedef enum {
  POWER_EXPLORE = 0,
  POWER_EXPLOIT,
  POWER_COE,
  POWER_FAST,
  POWER_LIN,
  POWER_QUAD
} PowerSchedule;

double power_schedule_factor(PowerSchedule schedule, uint64_t fuzz_level,
                             uint64_t exec_count, QueueStats *stats);

#endif
