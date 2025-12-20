#ifndef FUZZPRO_TRACE_H
#define FUZZPRO_TRACE_H

#include <mach/mach.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TRACE_MAP_SIZE (1 << 16)
#define TRACE_MAX_BREAKPOINTS 4096

typedef struct {
  uint64_t addr;
  uint32_t original;
  uint32_t loc_id;
  int active;
} Breakpoint;

typedef struct {
  Breakpoint *bps;
  size_t count;
  size_t capacity;
  uint8_t *trace_bits;
  uint8_t *virgin_bits;
  uint32_t prev_loc;
  task_t task;
  int attached;
} Tracer;

Tracer *tracer_create(void);
void tracer_destroy(Tracer *t);
int tracer_attach(Tracer *t, pid_t pid);
void tracer_detach(Tracer *t);
int tracer_set_breakpoint(Tracer *t, uint64_t addr);
int tracer_remove_breakpoint(Tracer *t, uint64_t addr);
int tracer_handle_trap(Tracer *t, uint64_t addr);
void tracer_reset(Tracer *t);
int tracer_has_new_bits(Tracer *t);
void tracer_update_virgin(Tracer *t);
uint64_t tracer_count_edges(Tracer *t);

int tracer_instrument_text(Tracer *t, uint64_t text_start, uint64_t text_end,
                           const uint8_t *code, size_t code_len);

#endif
