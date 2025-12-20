#include "trace.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#define BRK_INSN 0xD4200000
#define ARM64_INSN_SIZE 4

static const uint8_t count_class[256] = {
    0,   1,   2,   4,   8,   8,   8,   8,   16,  16,  16,  16,  16,  16,  16,
    16,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128};

Tracer *tracer_create(void) {
  Tracer *t = calloc(1, sizeof(Tracer));
  if (!t)
    return NULL;

  t->capacity = TRACE_MAX_BREAKPOINTS;
  t->bps = calloc(t->capacity, sizeof(Breakpoint));
  t->trace_bits = calloc(1, TRACE_MAP_SIZE);
  t->virgin_bits = malloc(TRACE_MAP_SIZE);

  if (!t->bps || !t->trace_bits || !t->virgin_bits) {
    tracer_destroy(t);
    return NULL;
  }

  memset(t->virgin_bits, 0xFF, TRACE_MAP_SIZE);
  return t;
}

void tracer_destroy(Tracer *t) {
  if (!t)
    return;
  if (t->attached)
    tracer_detach(t);
  free(t->bps);
  free(t->trace_bits);
  free(t->virgin_bits);
  free(t);
}

int tracer_attach(Tracer *t, pid_t pid) {
  if (!t)
    return -1;

  kern_return_t kr = task_for_pid(mach_task_self(), pid, &t->task);
  if (kr != KERN_SUCCESS) {
    return -1;
  }

  t->attached = 1;
  return 0;
}

void tracer_detach(Tracer *t) {
  if (!t || !t->attached)
    return;

  for (size_t i = 0; i < t->count; i++) {
    if (t->bps[i].active) {
      tracer_remove_breakpoint(t, t->bps[i].addr);
    }
  }

  t->attached = 0;
  t->task = MACH_PORT_NULL;
}

static int read_memory(task_t task, uint64_t addr, void *buf, size_t size) {
  mach_vm_size_t out_size;
  kern_return_t kr = mach_vm_read_overwrite(task, addr, size,
                                            (mach_vm_address_t)buf, &out_size);
  return (kr == KERN_SUCCESS && out_size == size) ? 0 : -1;
}

static int write_memory(task_t task, uint64_t addr, const void *buf,
                        size_t size) {
  kern_return_t kr;

  mach_vm_address_t region_addr = addr & ~0xFFFULL;
  mach_vm_size_t region_size = 0x1000;

  kr = mach_vm_protect(task, region_addr, region_size, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS)
    return -1;

  kr =
      mach_vm_write(task, addr, (vm_offset_t)buf, (mach_msg_type_number_t)size);

  mach_vm_protect(task, region_addr, region_size, FALSE,
                  VM_PROT_READ | VM_PROT_EXECUTE);

  return (kr == KERN_SUCCESS) ? 0 : -1;
}

int tracer_set_breakpoint(Tracer *t, uint64_t addr) {
  if (!t || !t->attached || t->count >= t->capacity)
    return -1;

  for (size_t i = 0; i < t->count; i++) {
    if (t->bps[i].addr == addr)
      return 0;
  }

  uint32_t original;
  if (read_memory(t->task, addr, &original, 4) < 0)
    return -1;

  uint32_t brk = BRK_INSN;
  if (write_memory(t->task, addr, &brk, 4) < 0)
    return -1;

  Breakpoint *bp = &t->bps[t->count++];
  bp->addr = addr;
  bp->original = original;
  bp->loc_id = (uint32_t)(addr ^ (addr >> 16));
  bp->active = 1;

  return 0;
}

int tracer_remove_breakpoint(Tracer *t, uint64_t addr) {
  if (!t || !t->attached)
    return -1;

  for (size_t i = 0; i < t->count; i++) {
    if (t->bps[i].addr == addr && t->bps[i].active) {
      write_memory(t->task, addr, &t->bps[i].original, 4);
      t->bps[i].active = 0;
      return 0;
    }
  }
  return -1;
}

int tracer_handle_trap(Tracer *t, uint64_t addr) {
  if (!t)
    return -1;

  for (size_t i = 0; i < t->count; i++) {
    if (t->bps[i].addr == addr && t->bps[i].active) {
      uint32_t idx = t->prev_loc ^ t->bps[i].loc_id;
      t->trace_bits[idx % TRACE_MAP_SIZE]++;
      t->prev_loc = t->bps[i].loc_id >> 1;
      return 0;
    }
  }
  return -1;
}

void tracer_reset(Tracer *t) {
  if (!t)
    return;
  memset(t->trace_bits, 0, TRACE_MAP_SIZE);
  t->prev_loc = 0;
}

int tracer_has_new_bits(Tracer *t) {
  if (!t)
    return 0;

  int ret = 0;
  for (size_t i = 0; i < TRACE_MAP_SIZE; i++) {
    if (t->trace_bits[i]) {
      t->trace_bits[i] = count_class[t->trace_bits[i]];
      if (t->trace_bits[i] & t->virgin_bits[i]) {
        ret = (t->virgin_bits[i] == 0xFF) ? 2 : 1;
      }
    }
  }
  return ret;
}

void tracer_update_virgin(Tracer *t) {
  if (!t)
    return;
  for (size_t i = 0; i < TRACE_MAP_SIZE; i++) {
    t->virgin_bits[i] &= ~t->trace_bits[i];
  }
}

uint64_t tracer_count_edges(Tracer *t) {
  if (!t)
    return 0;
  uint64_t count = 0;
  for (size_t i = 0; i < TRACE_MAP_SIZE; i++) {
    if (t->trace_bits[i])
      count++;
  }
  return count;
}

static int is_branch_insn(uint32_t insn) {
  if ((insn & 0x7C000000) == 0x14000000)
    return 1;
  if ((insn & 0xFE000000) == 0x54000000)
    return 1;
  if ((insn & 0x7E000000) == 0x34000000)
    return 1;
  if ((insn & 0x7E000000) == 0x36000000)
    return 1;
  if ((insn & 0xFE000000) == 0xD6000000)
    return 1;
  return 0;
}

int tracer_instrument_text(Tracer *t, uint64_t text_start, uint64_t text_end,
                           const uint8_t *code, size_t code_len) {
  if (!t || !code)
    return -1;

  int bp_count = 0;
  uint64_t prev_branch = 0;

  tracer_set_breakpoint(t, text_start);
  bp_count++;

  for (size_t off = 0; off + 4 <= code_len; off += 4) {
    uint32_t insn = *(uint32_t *)(code + off);
    uint64_t addr = text_start + off;

    if (is_branch_insn(insn)) {
      if ((insn & 0x7C000000) == 0x14000000) {
        int32_t imm26 = insn & 0x03FFFFFF;
        if (imm26 & 0x02000000)
          imm26 |= 0xFC000000;
        uint64_t target = addr + (imm26 << 2);

        if (target >= text_start && target < text_end) {
          tracer_set_breakpoint(t, target);
          bp_count++;
        }
      }

      if ((insn & 0xFE000000) == 0x54000000 ||
          (insn & 0x7E000000) == 0x34000000 ||
          (insn & 0x7E000000) == 0x36000000) {

        int32_t imm19 = (insn >> 5) & 0x7FFFF;
        if (imm19 & 0x40000)
          imm19 |= 0xFFF80000;
        uint64_t target = addr + (imm19 << 2);

        if (target >= text_start && target < text_end) {
          tracer_set_breakpoint(t, target);
          bp_count++;
        }

        tracer_set_breakpoint(t, addr + 4);
        bp_count++;
      }

      prev_branch = addr;
    }
  }

  return bp_count;
}
