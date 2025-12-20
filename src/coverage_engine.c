
#include "coverage_engine.h"
#include "arm64dis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t hash_location(uint64_t addr) {
  
  uint64_t h = addr;
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53ULL;
  h ^= h >> 33;
  return (uint16_t)(h & 0xFFFF);
}
CoverageEngine *coverage_engine_create(void) {
  CoverageEngine *cov = calloc(1, sizeof(CoverageEngine));
  if (!cov)
    return NULL;
  
  cov->bitmap = calloc(COVERAGE_MAP_SIZE, 1);
  cov->virgin_bits = malloc(COVERAGE_MAP_SIZE);
  if (!cov->bitmap || !cov->virgin_bits) {
    free(cov->bitmap);
    free(cov->virgin_bits);
    free(cov);
    return NULL;
  }
  
  memset(cov->virgin_bits, 0xFF, COVERAGE_MAP_SIZE);
  
  cov->bp_capacity = MAX_BREAKPOINTS;
  cov->breakpoints = calloc(cov->bp_capacity, sizeof(Breakpoint));
  if (!cov->breakpoints) {
    free(cov->bitmap);
    free(cov->virgin_bits);
    free(cov);
    return NULL;
  }
  return cov;
}
void coverage_engine_free(CoverageEngine *cov) {
  if (!cov)
    return;
  free(cov->bitmap);
  free(cov->virgin_bits);
  free(cov->breakpoints);
  free(cov);
}
void coverage_engine_reset_run(CoverageEngine *cov) {
  if (!cov)
    return;
  
  cov->new_edges = 0;
  cov->prev_loc = 0;
  cov->last_was_interesting = 0;
  
  memset(cov->bitmap, 0, COVERAGE_MAP_SIZE);
}
void coverage_engine_reset_all(CoverageEngine *cov) {
  if (!cov)
    return;
  
  memset(cov->bitmap, 0, COVERAGE_MAP_SIZE);
  memset(cov->virgin_bits, 0xFF, COVERAGE_MAP_SIZE);
  cov->total_edges = 0;
  cov->total_hits = 0;
  cov->new_edges = 0;
  cov->prev_loc = 0;
  cov->last_was_interesting = 0;
  
  for (size_t i = 0; i < cov->bp_count; i++) {
    cov->breakpoints[i].hit_count = 0;
  }
}
int coverage_instrument_binary(CoverageEngine *cov, TargetProcess *proc,
                               MachOInfo *info) {
  if (!cov || !info)
    return -1;
  
  printf("[*] Instrumenting %zu functions...\n", info->function_count);
  size_t instrumented = 0;
  for (size_t i = 0;
       i < info->function_count && cov->bp_count < cov->bp_capacity; i++) {
    uint64_t func_addr = info->functions[i];
    
    if (func_addr < info->text_vmaddr ||
        func_addr >= info->text_vmaddr + info->text_vmsize) {
      continue;
    }
    
    if (proc && coverage_add_breakpoint(cov, proc, func_addr) == 0) {
      instrumented++;
    } else {
      
      Breakpoint *bp = &cov->breakpoints[cov->bp_count];
      bp->addr = func_addr;
      bp->original = 0;
      bp->id = hash_location(func_addr);
      bp->active = 0;
      bp->hit_count = 0;
      cov->bp_count++;
    }
  }
  cov->total_blocks = cov->bp_count;
  printf("[*] Instrumented %zu of %zu function entries\n", instrumented,
         info->function_count);
  return 0;
}
int coverage_add_breakpoint(CoverageEngine *cov, TargetProcess *proc,
                            uint64_t addr) {
  if (!cov || !proc || cov->bp_count >= cov->bp_capacity) {
    return -1;
  }
  
  for (size_t i = 0; i < cov->bp_count; i++) {
    if (cov->breakpoints[i].addr == addr) {
      return 0; 
    }
  }
  
  uint32_t original = executor_set_breakpoint(proc, addr);
  if (original == 0) {
    return -1;
  }
  
  Breakpoint *bp = &cov->breakpoints[cov->bp_count];
  bp->addr = addr;
  bp->original = original;
  bp->id = hash_location(addr);
  bp->active = 1;
  bp->hit_count = 0;
  cov->bp_count++;
  return 0;
}
int coverage_remove_all(CoverageEngine *cov, TargetProcess *proc) {
  if (!cov || !proc)
    return -1;
  for (size_t i = 0; i < cov->bp_count; i++) {
    if (cov->breakpoints[i].active && cov->breakpoints[i].original != 0) {
      executor_remove_breakpoint(proc, cov->breakpoints[i].addr,
                                 cov->breakpoints[i].original);
      cov->breakpoints[i].active = 0;
    }
  }
  return 0;
}
int coverage_process_hit(CoverageEngine *cov, uint64_t addr) {
  if (!cov)
    return 0;
  
  Breakpoint *bp = NULL;
  for (size_t i = 0; i < cov->bp_count; i++) {
    if (cov->breakpoints[i].addr == addr) {
      bp = &cov->breakpoints[i];
      break;
    }
  }
  uint16_t cur_loc;
  if (bp) {
    cur_loc = bp->id;
    bp->hit_count++;
  } else {
    cur_loc = hash_location(addr);
  }
  
  uint16_t edge_idx = (cov->prev_loc ^ cur_loc) & COVERAGE_MAP_MASK;
  
  int is_new = 0;
  uint8_t old_val = cov->bitmap[edge_idx];
  
  if (old_val < 255) {
    cov->bitmap[edge_idx]++;
  }
  
  if (cov->virgin_bits[edge_idx] != 0) {
    
    uint8_t new_val = cov->bitmap[edge_idx];
    
    static const uint8_t count_class_lookup[256] = {
        0,  1,  2,  4,  8,  8,  8,  8,  16, 16, 16, 16, 16, 16, 16, 16,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        
    };
    uint8_t old_bucket = (old_val < 128) ? count_class_lookup[old_val] : 128;
    uint8_t new_bucket = (new_val < 128) ? count_class_lookup[new_val] : 128;
    if (old_val == 0 || new_bucket > old_bucket) {
      is_new = 1;
      cov->new_edges++;
      cov->total_edges++;
      
      cov->virgin_bits[edge_idx] = 0;
    }
  }
  cov->total_hits++;
  
  cov->prev_loc = cur_loc >> 1;
  if (is_new) {
    cov->last_was_interesting = 1;
  }
  return is_new;
}
int coverage_process_edge(CoverageEngine *cov, uint64_t addr_from,
                          uint64_t addr_to) {
  if (!cov)
    return 0;
  uint16_t from_id = hash_location(addr_from);
  uint16_t to_id = hash_location(addr_to);
  uint16_t edge_idx = (from_id ^ to_id) & COVERAGE_MAP_MASK;
  int is_new = (cov->bitmap[edge_idx] == 0);
  if (cov->bitmap[edge_idx] < 255) {
    cov->bitmap[edge_idx]++;
  }
  if (is_new) {
    cov->new_edges++;
    cov->total_edges++;
    cov->virgin_bits[edge_idx] = 0;
    cov->last_was_interesting = 1;
  }
  cov->total_hits++;
  return is_new;
}
int coverage_was_interesting(CoverageEngine *cov) {
  if (!cov)
    return 0;
  return cov->last_was_interesting;
}
double coverage_get_percentage(CoverageEngine *cov) {
  if (!cov || cov->total_blocks == 0)
    return 0.0;
  
  size_t covered = 0;
  for (size_t i = 0; i < cov->bp_count; i++) {
    if (cov->breakpoints[i].hit_count > 0) {
      covered++;
    }
  }
  return (double)covered * 100.0 / (double)cov->total_blocks;
}
uint64_t coverage_get_edge_count(CoverageEngine *cov) {
  if (!cov)
    return 0;
  return cov->total_edges;
}
int coverage_has_new_bits(CoverageEngine *cov) {
  if (!cov)
    return 0;
  return cov->new_edges > 0;
}
uint64_t coverage_classify_bitmap(CoverageEngine *cov) {
  if (!cov || !cov->bitmap)
    return 0;
  uint64_t score = 0;
  
  for (size_t i = 0; i < COVERAGE_MAP_SIZE; i++) {
    if (cov->bitmap[i]) {
      
      if (cov->virgin_bits[i] == 0) {
        score += cov->bitmap[i];
      } else {
        score += cov->bitmap[i] * 2; 
      }
    }
  }
  return score;
}
int coverage_compare_bitmaps(const uint8_t *base, const uint8_t *test,
                             size_t size) {
  if (!base || !test)
    return 0;
  int count = 0;
  for (size_t i = 0; i < size; i++) {
    if (test[i] && !base[i]) {
      count++;
    }
  }
  return count;
}
void coverage_print_stats(CoverageEngine *cov) {
  if (!cov)
    return;
  
  size_t covered = 0;
  for (size_t i = 0; i < cov->bp_count; i++) {
    if (cov->breakpoints[i].hit_count > 0) {
      covered++;
    }
  }
  printf("\n[*] Coverage Statistics:\n");
  printf("    Basic blocks instrumented: %zu\n", cov->total_blocks);
  printf("    Basic blocks covered: %zu (%.2f%%)\n", covered,
         cov->total_blocks > 0 ? (double)covered * 100.0 / cov->total_blocks
                               : 0.0);
  printf("    Total edges discovered: %llu\n",
         (unsigned long long)cov->total_edges);
  printf("    Total hits: %llu\n", (unsigned long long)cov->total_hits);
  printf("    New edges in last run: %llu\n",
         (unsigned long long)cov->new_edges);
}
void coverage_get_stats(CoverageEngine *cov, CoverageStats *stats) {
  if (!cov || !stats)
    return;
  memset(stats, 0, sizeof(CoverageStats));
  
  size_t covered = 0;
  for (size_t i = 0; i < cov->bp_count; i++) {
    if (cov->breakpoints[i].hit_count > 0) {
      covered++;
    }
  }
  stats->total_blocks = cov->total_blocks;
  stats->covered_blocks = covered;
  stats->total_edges = cov->total_edges;
  stats->total_hits = cov->total_hits;
  stats->coverage_pct =
      cov->total_blocks > 0 ? (double)covered * 100.0 / cov->total_blocks : 0.0;
}
