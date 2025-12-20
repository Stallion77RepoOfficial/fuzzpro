
#ifndef FUZZPRO_COVERAGE_ENGINE_H
#define FUZZPRO_COVERAGE_ENGINE_H
#include "executor.h"
#include "macho.h"
#include <stddef.h>
#include <stdint.h>

#define COVERAGE_MAP_SIZE 65536
#define COVERAGE_MAP_MASK (COVERAGE_MAP_SIZE - 1)

#define MAX_BREAKPOINTS 50000

typedef struct {
  uint64_t addr;      
  uint32_t original;  
  uint16_t id;        
  int active;         
  uint32_t hit_count; 
} Breakpoint;

typedef struct {
  
  uint8_t *bitmap;
  uint8_t *virgin_bits; 
  
  Breakpoint *breakpoints;
  size_t bp_count;
  size_t bp_capacity;
  
  uint64_t total_edges;  
  uint64_t total_hits;   
  uint64_t new_edges;    
  uint64_t total_blocks; 
  
  uint16_t prev_loc; 
  
  int last_was_interesting;
} CoverageEngine;


CoverageEngine *coverage_engine_create(void);

void coverage_engine_free(CoverageEngine *cov);

void coverage_engine_reset_run(CoverageEngine *cov);

void coverage_engine_reset_all(CoverageEngine *cov);


int coverage_instrument_binary(CoverageEngine *cov, TargetProcess *proc,
                               MachOInfo *info);

int coverage_add_breakpoint(CoverageEngine *cov, TargetProcess *proc,
                            uint64_t addr);

int coverage_remove_all(CoverageEngine *cov, TargetProcess *proc);


int coverage_process_hit(CoverageEngine *cov, uint64_t addr);

int coverage_process_edge(CoverageEngine *cov, uint64_t addr_from,
                          uint64_t addr_to);

int coverage_was_interesting(CoverageEngine *cov);

double coverage_get_percentage(CoverageEngine *cov);

uint64_t coverage_get_edge_count(CoverageEngine *cov);


int coverage_has_new_bits(CoverageEngine *cov);

uint64_t coverage_classify_bitmap(CoverageEngine *cov);

int coverage_compare_bitmaps(const uint8_t *base, const uint8_t *test,
                             size_t size);


void coverage_print_stats(CoverageEngine *cov);

typedef struct {
  uint64_t total_blocks;
  uint64_t covered_blocks;
  uint64_t total_edges;
  uint64_t total_hits;
  double coverage_pct;
} CoverageStats;
void coverage_get_stats(CoverageEngine *cov, CoverageStats *stats);
#endif 
