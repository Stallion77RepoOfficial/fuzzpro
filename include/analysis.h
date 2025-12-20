#ifndef FUZZPRO_ANALYSIS_H
#define FUZZPRO_ANALYSIS_H

#include <stddef.h>
#include <stdint.h>

#define MAX_FUNCTIONS 4096
#define MAX_BASIC_BLOCKS 16384
#define MAX_XREFS 65536
#define MAX_STRINGS 4096

typedef struct {
  uint64_t start;
  uint64_t end;
  uint64_t *successors;
  size_t succ_count;
  uint64_t *predecessors;
  size_t pred_count;
  int is_entry;
  int is_exit;
  int visited;
} BasicBlock;

typedef struct {
  uint64_t start;
  uint64_t end;
  char name[64];
  BasicBlock *blocks;
  size_t block_count;
  int is_leaf;
  int has_prologue;
  int stack_size;
  uint64_t *callers;
  size_t caller_count;
  uint64_t *callees;
  size_t callee_count;
} Function;

typedef enum {
  XREF_CODE_CALL = 0,
  XREF_CODE_JUMP,
  XREF_CODE_COND,
  XREF_DATA_READ,
  XREF_DATA_WRITE,
  XREF_DATA_OFFSET
} XRefType;

typedef struct {
  uint64_t from;
  uint64_t to;
  XRefType type;
} XRef;

typedef struct {
  uint64_t addr;
  char *data;
  size_t length;
} StringRef;

typedef struct {
  Function functions[MAX_FUNCTIONS];
  size_t func_count;

  BasicBlock blocks[MAX_BASIC_BLOCKS];
  size_t block_count;

  XRef xrefs[MAX_XREFS];
  size_t xref_count;

  StringRef strings[MAX_STRINGS];
  size_t string_count;

  uint64_t text_start;
  uint64_t text_end;
  uint64_t data_start;
  uint64_t data_end;

  const uint8_t *code;
  size_t code_len;
} AnalysisContext;

AnalysisContext *analysis_create(void);
void analysis_destroy(AnalysisContext *ctx);
int analysis_set_code(AnalysisContext *ctx, const uint8_t *code, size_t len,
                      uint64_t base);
int analysis_run(AnalysisContext *ctx);

int analysis_find_functions(AnalysisContext *ctx);
int analysis_build_cfg(AnalysisContext *ctx);
int analysis_find_xrefs(AnalysisContext *ctx);
int analysis_find_strings(AnalysisContext *ctx);

Function *analysis_get_function(AnalysisContext *ctx, uint64_t addr);
BasicBlock *analysis_get_block(AnalysisContext *ctx, uint64_t addr);
XRef *analysis_get_xrefs_to(AnalysisContext *ctx, uint64_t addr, size_t *count);
XRef *analysis_get_xrefs_from(AnalysisContext *ctx, uint64_t addr,
                              size_t *count);

void analysis_print_functions(AnalysisContext *ctx);
void analysis_print_cfg(AnalysisContext *ctx, Function *fn);
void analysis_print_xrefs(AnalysisContext *ctx, uint64_t addr);

#endif
