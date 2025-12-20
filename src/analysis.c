#include "analysis.h"
#include "arm64dis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

AnalysisContext *analysis_create(void) {
  AnalysisContext *ctx = calloc(1, sizeof(AnalysisContext));
  return ctx;
}

void analysis_destroy(AnalysisContext *ctx) {
  if (!ctx)
    return;
  for (size_t i = 0; i < ctx->func_count; i++) {
    free(ctx->functions[i].blocks);
    free(ctx->functions[i].callers);
    free(ctx->functions[i].callees);
  }
  for (size_t i = 0; i < ctx->block_count; i++) {
    free(ctx->blocks[i].successors);
    free(ctx->blocks[i].predecessors);
  }
  for (size_t i = 0; i < ctx->string_count; i++) {
    free(ctx->strings[i].data);
  }
  free(ctx);
}

int analysis_set_code(AnalysisContext *ctx, const uint8_t *code, size_t len,
                      uint64_t base) {
  if (!ctx || !code)
    return -1;
  ctx->code = code;
  ctx->code_len = len;
  ctx->text_start = base;
  ctx->text_end = base + len;
  return 0;
}

static int is_function_prologue(const uint8_t *code, size_t off, size_t len) {
  if (off + 8 > len)
    return 0;
  uint32_t insn1 = *(uint32_t *)(code + off);
  uint32_t insn2 = *(uint32_t *)(code + off + 4);

  if ((insn1 & 0xFFC003FF) == 0xA9007BFD)
    return 1;
  if ((insn1 & 0xFF8003FF) == 0xD10003FF)
    return 1;
  if ((insn1 & 0xFFC003FF) == 0xA98003FD)
    return 1;
  if ((insn2 & 0xFFC003FF) == 0xA9007BFD)
    return 1;

  return 0;
}

static int is_function_epilogue(uint32_t insn) {
  if (insn == 0xD65F03C0)
    return 1;
  if ((insn & 0xFFC003FF) == 0xA8C07BFD)
    return 1;
  return 0;
}

int analysis_find_functions(AnalysisContext *ctx) {
  if (!ctx || !ctx->code)
    return -1;

  ctx->func_count = 0;

  for (size_t off = 0; off + 4 <= ctx->code_len; off += 4) {
    if (is_function_prologue(ctx->code, off, ctx->code_len)) {
      if (ctx->func_count >= MAX_FUNCTIONS)
        break;

      Function *fn = &ctx->functions[ctx->func_count];
      memset(fn, 0, sizeof(*fn));
      fn->start = ctx->text_start + off;
      fn->has_prologue = 1;

      for (size_t end = off + 4; end + 4 <= ctx->code_len; end += 4) {
        uint32_t insn = *(uint32_t *)(ctx->code + end);
        if (is_function_epilogue(insn)) {
          fn->end = ctx->text_start + end + 4;
          break;
        }
        if (is_function_prologue(ctx->code, end, ctx->code_len) &&
            end > off + 8) {
          fn->end = ctx->text_start + end;
          break;
        }
      }

      if (fn->end == 0)
        fn->end = fn->start + 4;

      snprintf(fn->name, sizeof(fn->name), "sub_%llx",
               (unsigned long long)fn->start);
      ctx->func_count++;
      off = fn->end - ctx->text_start - 4;
    }
  }

  return (int)ctx->func_count;
}

static void add_block(AnalysisContext *ctx, uint64_t addr) {
  if (ctx->block_count >= MAX_BASIC_BLOCKS)
    return;
  for (size_t i = 0; i < ctx->block_count; i++) {
    if (ctx->blocks[i].start == addr)
      return;
  }
  BasicBlock *bb = &ctx->blocks[ctx->block_count++];
  memset(bb, 0, sizeof(*bb));
  bb->start = addr;
}

static void add_edge(AnalysisContext *ctx, uint64_t from, uint64_t to) {
  BasicBlock *src = NULL, *dst = NULL;
  for (size_t i = 0; i < ctx->block_count; i++) {
    if (ctx->blocks[i].start <= from && from < ctx->blocks[i].end) {
      src = &ctx->blocks[i];
    }
    if (ctx->blocks[i].start == to) {
      dst = &ctx->blocks[i];
    }
  }
  if (src && dst) {
    src->successors =
        realloc(src->successors, (src->succ_count + 1) * sizeof(uint64_t));
    if (src->successors)
      src->successors[src->succ_count++] = to;
    dst->predecessors =
        realloc(dst->predecessors, (dst->pred_count + 1) * sizeof(uint64_t));
    if (dst->predecessors)
      dst->predecessors[dst->pred_count++] = from;
  }
}

int analysis_build_cfg(AnalysisContext *ctx) {
  if (!ctx || !ctx->code)
    return -1;

  ctx->block_count = 0;
  add_block(ctx, ctx->text_start);

  for (size_t off = 0; off + 4 <= ctx->code_len; off += 4) {
    uint32_t insn = *(uint32_t *)(ctx->code + off);
    uint64_t addr = ctx->text_start + off;

    if ((insn & 0x7C000000) == 0x14000000) {
      int32_t imm26 = insn & 0x03FFFFFF;
      if (imm26 & 0x02000000)
        imm26 |= 0xFC000000;
      uint64_t target = addr + (imm26 << 2);

      add_block(ctx, target);
      if (!(insn & 0x80000000)) {
        add_block(ctx, addr + 4);
      }
    }

    if ((insn & 0xFE000000) == 0x54000000 ||
        (insn & 0x7E000000) == 0x34000000 ||
        (insn & 0x7E000000) == 0x36000000) {

      int32_t imm19 = (insn >> 5) & 0x7FFFF;
      if (imm19 & 0x40000)
        imm19 |= 0xFFF80000;
      uint64_t target = addr + (imm19 << 2);

      add_block(ctx, target);
      add_block(ctx, addr + 4);
    }

    if (is_function_epilogue(insn)) {
      if (off + 4 < ctx->code_len) {
        add_block(ctx, addr + 4);
      }
    }
  }

  for (size_t i = 0; i < ctx->block_count; i++) {
    BasicBlock *bb = &ctx->blocks[i];
    if (bb->end == 0) {
      uint64_t next_start = ctx->text_end;
      for (size_t j = 0; j < ctx->block_count; j++) {
        if (ctx->blocks[j].start > bb->start &&
            ctx->blocks[j].start < next_start) {
          next_start = ctx->blocks[j].start;
        }
      }
      bb->end = next_start;
    }
  }

  for (size_t off = 0; off + 4 <= ctx->code_len; off += 4) {
    uint32_t insn = *(uint32_t *)(ctx->code + off);
    uint64_t addr = ctx->text_start + off;

    if ((insn & 0x7C000000) == 0x14000000) {
      int32_t imm26 = insn & 0x03FFFFFF;
      if (imm26 & 0x02000000)
        imm26 |= 0xFC000000;
      uint64_t target = addr + (imm26 << 2);
      add_edge(ctx, addr, target);
    }

    if ((insn & 0xFE000000) == 0x54000000 ||
        (insn & 0x7E000000) == 0x34000000 ||
        (insn & 0x7E000000) == 0x36000000) {

      int32_t imm19 = (insn >> 5) & 0x7FFFF;
      if (imm19 & 0x40000)
        imm19 |= 0xFFF80000;
      uint64_t target = addr + (imm19 << 2);
      add_edge(ctx, addr, target);
      add_edge(ctx, addr, addr + 4);
    }
  }

  return (int)ctx->block_count;
}

int analysis_find_xrefs(AnalysisContext *ctx) {
  if (!ctx || !ctx->code)
    return -1;

  ctx->xref_count = 0;

  for (size_t off = 0; off + 4 <= ctx->code_len; off += 4) {
    uint32_t insn = *(uint32_t *)(ctx->code + off);
    uint64_t addr = ctx->text_start + off;

    if (ctx->xref_count >= MAX_XREFS)
      break;

    if ((insn & 0xFC000000) == 0x94000000) {
      int32_t imm26 = insn & 0x03FFFFFF;
      if (imm26 & 0x02000000)
        imm26 |= 0xFC000000;
      uint64_t target = addr + (imm26 << 2);

      XRef *xr = &ctx->xrefs[ctx->xref_count++];
      xr->from = addr;
      xr->to = target;
      xr->type = XREF_CODE_CALL;
    }

    if ((insn & 0xFC000000) == 0x14000000) {
      int32_t imm26 = insn & 0x03FFFFFF;
      if (imm26 & 0x02000000)
        imm26 |= 0xFC000000;
      uint64_t target = addr + (imm26 << 2);

      XRef *xr = &ctx->xrefs[ctx->xref_count++];
      xr->from = addr;
      xr->to = target;
      xr->type = XREF_CODE_JUMP;
    }

    if ((insn & 0xFE000000) == 0x54000000 ||
        (insn & 0x7E000000) == 0x34000000 ||
        (insn & 0x7E000000) == 0x36000000) {

      int32_t imm19 = (insn >> 5) & 0x7FFFF;
      if (imm19 & 0x40000)
        imm19 |= 0xFFF80000;
      uint64_t target = addr + (imm19 << 2);

      XRef *xr = &ctx->xrefs[ctx->xref_count++];
      xr->from = addr;
      xr->to = target;
      xr->type = XREF_CODE_COND;
    }

    if ((insn & 0x9F000000) == 0x90000000) {
      int64_t immlo = (insn >> 29) & 3;
      int64_t immhi = ((insn >> 5) & 0x7FFFF);
      if (immhi & 0x40000)
        immhi |= 0xFFFFFFFFFFF80000ULL;
      uint64_t target = (addr & ~0xFFFULL) + ((immhi << 14) | (immlo << 12));

      XRef *xr = &ctx->xrefs[ctx->xref_count++];
      xr->from = addr;
      xr->to = target;
      xr->type = XREF_DATA_OFFSET;
    }

    if ((insn & 0x3B000000) == 0x18000000) {
      int32_t imm19 = (insn >> 5) & 0x7FFFF;
      if (imm19 & 0x40000)
        imm19 |= 0xFFF80000;
      uint64_t target = addr + (imm19 << 2);

      XRef *xr = &ctx->xrefs[ctx->xref_count++];
      xr->from = addr;
      xr->to = target;
      xr->type = XREF_DATA_READ;
    }
  }

  return (int)ctx->xref_count;
}

static int is_printable_string(const uint8_t *data, size_t max_len,
                               size_t *out_len) {
  size_t len = 0;
  while (len < max_len && data[len] != 0) {
    if (data[len] < 0x20 || data[len] > 0x7E) {
      if (data[len] != '\n' && data[len] != '\r' && data[len] != '\t') {
        return 0;
      }
    }
    len++;
  }
  if (len >= 4 && data[len] == 0) {
    *out_len = len;
    return 1;
  }
  return 0;
}

int analysis_find_strings(AnalysisContext *ctx) {
  if (!ctx || !ctx->code)
    return -1;

  ctx->string_count = 0;

  for (size_t off = 0; off < ctx->code_len && ctx->string_count < MAX_STRINGS;
       off++) {
    size_t str_len = 0;
    if (is_printable_string(ctx->code + off, ctx->code_len - off, &str_len)) {
      StringRef *sr = &ctx->strings[ctx->string_count++];
      sr->addr = ctx->text_start + off;
      sr->length = str_len;
      sr->data = malloc(str_len + 1);
      if (sr->data) {
        memcpy(sr->data, ctx->code + off, str_len);
        sr->data[str_len] = 0;
      }
      off += str_len;
    }
  }

  return (int)ctx->string_count;
}

int analysis_run(AnalysisContext *ctx) {
  if (!ctx)
    return -1;

  int funcs = analysis_find_functions(ctx);
  int blocks = analysis_build_cfg(ctx);
  int xrefs = analysis_find_xrefs(ctx);
  int strings = analysis_find_strings(ctx);

  return funcs + blocks + xrefs + strings;
}

Function *analysis_get_function(AnalysisContext *ctx, uint64_t addr) {
  if (!ctx)
    return NULL;
  for (size_t i = 0; i < ctx->func_count; i++) {
    if (ctx->functions[i].start <= addr && addr < ctx->functions[i].end) {
      return &ctx->functions[i];
    }
  }
  return NULL;
}

BasicBlock *analysis_get_block(AnalysisContext *ctx, uint64_t addr) {
  if (!ctx)
    return NULL;
  for (size_t i = 0; i < ctx->block_count; i++) {
    if (ctx->blocks[i].start <= addr && addr < ctx->blocks[i].end) {
      return &ctx->blocks[i];
    }
  }
  return NULL;
}

XRef *analysis_get_xrefs_to(AnalysisContext *ctx, uint64_t addr,
                            size_t *count) {
  if (!ctx || !count)
    return NULL;
  static XRef results[256];
  *count = 0;
  for (size_t i = 0; i < ctx->xref_count && *count < 256; i++) {
    if (ctx->xrefs[i].to == addr) {
      results[(*count)++] = ctx->xrefs[i];
    }
  }
  return *count > 0 ? results : NULL;
}

XRef *analysis_get_xrefs_from(AnalysisContext *ctx, uint64_t addr,
                              size_t *count) {
  if (!ctx || !count)
    return NULL;
  static XRef results[256];
  *count = 0;
  for (size_t i = 0; i < ctx->xref_count && *count < 256; i++) {
    if (ctx->xrefs[i].from == addr) {
      results[(*count)++] = ctx->xrefs[i];
    }
  }
  return *count > 0 ? results : NULL;
}

void analysis_print_functions(AnalysisContext *ctx) {
  if (!ctx)
    return;
  printf("Functions: %zu\n", ctx->func_count);
  for (size_t i = 0; i < ctx->func_count && i < 20; i++) {
    Function *fn = &ctx->functions[i];
    printf("  %s: 0x%llx - 0x%llx (%llu bytes)\n", fn->name,
           (unsigned long long)fn->start, (unsigned long long)fn->end,
           (unsigned long long)(fn->end - fn->start));
  }
}

void analysis_print_cfg(AnalysisContext *ctx, Function *fn) {
  if (!ctx || !fn)
    return;
  printf("CFG for %s:\n", fn->name);
  for (size_t i = 0; i < ctx->block_count; i++) {
    BasicBlock *bb = &ctx->blocks[i];
    if (bb->start >= fn->start && bb->start < fn->end) {
      printf("  BB 0x%llx -> ", (unsigned long long)bb->start);
      for (size_t j = 0; j < bb->succ_count; j++) {
        printf("0x%llx ", (unsigned long long)bb->successors[j]);
      }
      printf("\n");
    }
  }
}

void analysis_print_xrefs(AnalysisContext *ctx, uint64_t addr) {
  if (!ctx)
    return;
  size_t count;
  XRef *xrefs = analysis_get_xrefs_to(ctx, addr, &count);
  printf("XRefs to 0x%llx: %zu\n", (unsigned long long)addr, count);
  for (size_t i = 0; i < count; i++) {
    const char *type_str[] = {"call", "jump",  "cond",
                              "read", "write", "offset"};
    printf("  0x%llx (%s)\n", (unsigned long long)xrefs[i].from,
           type_str[xrefs[i].type]);
  }
}
