#include "constraint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FCEContext *fce_context_create(void) {
  FCEContext *ctx = calloc(1, sizeof(FCEContext));
  return ctx;
}

void fce_context_destroy(FCEContext *ctx) {
  if (!ctx)
    return;
  for (size_t i = 0; i < ctx->node_count; i++) {
    free(ctx->nodes[i]);
  }
  free(ctx);
}

static FCENode *alloc_node(FCEContext *ctx, FCENodeType type, int width) {
  if (ctx->node_count >= FCE_MAX_NODES)
    return NULL;
  FCENode *n = calloc(1, sizeof(FCENode));
  if (!n)
    return NULL;
  n->type = type;
  n->width = width;
  ctx->nodes[ctx->node_count++] = n;
  return n;
}

FCENode *fce_const(FCEContext *ctx, uint64_t value, int width) {
  FCENode *n = alloc_node(ctx, FCE_CONST, width);
  if (n) {
    n->value = value & ((1ULL << width) - 1);
    if (width == 64)
      n->value = value;
  }
  return n;
}

FCENode *fce_var(FCEContext *ctx, const char *name, int width) {
  FCENode *n = alloc_node(ctx, FCE_VAR, width);
  if (n) {
    n->var_id = ctx->var_counter;
    if (name && ctx->var_counter < FCE_MAX_VARS) {
      strncpy(ctx->var_names[ctx->var_counter], name, 31);
    }
    ctx->var_counter++;
  }
  return n;
}

static FCENode *binop(FCEContext *ctx, FCENodeType type, FCENode *a, FCENode *b,
                      int width) {
  FCENode *n = alloc_node(ctx, type, width);
  if (n) {
    n->left = a;
    n->right = b;
  }
  return n;
}

FCENode *fce_not(FCEContext *ctx, FCENode *a) {
  FCENode *n = alloc_node(ctx, FCE_NOT, a ? a->width : 1);
  if (n)
    n->left = a;
  return n;
}

FCENode *fce_and(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_AND, a, b, a ? a->width : 1);
}

FCENode *fce_or(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_OR, a, b, a ? a->width : 1);
}

FCENode *fce_xor(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_XOR, a, b, a ? a->width : 1);
}

FCENode *fce_add(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_ADD, a, b, a ? a->width : 64);
}

FCENode *fce_sub(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_SUB, a, b, a ? a->width : 64);
}

FCENode *fce_mul(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_MUL, a, b, a ? a->width : 64);
}

FCENode *fce_udiv(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_UDIV, a, b, a ? a->width : 64);
}

FCENode *fce_urem(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_UREM, a, b, a ? a->width : 64);
}

FCENode *fce_shl(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_SHL, a, b, a ? a->width : 64);
}

FCENode *fce_lshr(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_LSHR, a, b, a ? a->width : 64);
}

FCENode *fce_eq(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_EQ, a, b, 1);
}

FCENode *fce_ne(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_NE, a, b, 1);
}

FCENode *fce_ult(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_ULT, a, b, 1);
}

FCENode *fce_ule(FCEContext *ctx, FCENode *a, FCENode *b) {
  return binop(ctx, FCE_ULE, a, b, 1);
}

FCENode *fce_concat(FCEContext *ctx, FCENode *hi, FCENode *lo) {
  int new_width = (hi ? hi->width : 0) + (lo ? lo->width : 0);
  return binop(ctx, FCE_CONCAT, hi, lo, new_width);
}

FCENode *fce_extract(FCEContext *ctx, FCENode *a, int hi, int lo) {
  FCENode *n = alloc_node(ctx, FCE_EXTRACT, hi - lo + 1);
  if (n) {
    n->left = a;
    n->hi = hi;
    n->lo = lo;
  }
  return n;
}

FCENode *fce_zext(FCEContext *ctx, FCENode *a, int new_width) {
  FCENode *n = alloc_node(ctx, FCE_ZEXT, new_width);
  if (n)
    n->left = a;
  return n;
}

FCENode *fce_sext(FCEContext *ctx, FCENode *a, int new_width) {
  FCENode *n = alloc_node(ctx, FCE_SEXT, new_width);
  if (n)
    n->left = a;
  return n;
}

FCENode *fce_ite(FCEContext *ctx, FCENode *cond, FCENode *t, FCENode *f) {
  FCENode *n = alloc_node(ctx, FCE_ITE, t ? t->width : 64);
  if (n) {
    n->cond = cond;
    n->left = t;
    n->right = f;
  }
  return n;
}

int fce_is_const(FCENode *n) { return n && n->type == FCE_CONST; }

uint64_t fce_get_const(FCENode *n) { return n ? n->value : 0; }

static uint64_t mask_width(int width) {
  if (width >= 64)
    return ~0ULL;
  return (1ULL << width) - 1;
}

FCENode *fce_simplify(FCEContext *ctx, FCENode *n) {
  if (!n)
    return NULL;

  if (n->type == FCE_CONST || n->type == FCE_VAR)
    return n;

  FCENode *l = n->left ? fce_simplify(ctx, n->left) : NULL;
  FCENode *r = n->right ? fce_simplify(ctx, n->right) : NULL;

  if (l && fce_is_const(l) && r && fce_is_const(r)) {
    uint64_t lv = fce_get_const(l);
    uint64_t rv = fce_get_const(r);
    uint64_t result = 0;

    switch (n->type) {
    case FCE_AND:
      result = lv & rv;
      break;
    case FCE_OR:
      result = lv | rv;
      break;
    case FCE_XOR:
      result = lv ^ rv;
      break;
    case FCE_ADD:
      result = (lv + rv) & mask_width(n->width);
      break;
    case FCE_SUB:
      result = (lv - rv) & mask_width(n->width);
      break;
    case FCE_MUL:
      result = (lv * rv) & mask_width(n->width);
      break;
    case FCE_UDIV:
      result = rv ? lv / rv : 0;
      break;
    case FCE_UREM:
      result = rv ? lv % rv : 0;
      break;
    case FCE_SHL:
      result = (lv << rv) & mask_width(n->width);
      break;
    case FCE_LSHR:
      result = lv >> rv;
      break;
    case FCE_EQ:
      result = lv == rv;
      break;
    case FCE_NE:
      result = lv != rv;
      break;
    case FCE_ULT:
      result = lv < rv;
      break;
    case FCE_ULE:
      result = lv <= rv;
      break;
    default:
      return n;
    }
    return fce_const(ctx, result, n->width);
  }

  if (l && fce_is_const(l) && n->type == FCE_NOT) {
    return fce_const(ctx, ~fce_get_const(l) & mask_width(n->width), n->width);
  }

  return n;
}

void fce_print(FCENode *n, char *buf, size_t len) {
  if (!n || !buf || len == 0)
    return;

  switch (n->type) {
  case FCE_CONST:
    snprintf(buf, len, "0x%llx", (unsigned long long)n->value);
    break;
  case FCE_VAR:
    snprintf(buf, len, "v%d", n->var_id);
    break;
  default:
    snprintf(buf, len, "(expr)");
    break;
  }
}
