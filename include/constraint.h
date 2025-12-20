#ifndef FUZZPRO_CONSTRAINT_H
#define FUZZPRO_CONSTRAINT_H

#include <stddef.h>
#include <stdint.h>

#define FCE_MAX_NODES 4096
#define FCE_MAX_VARS 512
#define FCE_MAX_CLAUSES 2048

typedef enum {
  FCE_CONST = 0,
  FCE_VAR,
  FCE_NOT,
  FCE_AND,
  FCE_OR,
  FCE_XOR,
  FCE_ADD,
  FCE_SUB,
  FCE_MUL,
  FCE_UDIV,
  FCE_UREM,
  FCE_SHL,
  FCE_LSHR,
  FCE_ASHR,
  FCE_EQ,
  FCE_NE,
  FCE_ULT,
  FCE_ULE,
  FCE_UGT,
  FCE_UGE,
  FCE_SLT,
  FCE_SLE,
  FCE_SGT,
  FCE_SGE,
  FCE_CONCAT,
  FCE_EXTRACT,
  FCE_ZEXT,
  FCE_SEXT,
  FCE_ITE
} FCENodeType;

typedef struct FCENode {
  FCENodeType type;
  int width;
  uint64_t value;
  int var_id;
  struct FCENode *left;
  struct FCENode *right;
  struct FCENode *cond;
  int hi;
  int lo;
} FCENode;

typedef struct {
  int var_id;
  uint64_t value;
  int width;
} FCESolution;

typedef struct {
  FCENode *nodes[FCE_MAX_NODES];
  size_t node_count;
  int var_counter;
  char var_names[FCE_MAX_VARS][32];
} FCEContext;

FCEContext *fce_context_create(void);
void fce_context_destroy(FCEContext *ctx);

FCENode *fce_const(FCEContext *ctx, uint64_t value, int width);
FCENode *fce_var(FCEContext *ctx, const char *name, int width);
FCENode *fce_not(FCEContext *ctx, FCENode *a);
FCENode *fce_and(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_or(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_xor(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_add(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_sub(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_mul(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_udiv(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_urem(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_shl(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_lshr(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_eq(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_ne(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_ult(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_ule(FCEContext *ctx, FCENode *a, FCENode *b);
FCENode *fce_concat(FCEContext *ctx, FCENode *hi, FCENode *lo);
FCENode *fce_extract(FCEContext *ctx, FCENode *a, int hi, int lo);
FCENode *fce_zext(FCEContext *ctx, FCENode *a, int new_width);
FCENode *fce_sext(FCEContext *ctx, FCENode *a, int new_width);
FCENode *fce_ite(FCEContext *ctx, FCENode *cond, FCENode *t, FCENode *f);

int fce_is_const(FCENode *n);
uint64_t fce_get_const(FCENode *n);
FCENode *fce_simplify(FCEContext *ctx, FCENode *n);
void fce_print(FCENode *n, char *buf, size_t len);

#endif
