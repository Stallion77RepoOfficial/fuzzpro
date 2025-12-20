#ifndef FUZZPRO_SYMBOLIC_H
#define FUZZPRO_SYMBOLIC_H

#include <stddef.h>
#include <stdint.h>

#define SYM_MAX_BITS 64
#define SYM_MAX_CONSTRAINTS 1024
#define SYM_MAX_MEMORY 4096
#define SYM_MAX_VARS 256

typedef enum { SYM_CONCRETE = 0, SYM_SYMBOLIC, SYM_MIXED } SymType;

typedef enum {
  OP_CONST = 0,
  OP_VAR,
  OP_ADD,
  OP_SUB,
  OP_MUL,
  OP_DIV,
  OP_MOD,
  OP_AND,
  OP_OR,
  OP_XOR,
  OP_NOT,
  OP_SHL,
  OP_SHR,
  OP_SAR,
  OP_EQ,
  OP_NE,
  OP_LT,
  OP_LE,
  OP_GT,
  OP_GE,
  OP_SEXT,
  OP_ZEXT,
  OP_EXTRACT,
  OP_CONCAT,
  OP_ITE
} SymOp;

typedef struct SymExpr {
  SymOp op;
  int bits;
  uint64_t value;
  int var_id;
  struct SymExpr *left;
  struct SymExpr *right;
  struct SymExpr *cond;
} SymExpr;

typedef struct {
  SymExpr *exprs[SYM_MAX_CONSTRAINTS];
  size_t count;
} PathConstraints;

typedef struct {
  SymExpr *regs[32];
  SymExpr *sp;
  SymExpr *pc;
  uint64_t flags_n, flags_z, flags_c, flags_v;
  uint8_t mem_concrete[SYM_MAX_MEMORY];
  SymExpr *mem_symbolic[SYM_MAX_MEMORY];
  size_t mem_base;
  size_t mem_size;
  PathConstraints constraints;
  int var_counter;
} SymState;

typedef struct {
  int var_id;
  uint64_t value;
  int bits;
} SymSolution;

typedef struct {
  SymSolution solutions[SYM_MAX_VARS];
  size_t count;
  int satisfiable;
} SolverResult;

SymState *sym_state_create(void);
void sym_state_destroy(SymState *state);
void sym_state_clone(SymState *dst, SymState *src);

SymExpr *sym_const(uint64_t value, int bits);
SymExpr *sym_var(SymState *state, int bits);
SymExpr *sym_binop(SymOp op, SymExpr *left, SymExpr *right, int bits);
SymExpr *sym_unop(SymOp op, SymExpr *expr, int bits);
void sym_expr_free(SymExpr *expr);

void sym_add_constraint(SymState *state, SymExpr *expr);
int sym_is_concrete(SymExpr *expr);
uint64_t sym_get_concrete(SymExpr *expr);
SymExpr *sym_simplify(SymExpr *expr);

int sym_solve(PathConstraints *constraints, SolverResult *result);

#endif
