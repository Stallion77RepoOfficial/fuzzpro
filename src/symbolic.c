#include "symbolic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SymState *sym_state_create(void) {
  SymState *state = calloc(1, sizeof(SymState));
  if (!state)
    return NULL;

  for (int i = 0; i < 32; i++) {
    state->regs[i] = sym_const(0, 64);
  }
  state->sp = sym_const(0x7FFFFF00, 64);
  state->pc = sym_const(0, 64);
  state->var_counter = 0;

  return state;
}

void sym_state_destroy(SymState *state) {
  if (!state)
    return;
  for (int i = 0; i < 32; i++) {
    sym_expr_free(state->regs[i]);
  }
  sym_expr_free(state->sp);
  sym_expr_free(state->pc);
  for (size_t i = 0; i < state->constraints.count; i++) {
    sym_expr_free(state->constraints.exprs[i]);
  }
  for (size_t i = 0; i < SYM_MAX_MEMORY; i++) {
    if (state->mem_symbolic[i]) {
      sym_expr_free(state->mem_symbolic[i]);
    }
  }
  free(state);
}

SymExpr *sym_const(uint64_t value, int bits) {
  SymExpr *expr = calloc(1, sizeof(SymExpr));
  if (!expr)
    return NULL;
  expr->op = OP_CONST;
  expr->value = value;
  expr->bits = bits;
  return expr;
}

SymExpr *sym_var(SymState *state, int bits) {
  SymExpr *expr = calloc(1, sizeof(SymExpr));
  if (!expr)
    return NULL;
  expr->op = OP_VAR;
  expr->var_id = state->var_counter++;
  expr->bits = bits;
  return expr;
}

SymExpr *sym_binop(SymOp op, SymExpr *left, SymExpr *right, int bits) {
  SymExpr *expr = calloc(1, sizeof(SymExpr));
  if (!expr)
    return NULL;
  expr->op = op;
  expr->left = left;
  expr->right = right;
  expr->bits = bits;
  return expr;
}

SymExpr *sym_unop(SymOp op, SymExpr *expr_in, int bits) {
  SymExpr *expr = calloc(1, sizeof(SymExpr));
  if (!expr)
    return NULL;
  expr->op = op;
  expr->left = expr_in;
  expr->bits = bits;
  return expr;
}

void sym_expr_free(SymExpr *expr) {
  if (!expr)
    return;
  sym_expr_free(expr->left);
  sym_expr_free(expr->right);
  sym_expr_free(expr->cond);
  free(expr);
}

int sym_is_concrete(SymExpr *expr) {
  if (!expr)
    return 1;
  if (expr->op == OP_CONST)
    return 1;
  if (expr->op == OP_VAR)
    return 0;
  return sym_is_concrete(expr->left) && sym_is_concrete(expr->right);
}

uint64_t sym_get_concrete(SymExpr *expr) {
  if (!expr || expr->op == OP_VAR)
    return 0;
  if (expr->op == OP_CONST)
    return expr->value;

  uint64_t l = expr->left ? sym_get_concrete(expr->left) : 0;
  uint64_t r = expr->right ? sym_get_concrete(expr->right) : 0;

  switch (expr->op) {
  case OP_ADD:
    return l + r;
  case OP_SUB:
    return l - r;
  case OP_MUL:
    return l * r;
  case OP_DIV:
    return r ? l / r : 0;
  case OP_MOD:
    return r ? l % r : 0;
  case OP_AND:
    return l & r;
  case OP_OR:
    return l | r;
  case OP_XOR:
    return l ^ r;
  case OP_NOT:
    return ~l;
  case OP_SHL:
    return l << r;
  case OP_SHR:
    return l >> r;
  case OP_EQ:
    return l == r;
  case OP_NE:
    return l != r;
  case OP_LT:
    return l < r;
  case OP_LE:
    return l <= r;
  case OP_GT:
    return l > r;
  case OP_GE:
    return l >= r;
  default:
    return 0;
  }
}

SymExpr *sym_simplify(SymExpr *expr) {
  if (!expr)
    return NULL;
  if (sym_is_concrete(expr)) {
    uint64_t val = sym_get_concrete(expr);
    return sym_const(val, expr->bits);
  }
  return expr;
}

void sym_add_constraint(SymState *state, SymExpr *expr) {
  if (!state || !expr)
    return;
  if (state->constraints.count >= SYM_MAX_CONSTRAINTS)
    return;
  state->constraints.exprs[state->constraints.count++] = expr;
}

static int solve_recursive(SymExpr *expr, SolverResult *result, int depth) {
  if (depth > 20)
    return 0;
  if (!expr)
    return 1;

  if (expr->op == OP_CONST) {
    return expr->value != 0;
  }

  if (expr->op == OP_VAR) {
    for (size_t i = 0; i < result->count; i++) {
      if (result->solutions[i].var_id == expr->var_id) {
        return result->solutions[i].value != 0;
      }
    }
    return 1;
  }

  if (expr->op == OP_EQ && expr->left && expr->right) {
    if (expr->left->op == OP_VAR && sym_is_concrete(expr->right)) {
      int var_id = expr->left->var_id;
      uint64_t val = sym_get_concrete(expr->right);

      for (size_t i = 0; i < result->count; i++) {
        if (result->solutions[i].var_id == var_id) {
          return result->solutions[i].value == val;
        }
      }

      if (result->count < SYM_MAX_VARS) {
        result->solutions[result->count].var_id = var_id;
        result->solutions[result->count].value = val;
        result->solutions[result->count].bits = expr->left->bits;
        result->count++;
      }
      return 1;
    }

    if (expr->right->op == OP_VAR && sym_is_concrete(expr->left)) {
      int var_id = expr->right->var_id;
      uint64_t val = sym_get_concrete(expr->left);

      if (result->count < SYM_MAX_VARS) {
        result->solutions[result->count].var_id = var_id;
        result->solutions[result->count].value = val;
        result->solutions[result->count].bits = expr->right->bits;
        result->count++;
      }
      return 1;
    }
  }

  if (expr->op == OP_AND) {
    return solve_recursive(expr->left, result, depth + 1) &&
           solve_recursive(expr->right, result, depth + 1);
  }

  return 1;
}

int sym_solve(PathConstraints *constraints, SolverResult *result) {
  if (!constraints || !result)
    return 0;

  memset(result, 0, sizeof(*result));

  for (size_t i = 0; i < constraints->count; i++) {
    if (!solve_recursive(constraints->exprs[i], result, 0)) {
      result->satisfiable = 0;
      return 0;
    }
  }

  result->satisfiable = 1;
  return 1;
}
