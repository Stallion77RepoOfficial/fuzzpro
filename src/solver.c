#include "solver.h"
#include <stdlib.h>
#include <string.h>

SATSolver *sat_create(void) {
  SATSolver *sat = calloc(1, sizeof(SATSolver));
  if (sat) {
    sat->max_iterations = 100000;
    for (int i = 0; i < SOLVER_MAX_VARS; i++) {
      sat->assignment[i] = -1;
    }
  }
  return sat;
}

void sat_destroy(SATSolver *sat) { free(sat); }

void sat_add_clause(SATSolver *sat, int *literals, int count) {
  if (!sat || sat->clause_count >= SOLVER_MAX_CLAUSES)
    return;
  if (count > 16)
    count = 16;

  Clause *c = &sat->clauses[sat->clause_count++];
  c->count = count;
  for (int i = 0; i < count; i++) {
    c->literals[i] = literals[i];
    int var = abs(literals[i]);
    if (var > sat->var_count)
      sat->var_count = var;
  }
}

static int eval_literal(SATSolver *sat, int lit) {
  int var = abs(lit);
  if (var >= SOLVER_MAX_VARS)
    return 0;
  int val = sat->assignment[var];
  if (val == -1)
    return -1;
  return (lit > 0) ? val : !val;
}

static int eval_clause(SATSolver *sat, Clause *c) {
  int has_unassigned = 0;
  for (int i = 0; i < c->count; i++) {
    int v = eval_literal(sat, c->literals[i]);
    if (v == 1)
      return 1;
    if (v == -1)
      has_unassigned = 1;
  }
  return has_unassigned ? -1 : 0;
}

static int unit_propagate(SATSolver *sat) {
  int changed = 1;
  while (changed) {
    changed = 0;
    for (size_t i = 0; i < sat->clause_count; i++) {
      Clause *c = &sat->clauses[i];
      int unassigned_lit = 0;
      int unassigned_count = 0;
      int satisfied = 0;

      for (int j = 0; j < c->count; j++) {
        int v = eval_literal(sat, c->literals[j]);
        if (v == 1) {
          satisfied = 1;
          break;
        }
        if (v == -1) {
          unassigned_lit = c->literals[j];
          unassigned_count++;
        }
      }

      if (satisfied)
        continue;

      if (unassigned_count == 0) {
        sat->conflicts++;
        return 0;
      }

      if (unassigned_count == 1) {
        int var = abs(unassigned_lit);
        sat->assignment[var] = (unassigned_lit > 0) ? 1 : 0;
        sat->propagations++;
        changed = 1;
      }
    }
  }
  return 1;
}

static int all_satisfied(SATSolver *sat) {
  for (size_t i = 0; i < sat->clause_count; i++) {
    if (eval_clause(sat, &sat->clauses[i]) != 1)
      return 0;
  }
  return 1;
}

static int pick_unassigned(SATSolver *sat) {
  for (int i = 1; i <= sat->var_count; i++) {
    if (sat->assignment[i] == -1)
      return i;
  }
  return 0;
}

static SolverStatus dpll(SATSolver *sat, int depth) {
  if (depth > sat->max_iterations)
    return SOLVER_TIMEOUT;

  if (!unit_propagate(sat))
    return SOLVER_UNSAT;
  if (all_satisfied(sat))
    return SOLVER_SAT;

  int var = pick_unassigned(sat);
  if (var == 0)
    return SOLVER_UNSAT;

  int8_t saved[SOLVER_MAX_VARS];
  memcpy(saved, sat->assignment, sizeof(saved));

  sat->assignment[var] = 1;
  sat->decisions++;
  if (dpll(sat, depth + 1) == SOLVER_SAT)
    return SOLVER_SAT;

  memcpy(sat->assignment, saved, sizeof(saved));

  sat->assignment[var] = 0;
  sat->decisions++;
  if (dpll(sat, depth + 1) == SOLVER_SAT)
    return SOLVER_SAT;

  memcpy(sat->assignment, saved, sizeof(saved));
  return SOLVER_UNSAT;
}

SolverStatus sat_solve(SATSolver *sat) {
  if (!sat)
    return SOLVER_UNKNOWN;
  return dpll(sat, 0);
}

int sat_get_value(SATSolver *sat, int var) {
  if (!sat || var < 0 || var >= SOLVER_MAX_VARS)
    return -1;
  return sat->assignment[var];
}

FCESolver *fce_solver_create(FCEContext *ctx) {
  FCESolver *s = calloc(1, sizeof(FCESolver));
  if (!s)
    return NULL;
  s->ctx = ctx;
  s->sat = sat_create();
  s->status = SOLVER_UNKNOWN;
  return s;
}

void fce_solver_destroy(FCESolver *s) {
  if (!s)
    return;
  sat_destroy(s->sat);
  free(s);
}

static void encode_constraint(FCESolver *s, FCENode *n, int target_lit);

static int fresh_var(FCESolver *s) { return ++s->sat->var_count; }

static void encode_eq_const(FCESolver *s, FCENode *var_node, uint64_t target) {
  if (!var_node || var_node->type != FCE_VAR)
    return;

  int base_var = var_node->var_id * 64;

  for (int bit = 0; bit < var_node->width; bit++) {
    int lit = base_var + bit + 1;
    int target_bit = (target >> bit) & 1;

    int clause[1];
    clause[0] = target_bit ? lit : -lit;
    sat_add_clause(s->sat, clause, 1);
  }
}

void fce_solver_add_constraint(FCESolver *s, FCENode *constraint) {
  if (!s || !constraint)
    return;

  if (constraint->type == FCE_EQ) {
    FCENode *left = constraint->left;
    FCENode *right = constraint->right;

    if (left && left->type == FCE_VAR && right && right->type == FCE_CONST) {
      encode_eq_const(s, left, right->value);
      return;
    }
    if (right && right->type == FCE_VAR && left && left->type == FCE_CONST) {
      encode_eq_const(s, right, left->value);
      return;
    }
  }
}

SolverStatus fce_solver_check(FCESolver *s) {
  if (!s)
    return SOLVER_UNKNOWN;

  s->status = sat_solve(s->sat);

  if (s->status == SOLVER_SAT) {
    s->solution_count = 0;
    for (int v = 0; v < s->ctx->var_counter && s->solution_count < FCE_MAX_VARS;
         v++) {
      uint64_t val = 0;
      int base = v * 64;
      for (int bit = 0; bit < 64; bit++) {
        int lit_val = sat_get_value(s->sat, base + bit + 1);
        if (lit_val == 1)
          val |= (1ULL << bit);
      }
      s->solutions[s->solution_count].var_id = v;
      s->solutions[s->solution_count].value = val;
      s->solutions[s->solution_count].width = 64;
      s->solution_count++;
    }
  }

  return s->status;
}

int fce_solver_get_value(FCESolver *s, FCENode *var, uint64_t *value) {
  if (!s || !var || !value || var->type != FCE_VAR)
    return 0;

  for (size_t i = 0; i < s->solution_count; i++) {
    if (s->solutions[i].var_id == var->var_id) {
      *value = s->solutions[i].value;
      return 1;
    }
  }
  return 0;
}

int fce_solver_model_count(FCESolver *s) {
  return s ? (int)s->solution_count : 0;
}
