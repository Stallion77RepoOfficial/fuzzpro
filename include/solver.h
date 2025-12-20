#ifndef FUZZPRO_SOLVER_H
#define FUZZPRO_SOLVER_H

#include "constraint.h"

#define SOLVER_MAX_VARS 512
#define SOLVER_MAX_CLAUSES 4096

typedef enum {
  SOLVER_SAT = 0,
  SOLVER_UNSAT,
  SOLVER_UNKNOWN,
  SOLVER_TIMEOUT
} SolverStatus;

typedef struct {
  int literals[16];
  int count;
} Clause;

typedef struct {
  Clause clauses[SOLVER_MAX_CLAUSES];
  size_t clause_count;
  int8_t assignment[SOLVER_MAX_VARS];
  int8_t decision_level[SOLVER_MAX_VARS];
  int var_count;
  int decisions;
  int propagations;
  int conflicts;
  int max_iterations;
} SATSolver;

typedef struct {
  FCEContext *ctx;
  SATSolver *sat;
  FCESolution solutions[FCE_MAX_VARS];
  size_t solution_count;
  SolverStatus status;
} FCESolver;

FCESolver *fce_solver_create(FCEContext *ctx);
void fce_solver_destroy(FCESolver *s);
void fce_solver_add_constraint(FCESolver *s, FCENode *constraint);
SolverStatus fce_solver_check(FCESolver *s);
int fce_solver_get_value(FCESolver *s, FCENode *var, uint64_t *value);
int fce_solver_model_count(FCESolver *s);

SATSolver *sat_create(void);
void sat_destroy(SATSolver *sat);
void sat_add_clause(SATSolver *sat, int *literals, int count);
SolverStatus sat_solve(SATSolver *sat);
int sat_get_value(SATSolver *sat, int var);

#endif
