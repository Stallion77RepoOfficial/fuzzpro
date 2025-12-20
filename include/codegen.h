#ifndef FUZZPRO_CODEGEN_H
#define FUZZPRO_CODEGEN_H

#include "ssa.h"
#include <stddef.h>

#define CODEGEN_MAX_VARS 256
#define CODEGEN_MAX_OUTPUT 65536

typedef enum {
  TYPE_UNKNOWN = 0,
  TYPE_VOID,
  TYPE_INT8,
  TYPE_UINT8,
  TYPE_INT16,
  TYPE_UINT16,
  TYPE_INT32,
  TYPE_UINT32,
  TYPE_INT64,
  TYPE_UINT64,
  TYPE_PTR,
  TYPE_ARRAY
} VarType;

typedef struct {
  int var_id;
  int version;
  VarType type;
  char name[32];
  int is_param;
  int is_local;
} VarInfo;

typedef struct {
  VarInfo vars[CODEGEN_MAX_VARS];
  size_t var_count;
  char output[CODEGEN_MAX_OUTPUT];
  size_t output_len;
  int indent;
  int use_structured;
} CodeGen;

CodeGen *codegen_create(void);
void codegen_destroy(CodeGen *cg);
int codegen_from_ssa(CodeGen *cg, SSAFunction *fn);
const char *codegen_get_output(CodeGen *cg);
void codegen_set_structured(CodeGen *cg, int enable);
VarType codegen_infer_type(CodeGen *cg, SSAOperand *op);
const char *codegen_type_name(VarType t);

#endif
