
#ifndef FUZZPRO_ARM64DIS_V2_H
#define FUZZPRO_ARM64DIS_V2_H
#include <stddef.h>
#include <stdint.h>

typedef enum {
  A64_INVALID = 0,

  A64_ADD_IMM,
  A64_ADDS_IMM,
  A64_SUB_IMM,
  A64_SUBS_IMM,
  A64_CMN_IMM,
  A64_CMP_IMM,

  A64_AND_IMM,
  A64_ORR_IMM,
  A64_EOR_IMM,
  A64_ANDS_IMM,
  A64_TST_IMM,

  A64_MOVN,
  A64_MOVZ,
  A64_MOVK,
  A64_MOV_IMM,

  A64_ADR,
  A64_ADRP,

  A64_SBFM,
  A64_BFM,
  A64_UBFM,
  A64_SXTB,
  A64_SXTH,
  A64_SXTW,
  A64_UXTB,
  A64_UXTH,
  A64_ASR_IMM,
  A64_LSL_IMM,
  A64_LSR_IMM,

  A64_EXTR,
  A64_ROR_IMM,

  A64_AND_REG,
  A64_BIC,
  A64_ORR_REG,
  A64_ORN,
  A64_EOR_REG,
  A64_EON,
  A64_ANDS_REG,
  A64_BICS,
  A64_TST_REG,
  A64_MOV_REG,
  A64_MVN,

  A64_ADD_REG,
  A64_ADDS_REG,
  A64_SUB_REG,
  A64_SUBS_REG,
  A64_CMN_REG,
  A64_CMP_REG,
  A64_NEG,
  A64_NEGS,

  A64_ADD_EXT,
  A64_ADDS_EXT,
  A64_SUB_EXT,
  A64_SUBS_EXT,

  A64_ADC,
  A64_ADCS,
  A64_SBC,
  A64_SBCS,
  A64_NGC,
  A64_NGCS,

  A64_CCMN_REG,
  A64_CCMP_REG,
  A64_CCMN_IMM,
  A64_CCMP_IMM,

  A64_CSEL,
  A64_CSINC,
  A64_CSINV,
  A64_CSNEG,
  A64_CSET,
  A64_CSETM,
  A64_CINC,
  A64_CINV,
  A64_CNEG,

  A64_LSLV,
  A64_LSRV,
  A64_ASRV,
  A64_RORV,
  A64_LSL_REG,
  A64_LSR_REG,
  A64_ASR_REG,
  A64_ROR_REG,

  A64_CLS,
  A64_CLZ,
  A64_RBIT,
  A64_REV,
  A64_REV16,
  A64_REV32,

  A64_MADD,
  A64_MSUB,
  A64_MUL,
  A64_MNEG,
  A64_SMADDL,
  A64_SMSUBL,
  A64_SMULL,
  A64_SMNEGL,
  A64_SMULH,
  A64_UMADDL,
  A64_UMSUBL,
  A64_UMULL,
  A64_UMNEGL,
  A64_UMULH,

  A64_SDIV,
  A64_UDIV,

  A64_B,
  A64_BL,

  A64_BR,
  A64_BLR,
  A64_RET,
  A64_ERET,
  A64_DRPS,

  A64_B_COND,

  A64_CBZ,
  A64_CBNZ,

  A64_TBZ,
  A64_TBNZ,

  A64_LDR_IMM,
  A64_LDRB_IMM,
  A64_LDRH_IMM,
  A64_LDRSB_IMM,
  A64_LDRSH_IMM,
  A64_LDRSW_IMM,

  A64_STR_IMM,
  A64_STRB_IMM,
  A64_STRH_IMM,

  A64_LDR_REG,
  A64_LDRB_REG,
  A64_LDRH_REG,
  A64_LDRSB_REG,
  A64_LDRSH_REG,
  A64_LDRSW_REG,

  A64_STR_REG,
  A64_STRB_REG,
  A64_STRH_REG,

  A64_LDUR,
  A64_LDURB,
  A64_LDURH,
  A64_LDURSB,
  A64_LDURSH,
  A64_LDURSW,
  A64_STUR,
  A64_STURB,
  A64_STURH,

  A64_LDR_PRE,
  A64_STR_PRE,

  A64_LDR_POST,
  A64_STR_POST,

  A64_LDR_LIT,
  A64_LDRSW_LIT,

  A64_LDP,
  A64_STP,
  A64_LDP_PRE,
  A64_STP_PRE,
  A64_LDP_POST,
  A64_STP_POST,
  A64_LDPSW,
  A64_LDNP,
  A64_STNP,

  A64_LDXR,
  A64_LDXRB,
  A64_LDXRH,
  A64_LDXP,
  A64_STXR,
  A64_STXRB,
  A64_STXRH,
  A64_STXP,

  A64_LDAR,
  A64_LDARB,
  A64_LDARH,
  A64_LDAXR,
  A64_LDAXRB,
  A64_LDAXRH,
  A64_LDAXP,
  A64_STLR,
  A64_STLRB,
  A64_STLRH,
  A64_STLXR,
  A64_STLXRB,
  A64_STLXRH,
  A64_STLXP,

  A64_LDADD,
  A64_LDADDA,
  A64_LDADDAL,
  A64_LDADDL,
  A64_STADD,
  A64_STADDL,
  A64_LDCLR,
  A64_LDEOR,
  A64_LDSET,
  A64_LDSMAX,
  A64_LDSMIN,
  A64_LDUMAX,
  A64_LDUMIN,
  A64_SWP,
  A64_SWPA,
  A64_SWPAL,
  A64_SWPL,
  A64_CAS,
  A64_CASA,
  A64_CASAL,
  A64_CASL,
  A64_CASP,

  A64_NOP,
  A64_YIELD,
  A64_WFE,
  A64_WFI,
  A64_SEV,
  A64_SEVL,
  A64_HINT,
  A64_CLREX,
  A64_DSB,
  A64_DMB,
  A64_ISB,
  A64_SYS,
  A64_SYSL,
  A64_MSR_REG,
  A64_MSR_IMM,
  A64_MRS,
  A64_SVC,
  A64_HVC,
  A64_SMC,
  A64_BRK,
  A64_HLT,
  A64_DCPS1,
  A64_DCPS2,
  A64_DCPS3,

  A64_DC,
  A64_IC,
  A64_AT,
  A64_TLBI,

  A64_FMOV,
  A64_FABS,
  A64_FNEG,
  A64_FSQRT,
  A64_FADD,
  A64_FSUB,
  A64_FMUL,
  A64_FDIV,
  A64_FMAX,
  A64_FMIN,
  A64_FMADD,
  A64_FMSUB,
  A64_FNMADD,
  A64_FNMSUB,

  A64_FCMP,
  A64_FCMPE,
  A64_FCCMP,
  A64_FCCMPE,

  A64_FCSEL,

  A64_FCVT,
  A64_FCVTZS,
  A64_FCVTZU,
  A64_SCVTF,
  A64_UCVTF,
  A64_FRINTN,
  A64_FRINTP,
  A64_FRINTM,
  A64_FRINTZ,

  A64_FMOV_GEN,

  A64_LDR_SIMD,
  A64_STR_SIMD,
  A64_LDP_SIMD,
  A64_STP_SIMD,
  A64_LD1,
  A64_LD2,
  A64_LD3,
  A64_LD4,
  A64_ST1,
  A64_ST2,
  A64_ST3,
  A64_ST4,

  A64_AESE,
  A64_AESD,
  A64_AESMC,
  A64_AESIMC,
  A64_SHA1C,
  A64_SHA1P,
  A64_SHA1M,
  A64_SHA1SU0,
  A64_SHA256H,
  A64_SHA256H2,
  A64_SHA256SU1,
  A64_SHA1H,
  A64_SHA1SU1,
  A64_SHA256SU0,
  A64_SM3SS1,
  A64_SM4E,
  A64_SM4EKEY,

  A64_OPCODE_COUNT
} A64Opcode;

typedef enum {
  A64_COND_EQ = 0,
  A64_COND_NE = 1,
  A64_COND_CS = 2,
  A64_COND_HS = 2,
  A64_COND_CC = 3,
  A64_COND_LO = 3,
  A64_COND_MI = 4,
  A64_COND_PL = 5,
  A64_COND_VS = 6,
  A64_COND_VC = 7,
  A64_COND_HI = 8,
  A64_COND_LS = 9,
  A64_COND_GE = 10,
  A64_COND_LT = 11,
  A64_COND_GT = 12,
  A64_COND_LE = 13,
  A64_COND_AL = 14,
  A64_COND_NV = 15
} A64Condition;

typedef enum {
  A64_SHIFT_LSL = 0,
  A64_SHIFT_LSR = 1,
  A64_SHIFT_ASR = 2,
  A64_SHIFT_ROR = 3
} A64ShiftType;
typedef enum {
  A64_EXT_UXTB = 0,
  A64_EXT_UXTH = 1,
  A64_EXT_UXTW = 2,
  A64_EXT_UXTX = 3,
  A64_EXT_SXTB = 4,
  A64_EXT_SXTH = 5,
  A64_EXT_SXTW = 6,
  A64_EXT_SXTX = 7
} A64ExtendType;

typedef enum {
  A64_OP_NONE = 0,
  A64_OP_REG,
  A64_OP_REG_SP,
  A64_OP_VREG,
  A64_OP_IMM,
  A64_OP_IMM_SHIFT,
  A64_OP_LABEL,
  A64_OP_MEM_BASE,
  A64_OP_MEM_OFFSET,
  A64_OP_MEM_PRE,
  A64_OP_MEM_POST,
  A64_OP_MEM_REG,
  A64_OP_COND,
  A64_OP_SHIFT,
  A64_OP_EXTEND,
  A64_OP_SYSREG,
  A64_OP_PSTATE,
  A64_OP_BARRIER
} A64OpType;

typedef enum {
  A64_ARR_NONE = 0,
  A64_ARR_8B,
  A64_ARR_16B,
  A64_ARR_4H,
  A64_ARR_8H,
  A64_ARR_2S,
  A64_ARR_4S,
  A64_ARR_1D,
  A64_ARR_2D,
  A64_ARR_B,
  A64_ARR_H,
  A64_ARR_S,
  A64_ARR_D
} A64SIMDArrangement;

typedef struct {
  A64OpType type;

  int reg;
  int is_64bit;
  int is_sp;

  A64SIMDArrangement arr;
  int lane;

  int64_t imm;

  A64ShiftType shift_type;
  A64ExtendType extend_type;
  int shift_amount;

  int base_reg;
  int index_reg;

  A64Condition cond;
} A64Operand;

typedef struct {

  A64Opcode opcode;
  uint64_t address;
  uint32_t raw;

  A64Operand operands[5];
  int operand_count;

  int is_branch;
  int is_call;
  int is_return;
  int is_conditional;
  int is_indirect;
  uint64_t branch_target;

  int is_load;
  int is_store;
  int access_size;
  int is_atomic;
  int is_acquire;
  int is_release;

  char mnemonic[24];
  char operands_str[128];
  char full_text[160];
} A64Instruction;

int a64_decode(uint32_t insn, uint64_t addr, A64Instruction *out);

int a64_disasm_buffer(const uint8_t *buf, size_t len, uint64_t base_addr,
                      A64Instruction *out, size_t max_insns);

const char *a64_opcode_name(A64Opcode opcode);

const char *a64_cond_name(A64Condition cond);

const char *a64_shift_name(A64ShiftType shift);

const char *a64_extend_name(A64ExtendType extend);

void a64_format(const A64Instruction *insn, char *buf, size_t buflen);

const char *a64_reg_name(int reg, int is_64bit, int is_sp);

const char *a64_vreg_name(int reg, A64SIMDArrangement arr);
#endif
