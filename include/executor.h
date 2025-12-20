
#ifndef FUZZPRO_EXECUTOR_H
#define FUZZPRO_EXECUTOR_H
#include <mach/mach.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
  EXEC_SUCCESS = 0, 
  EXEC_CRASH,       
  EXEC_TIMEOUT,     
  EXEC_ERROR        
} ExecResult;

typedef struct {
  uint64_t x[29]; 
  uint64_t fp;    
  uint64_t lr;    
  uint64_t sp;    
  uint64_t pc;    
  uint32_t cpsr;  
} Arm64Regs;

typedef struct {
  int signal;            
  uint64_t fault_addr;   
  uint64_t pc;           
  Arm64Regs regs;        
  char description[256]; 
} CrashData;

typedef struct {
  
  pid_t pid;
  mach_port_t task;
  mach_port_t exception_port;
  thread_t main_thread;
  
  int is_running;
  int is_attached;
  ExecResult last_result;
  
  int crashed;
  CrashData crash;
  
  uint64_t base_addr; 
} TargetProcess;


TargetProcess *executor_spawn(const char *binary, const uint8_t *input,
                              size_t input_len);

ExecResult executor_wait(TargetProcess *proc, int timeout_ms);

int executor_continue(TargetProcess *proc);

void executor_cleanup(TargetProcess *proc);


int executor_read_memory(TargetProcess *proc, uint64_t addr, void *buf,
                         size_t len);

int executor_write_memory(TargetProcess *proc, uint64_t addr, const void *buf,
                          size_t len);

uint32_t executor_read_insn(TargetProcess *proc, uint64_t addr);

int executor_write_insn(TargetProcess *proc, uint64_t addr, uint32_t insn);


int executor_get_regs(TargetProcess *proc, Arm64Regs *regs);

int executor_set_regs(TargetProcess *proc, const Arm64Regs *regs);

uint64_t executor_get_pc(TargetProcess *proc);

int executor_set_pc(TargetProcess *proc, uint64_t pc);


uint32_t executor_set_breakpoint(TargetProcess *proc, uint64_t addr);

int executor_remove_breakpoint(TargetProcess *proc, uint64_t addr,
                               uint32_t original);


int executor_setup_exception_port(TargetProcess *proc);

int executor_check_exception(TargetProcess *proc);


const char *executor_signal_name(int sig);

void executor_print_crash(const CrashData *crash);

mach_port_t executor_get_task_port(pid_t pid);
#endif 
