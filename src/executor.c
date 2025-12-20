
#include <errno.h>
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "executor.h"
extern char **environ;

#define ARM64_BRK_0 0xD4200000

static const char *signal_names[] = {
    [0] = "NONE",    [1] = "SIGHUP",   [2] = "SIGINT",   [3] = "SIGQUIT",
    [4] = "SIGILL",  [5] = "SIGTRAP",  [6] = "SIGABRT",  [7] = "SIGEMT",
    [8] = "SIGFPE",  [9] = "SIGKILL",  [10] = "SIGBUS",  [11] = "SIGSEGV",
    [12] = "SIGSYS", [13] = "SIGPIPE", [14] = "SIGALRM", [15] = "SIGTERM"};
const char *executor_signal_name(int sig) {
  if (sig >= 0 && sig <= 15) {
    return signal_names[sig];
  }
  return "UNKNOWN";
}
mach_port_t executor_get_task_port(pid_t pid) {
  mach_port_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  if (kr != KERN_SUCCESS) {
    
    return MACH_PORT_NULL;
  }
  return task;
}
TargetProcess *executor_spawn(const char *binary, const uint8_t *input,
                              size_t input_len) {
  TargetProcess *proc = calloc(1, sizeof(TargetProcess));
  if (!proc)
    return NULL;
  
  int stdin_pipe[2];
  if (pipe(stdin_pipe) < 0) {
    free(proc);
    return NULL;
  }
  
  pid_t pid = fork();
  if (pid < 0) {
    
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);
    free(proc);
    return NULL;
  }
  if (pid == 0) {
    
    close(stdin_pipe[1]); 
    dup2(stdin_pipe[0], STDIN_FILENO);
    close(stdin_pipe[0]);
    
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
    
    execl(binary, binary, NULL);
    
    _exit(127);
  }
  
  close(stdin_pipe[0]); 
  
  if (input && input_len > 0) {
    ssize_t written = write(stdin_pipe[1], input, input_len);
    (void)written; 
  }
  close(stdin_pipe[1]);
  proc->pid = pid;
  proc->is_running = 1;
  
  proc->task = executor_get_task_port(pid);
  if (proc->task != MACH_PORT_NULL) {
    proc->is_attached = 1;
    
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    if (task_threads(proc->task, &threads, &thread_count) == KERN_SUCCESS) {
      if (thread_count > 0) {
        proc->main_thread = threads[0];
      }
      
      for (mach_msg_type_number_t i = 1; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
      }
      vm_deallocate(mach_task_self(), (vm_address_t)threads,
                    thread_count * sizeof(thread_t));
    }
  }
  return proc;
}
ExecResult executor_wait(TargetProcess *proc, int timeout_ms) {
  if (!proc || !proc->is_running) {
    return EXEC_ERROR;
  }
  int status;
  pid_t result;
  if (timeout_ms <= 0) {
    
    result = waitpid(proc->pid, &status, 0);
  } else {
    
    int elapsed = 0;
    const int poll_interval = 1; 
    while (elapsed < timeout_ms) {
      result = waitpid(proc->pid, &status, WNOHANG);
      if (result != 0)
        break;
      usleep(poll_interval * 1000);
      elapsed += poll_interval;
    }
    if (result == 0) {
      
      kill(proc->pid, SIGKILL);
      waitpid(proc->pid, &status, 0);
      proc->is_running = 0;
      proc->last_result = EXEC_TIMEOUT;
      return EXEC_TIMEOUT;
    }
  }
  if (result < 0) {
    proc->last_result = EXEC_ERROR;
    return EXEC_ERROR;
  }
  proc->is_running = 0;
  if (WIFSIGNALED(status)) {
    
    int sig = WTERMSIG(status);
    proc->crashed = 1;
    proc->crash.signal = sig;
    
    if (proc->is_attached && proc->main_thread != MACH_PORT_NULL) {
      executor_get_regs(proc, &proc->crash.regs);
      proc->crash.pc = proc->crash.regs.pc;
    }
    snprintf(proc->crash.description, sizeof(proc->crash.description),
             "%s (signal %d)", executor_signal_name(sig), sig);
    proc->last_result = EXEC_CRASH;
    return EXEC_CRASH;
  }
  proc->last_result = EXEC_SUCCESS;
  return EXEC_SUCCESS;
}
int executor_continue(TargetProcess *proc) {
  if (!proc || !proc->is_attached || proc->main_thread == MACH_PORT_NULL) {
    return -1;
  }
  kern_return_t kr = thread_resume(proc->main_thread);
  return (kr == KERN_SUCCESS) ? 0 : -1;
}
void executor_cleanup(TargetProcess *proc) {
  if (!proc)
    return;
  
  if (proc->is_running && proc->pid > 0) {
    kill(proc->pid, SIGKILL);
    waitpid(proc->pid, NULL, 0);
  }
  
  if (proc->exception_port != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), proc->exception_port);
  }
  if (proc->main_thread != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), proc->main_thread);
  }
  if (proc->task != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), proc->task);
  }
  free(proc);
}
int executor_read_memory(TargetProcess *proc, uint64_t addr, void *buf,
                         size_t len) {
  if (!proc || !proc->is_attached || proc->task == MACH_PORT_NULL) {
    return -1;
  }
  mach_vm_size_t out_size;
  kern_return_t kr = mach_vm_read_overwrite(proc->task, (mach_vm_address_t)addr,
                                            (mach_vm_size_t)len,
                                            (mach_vm_address_t)buf, &out_size);
  return (kr == KERN_SUCCESS && out_size == len) ? 0 : -1;
}
int executor_write_memory(TargetProcess *proc, uint64_t addr, const void *buf,
                          size_t len) {
  if (!proc || !proc->is_attached || proc->task == MACH_PORT_NULL) {
    return -1;
  }
  kern_return_t kr =
      mach_vm_write(proc->task, (mach_vm_address_t)addr, (vm_offset_t)buf,
                    (mach_msg_type_number_t)len);
  return (kr == KERN_SUCCESS) ? 0 : -1;
}
uint32_t executor_read_insn(TargetProcess *proc, uint64_t addr) {
  uint32_t insn = 0;
  if (executor_read_memory(proc, addr, &insn, sizeof(insn)) < 0) {
    return 0;
  }
  return insn;
}
int executor_write_insn(TargetProcess *proc, uint64_t addr, uint32_t insn) {
  return executor_write_memory(proc, addr, &insn, sizeof(insn));
}
int executor_get_regs(TargetProcess *proc, Arm64Regs *regs) {
  if (!proc || !regs || proc->main_thread == MACH_PORT_NULL) {
    return -1;
  }
  arm_thread_state64_t state;
  mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
  kern_return_t kr = thread_get_state(proc->main_thread, ARM_THREAD_STATE64,
                                      (thread_state_t)&state, &count);
  if (kr != KERN_SUCCESS) {
    return -1;
  }
  
  for (int i = 0; i < 29; i++) {
    regs->x[i] = state.__x[i];
  }
  regs->fp = state.__fp;
  regs->lr = state.__lr;
  regs->sp = state.__sp;
  regs->pc = state.__pc;
  regs->cpsr = state.__cpsr;
  return 0;
}
int executor_set_regs(TargetProcess *proc, const Arm64Regs *regs) {
  if (!proc || !regs || proc->main_thread == MACH_PORT_NULL) {
    return -1;
  }
  arm_thread_state64_t state;
  
  for (int i = 0; i < 29; i++) {
    state.__x[i] = regs->x[i];
  }
  state.__fp = regs->fp;
  state.__lr = regs->lr;
  state.__sp = regs->sp;
  state.__pc = regs->pc;
  state.__cpsr = regs->cpsr;
  kern_return_t kr =
      thread_set_state(proc->main_thread, ARM_THREAD_STATE64,
                       (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
  return (kr == KERN_SUCCESS) ? 0 : -1;
}
uint64_t executor_get_pc(TargetProcess *proc) {
  Arm64Regs regs;
  if (executor_get_regs(proc, &regs) < 0) {
    return 0;
  }
  return regs.pc;
}
int executor_set_pc(TargetProcess *proc, uint64_t pc) {
  Arm64Regs regs;
  if (executor_get_regs(proc, &regs) < 0) {
    return -1;
  }
  regs.pc = pc;
  return executor_set_regs(proc, &regs);
}
uint32_t executor_set_breakpoint(TargetProcess *proc, uint64_t addr) {
  
  uint32_t original = executor_read_insn(proc, addr);
  if (original == 0) {
    return 0;
  }
  
  if (executor_write_insn(proc, addr, ARM64_BRK_0) < 0) {
    return 0;
  }
  return original;
}
int executor_remove_breakpoint(TargetProcess *proc, uint64_t addr,
                               uint32_t original) {
  return executor_write_insn(proc, addr, original);
}
int executor_setup_exception_port(TargetProcess *proc) {
  if (!proc || proc->task == MACH_PORT_NULL) {
    return -1;
  }
  kern_return_t kr;
  
  kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                          &proc->exception_port);
  if (kr != KERN_SUCCESS) {
    return -1;
  }
  
  kr = mach_port_insert_right(mach_task_self(), proc->exception_port,
                              proc->exception_port, MACH_MSG_TYPE_MAKE_SEND);
  if (kr != KERN_SUCCESS) {
    mach_port_deallocate(mach_task_self(), proc->exception_port);
    proc->exception_port = MACH_PORT_NULL;
    return -1;
  }
  
  kr = task_set_exception_ports(
      proc->task,
      EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC |
          EXC_MASK_BREAKPOINT | EXC_MASK_CRASH,
      proc->exception_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
      ARM_THREAD_STATE64);
  if (kr != KERN_SUCCESS) {
    mach_port_deallocate(mach_task_self(), proc->exception_port);
    proc->exception_port = MACH_PORT_NULL;
    return -1;
  }
  return 0;
}
int executor_check_exception(TargetProcess *proc) {
  if (!proc || proc->exception_port == MACH_PORT_NULL) {
    return 0;
  }
  
  struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    char data[1024];
  } msg;
  kern_return_t kr =
      mach_msg(&msg.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg),
               proc->exception_port, 0, 
               MACH_PORT_NULL);
  if (kr == MACH_MSG_SUCCESS) {
    
    return 1;
  }
  return 0;
}
void executor_print_crash(const CrashData *crash) {
  if (!crash)
    return;
  printf("[!] CRASH DETECTED\n");
  printf("    Signal: %s (%d)\n", executor_signal_name(crash->signal),
         crash->signal);
  printf("    PC: 0x%llx\n", (unsigned long long)crash->pc);
  printf("    Fault Address: 0x%llx\n", (unsigned long long)crash->fault_addr);
  printf("    Description: %s\n", crash->description);
  printf("    Registers:\n");
  for (int i = 0; i < 29; i += 4) {
    printf("      x%-2d: 0x%016llx  x%-2d: 0x%016llx  "
           "x%-2d: 0x%016llx  x%-2d: 0x%016llx\n",
           i, (unsigned long long)crash->regs.x[i], i + 1,
           (unsigned long long)crash->regs.x[i + 1], i + 2,
           (unsigned long long)crash->regs.x[i + 2], i + 3,
           (unsigned long long)crash->regs.x[i + 3]);
  }
  printf("      fp:  0x%016llx  lr:  0x%016llx\n",
         (unsigned long long)crash->regs.fp,
         (unsigned long long)crash->regs.lr);
  printf("      sp:  0x%016llx  pc:  0x%016llx\n",
         (unsigned long long)crash->regs.sp,
         (unsigned long long)crash->regs.pc);
}
