#ifndef FUZZPRO_SYSCALL_H
#define FUZZPRO_SYSCALL_H

#include "symbolic.h"
#include <stdint.h>

#define SYS_READ 3
#define SYS_WRITE 4
#define SYS_OPEN 5
#define SYS_CLOSE 6
#define SYS_MMAP 197
#define SYS_MUNMAP 73
#define SYS_EXIT 1

typedef struct {
  int number;
  uint64_t args[6];
  uint64_t ret;
} SyscallInfo;

int syscall_stub_read(SymState *state, SyscallInfo *info);
int syscall_stub_write(SymState *state, SyscallInfo *info);
int syscall_stub_mmap(SymState *state, SyscallInfo *info);
int syscall_stub_exit(SymState *state, SyscallInfo *info);
int syscall_dispatch(SymState *state, int number);

#endif
