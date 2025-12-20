#include "syscall.h"
#include <stdlib.h>
#include <string.h>

int syscall_stub_read(SymState *state, SyscallInfo *info) {
  if (!state || !info)
    return -1;

  int fd = (int)info->args[0];
  uint64_t buf = info->args[1];
  size_t count = (size_t)info->args[2];

  if (fd == 0) {
    size_t offset = buf - state->mem_base;
    if (offset < SYM_MAX_MEMORY) {
      for (size_t i = 0; i < count && offset + i < SYM_MAX_MEMORY; i++) {
        state->mem_symbolic[offset + i] = sym_var(state, 8);
      }
    }
    info->ret = count;
    return 0;
  }

  info->ret = (uint64_t)-1;
  return -1;
}

int syscall_stub_write(SymState *state, SyscallInfo *info) {
  if (!state || !info)
    return -1;

  size_t count = (size_t)info->args[2];
  info->ret = count;
  return 0;
}

int syscall_stub_mmap(SymState *state, SyscallInfo *info) {
  if (!state || !info)
    return -1;

  static uint64_t mmap_base = 0x100000000ULL;
  size_t len = (size_t)info->args[1];

  info->ret = mmap_base;
  mmap_base += (len + 0xFFF) & ~0xFFFULL;

  return 0;
}

int syscall_stub_exit(SymState *state, SyscallInfo *info) {
  (void)state;
  (void)info;
  return 1;
}

int syscall_dispatch(SymState *state, int number) {
  if (!state)
    return -1;

  SyscallInfo info = {0};
  info.number = number;

  info.args[0] =
      sym_is_concrete(state->regs[0]) ? sym_get_concrete(state->regs[0]) : 0;
  info.args[1] =
      sym_is_concrete(state->regs[1]) ? sym_get_concrete(state->regs[1]) : 0;
  info.args[2] =
      sym_is_concrete(state->regs[2]) ? sym_get_concrete(state->regs[2]) : 0;
  info.args[3] =
      sym_is_concrete(state->regs[3]) ? sym_get_concrete(state->regs[3]) : 0;

  int result = -1;

  switch (number) {
  case SYS_READ:
    result = syscall_stub_read(state, &info);
    break;
  case SYS_WRITE:
    result = syscall_stub_write(state, &info);
    break;
  case SYS_MMAP:
    result = syscall_stub_mmap(state, &info);
    break;
  case SYS_EXIT:
    result = syscall_stub_exit(state, &info);
    break;
  default:
    info.ret = 0;
    result = 0;
    break;
  }

  state->regs[0] = sym_const(info.ret, 64);

  return result;
}
