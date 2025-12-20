
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "macho.h"

static uint32_t swap32(uint32_t x) {
  return ((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) |
         ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24);
}

static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end) {
  uint64_t result = 0;
  int shift = 0;
  while (*p < end) {
    uint8_t byte = **p;
    (*p)++;
    result |= ((uint64_t)(byte & 0x7F)) << shift;
    if ((byte & 0x80) == 0)
      break;
    shift += 7;
  }
  return result;
}

static int parse_load_commands(MachOInfo *info, const uint8_t *base) {
  const struct mach_header_64 *header = (const struct mach_header_64 *)base;
  const uint8_t *cmd_ptr = base + sizeof(struct mach_header_64);
  
  info->segments = calloc(header->ncmds, sizeof(MachOSegment));
  info->sections =
      calloc(header->ncmds * 16, sizeof(MachOSection)); 
  if (!info->segments || !info->sections) {
    return -1;
  }
  const uint8_t *func_starts_data = NULL;
  uint32_t func_starts_size = 0;
  uint64_t linkedit_vmaddr = 0;
  uint64_t linkedit_fileoff = 0;
  
  for (uint32_t i = 0; i < header->ncmds; i++) {
    const struct load_command *cmd = (const struct load_command *)cmd_ptr;
    switch (cmd->cmd) {
    case LC_SEGMENT_64: {
      const struct segment_command_64 *seg =
          (const struct segment_command_64 *)cmd_ptr;
      
      MachOSegment *seg_info = &info->segments[info->segment_count];
      strncpy(seg_info->name, seg->segname, 16);
      seg_info->name[16] = '\0';
      seg_info->vmaddr = seg->vmaddr;
      seg_info->vmsize = seg->vmsize;
      seg_info->fileoff = seg->fileoff;
      seg_info->filesize = seg->filesize;
      seg_info->maxprot = seg->maxprot;
      seg_info->initprot = seg->initprot;
      info->segment_count++;
      
      if (strcmp(seg->segname, "__TEXT") == 0) {
        info->text_vmaddr = seg->vmaddr;
        info->text_vmsize = seg->vmsize;
        info->text_fileoff = seg->fileoff;
      }
      
      if (strcmp(seg->segname, "__LINKEDIT") == 0) {
        linkedit_vmaddr = seg->vmaddr;
        linkedit_fileoff = seg->fileoff;
      }
      
      const struct section_64 *sect =
          (const struct section_64 *)(cmd_ptr +
                                      sizeof(struct segment_command_64));
      for (uint32_t j = 0; j < seg->nsects; j++) {
        MachOSection *sect_info = &info->sections[info->section_count];
        strncpy(sect_info->sectname, sect[j].sectname, 16);
        sect_info->sectname[16] = '\0';
        strncpy(sect_info->segname, sect[j].segname, 16);
        sect_info->segname[16] = '\0';
        sect_info->addr = sect[j].addr;
        sect_info->size = sect[j].size;
        sect_info->offset = sect[j].offset;
        sect_info->flags = sect[j].flags;
        info->section_count++;
      }
      break;
    }
    case LC_MAIN: {
      
      const struct entry_point_command *entry =
          (const struct entry_point_command *)cmd_ptr;
      info->entry_point = info->text_vmaddr + entry->entryoff;
      break;
    }
    case LC_UNIXTHREAD: {
      
      
      const uint32_t *thread_cmd = (const uint32_t *)cmd_ptr;
      
      
      const uint64_t *regs = (const uint64_t *)(cmd_ptr + 16);
      info->entry_point = regs[32]; 
      break;
    }
    case LC_FUNCTION_STARTS: {
      const struct linkedit_data_command *func_cmd =
          (const struct linkedit_data_command *)cmd_ptr;
      func_starts_size = func_cmd->datasize;
      
      func_starts_data = base + func_cmd->dataoff;
      break;
    }
    case LC_SYMTAB: {
      const struct symtab_command *symtab =
          (const struct symtab_command *)cmd_ptr;
      info->symtab_offset = symtab->symoff;
      info->symtab_count = symtab->nsyms;
      info->strtab_offset = symtab->stroff;
      info->strtab_size = symtab->strsize;
      break;
    }
    }
    cmd_ptr += cmd->cmdsize;
  }
  
  if (func_starts_data && func_starts_size > 0) {
    info->functions = calloc(MACHO_MAX_FUNCTIONS, sizeof(uint64_t));
    if (info->functions) {
      const uint8_t *p = func_starts_data;
      const uint8_t *end = p + func_starts_size;
      uint64_t addr = info->text_vmaddr;
      while (p < end && info->function_count < MACHO_MAX_FUNCTIONS) {
        uint64_t delta = read_uleb128(&p, end);
        if (delta == 0)
          break;
        addr += delta;
        info->functions[info->function_count++] = addr;
      }
    }
  }
  return 0;
}

static const uint8_t *get_arm64_slice(const uint8_t *data, size_t size,
                                      size_t *slice_size) {
  const struct fat_header *fat = (const struct fat_header *)data;
  if (fat->magic != FAT_MAGIC && fat->magic != FAT_CIGAM) {
    
    *slice_size = size;
    return data;
  }
  uint32_t nfat_arch = swap32(fat->nfat_arch);
  const struct fat_arch *archs =
      (const struct fat_arch *)(data + sizeof(struct fat_header));
  for (uint32_t i = 0; i < nfat_arch; i++) {
    uint32_t cputype = swap32(archs[i].cputype);
    if (cputype == CPU_TYPE_ARM64) {
      uint32_t offset = swap32(archs[i].offset);
      uint32_t arch_size = swap32(archs[i].size);
      *slice_size = arch_size;
      return data + offset;
    }
  }
  
  return NULL;
}
MachOInfo *macho_parse(const char *path) {
  MachOInfo *info = calloc(1, sizeof(MachOInfo));
  if (!info)
    return NULL;
  
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    free(info);
    return NULL;
  }
  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    free(info);
    return NULL;
  }
  info->size = st.st_size;
  info->data = mmap(NULL, info->size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (info->data == MAP_FAILED) {
    free(info);
    return NULL;
  }
  
  info->path = strdup(path);
  
  size_t slice_size;
  const uint8_t *macho_data =
      get_arm64_slice(info->data, info->size, &slice_size);
  if (!macho_data) {
    fprintf(stderr, "[!] No ARM64 slice found in binary\n");
    munmap(info->data, info->size);
    free(info->path);
    free(info);
    return NULL;
  }
  
  const struct mach_header_64 *header =
      (const struct mach_header_64 *)macho_data;
  if (header->magic != MH_MAGIC_64) {
    fprintf(stderr, "[!] Not a 64-bit Mach-O binary\n");
    munmap(info->data, info->size);
    free(info->path);
    free(info);
    return NULL;
  }
  if (header->cputype != CPU_TYPE_ARM64) {
    fprintf(stderr, "[!] Not an ARM64 binary\n");
    munmap(info->data, info->size);
    free(info->path);
    free(info);
    return NULL;
  }
  
  info->magic = header->magic;
  info->cputype = header->cputype;
  info->cpusubtype = header->cpusubtype;
  info->filetype = header->filetype;
  info->ncmds = header->ncmds;
  info->sizeofcmds = header->sizeofcmds;
  info->flags = header->flags;
  
  if (parse_load_commands(info, macho_data) < 0) {
    macho_free(info);
    return NULL;
  }
  return info;
}
void macho_free(MachOInfo *info) {
  if (!info)
    return;
  if (info->data && info->data != MAP_FAILED) {
    munmap(info->data, info->size);
  }
  free(info->path);
  free(info->segments);
  free(info->sections);
  free(info->functions);
  free(info);
}
int macho_get_segment(MachOInfo *info, const char *name, uint64_t *vmaddr,
                      uint64_t *vmsize) {
  if (!info || !name)
    return -1;
  for (size_t i = 0; i < info->segment_count; i++) {
    if (strcmp(info->segments[i].name, name) == 0) {
      if (vmaddr)
        *vmaddr = info->segments[i].vmaddr;
      if (vmsize)
        *vmsize = info->segments[i].vmsize;
      return 0;
    }
  }
  return -1;
}
int macho_get_section(MachOInfo *info, const char *segname,
                      const char *sectname, uint64_t *addr, uint64_t *size,
                      uint32_t *offset) {
  if (!info || !segname || !sectname)
    return -1;
  for (size_t i = 0; i < info->section_count; i++) {
    if (strcmp(info->sections[i].segname, segname) == 0 &&
        strcmp(info->sections[i].sectname, sectname) == 0) {
      if (addr)
        *addr = info->sections[i].addr;
      if (size)
        *size = info->sections[i].size;
      if (offset)
        *offset = info->sections[i].offset;
      return 0;
    }
  }
  return -1;
}
uint8_t *macho_read_section(MachOInfo *info, const char *segname,
                            const char *sectname, size_t *out_size) {
  uint64_t addr, size;
  uint32_t offset;
  if (macho_get_section(info, segname, sectname, &addr, &size, &offset) < 0) {
    return NULL;
  }
  uint8_t *buf = malloc(size);
  if (!buf)
    return NULL;
  memcpy(buf, info->data + offset, size);
  if (out_size)
    *out_size = size;
  return buf;
}
int macho_read_bytes(MachOInfo *info, uint64_t offset, void *buf, size_t len) {
  if (!info || !buf)
    return -1;
  if (offset + len > info->size)
    return -1;
  memcpy(buf, info->data + offset, len);
  return 0;
}
int64_t macho_va_to_offset(MachOInfo *info, uint64_t va) {
  if (!info)
    return -1;
  for (size_t i = 0; i < info->segment_count; i++) {
    MachOSegment *seg = &info->segments[i];
    if (va >= seg->vmaddr && va < seg->vmaddr + seg->vmsize) {
      return seg->fileoff + (va - seg->vmaddr);
    }
  }
  return -1;
}
int macho_get_function_starts(MachOInfo *info) {
  
  return (info && info->functions) ? 0 : -1;
}
int macho_is_executable_addr(MachOInfo *info, uint64_t addr) {
  if (!info)
    return 0;
  for (size_t i = 0; i < info->segment_count; i++) {
    MachOSegment *seg = &info->segments[i];
    if (addr >= seg->vmaddr && addr < seg->vmaddr + seg->vmsize) {
      return (seg->initprot & VM_PROT_EXECUTE) != 0;
    }
  }
  return 0;
}
void macho_print_info(MachOInfo *info) {
  if (!info)
    return;
  printf("[*] Mach-O Binary: %s\n", info->path);
  printf("[*] CPU Type: ARM64 (0x%x)\n", info->cputype);
  printf("[*] File Type: 0x%x\n", info->filetype);
  printf("[*] Entry Point: 0x%llx\n", (unsigned long long)info->entry_point);
  printf("[*] Load Commands: %u\n", info->ncmds);
  printf("\n[*] Segments:\n");
  for (size_t i = 0; i < info->segment_count; i++) {
    MachOSegment *seg = &info->segments[i];
    printf("    %-16s vmaddr=0x%012llx vmsize=0x%08llx prot=%c%c%c\n",
           seg->name, (unsigned long long)seg->vmaddr,
           (unsigned long long)seg->vmsize,
           (seg->initprot & VM_PROT_READ) ? 'r' : '-',
           (seg->initprot & VM_PROT_WRITE) ? 'w' : '-',
           (seg->initprot & VM_PROT_EXECUTE) ? 'x' : '-');
  }
  printf("\n[*] Function Starts: %zu functions found\n", info->function_count);
  
  if (info->function_count > 0) {
    printf("    First functions:\n");
    for (size_t i = 0; i < info->function_count && i < 10; i++) {
      printf("      [%zu] 0x%llx\n", i, (unsigned long long)info->functions[i]);
    }
    if (info->function_count > 10) {
      printf("      ... and %zu more\n", info->function_count - 10);
    }
  }
}
