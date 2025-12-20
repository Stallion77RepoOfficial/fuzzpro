
#ifndef FUZZPRO_MACHO_H
#define FUZZPRO_MACHO_H
#include <stdint.h>
#include <stddef.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define MACHO_MAX_FUNCTIONS 100000

typedef struct {
    char name[17];          
    uint64_t vmaddr;        
    uint64_t vmsize;        
    uint64_t fileoff;       
    uint64_t filesize;      
    uint32_t maxprot;       
    uint32_t initprot;      
} MachOSegment;

typedef struct {
    char sectname[17];      
    char segname[17];       
    uint64_t addr;          
    uint64_t size;          
    uint32_t offset;        
    uint32_t flags;         
} MachOSection;

typedef struct {
    
    char *path;
    uint8_t *data;          
    size_t size;            
    
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    
    uint64_t entry_point;
    
    MachOSegment *segments;
    size_t segment_count;
    
    MachOSection *sections;
    size_t section_count;
    
    uint64_t text_vmaddr;
    uint64_t text_vmsize;
    uint64_t text_fileoff;
    
    uint64_t *functions;
    size_t function_count;
    
    uint64_t symtab_offset;
    uint32_t symtab_count;
    uint64_t strtab_offset;
    uint32_t strtab_size;
} MachOInfo;

MachOInfo* macho_parse(const char *path);

void macho_free(MachOInfo *info);

int macho_get_segment(MachOInfo *info, const char *name, 
                      uint64_t *vmaddr, uint64_t *vmsize);

int macho_get_section(MachOInfo *info, const char *segname, const char *sectname,
                      uint64_t *addr, uint64_t *size, uint32_t *offset);

uint8_t* macho_read_section(MachOInfo *info, const char *segname, 
                            const char *sectname, size_t *out_size);

int macho_read_bytes(MachOInfo *info, uint64_t offset, void *buf, size_t len);

int64_t macho_va_to_offset(MachOInfo *info, uint64_t va);

int macho_get_function_starts(MachOInfo *info);

int macho_is_executable_addr(MachOInfo *info, uint64_t addr);

void macho_print_info(MachOInfo *info);
#endif 
