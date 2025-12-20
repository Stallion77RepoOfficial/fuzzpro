#include "autodict.h"
#include "arm64dis.h"
#include <fcntl.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define BITS(v, hi, lo) (((v) >> (lo)) & ((1U << ((hi) - (lo) + 1)) - 1))

AutoDict *autodict_create(void) {
  AutoDict *ad = calloc(1, sizeof(AutoDict));
  return ad;
}

void autodict_destroy(AutoDict *ad) { free(ad); }

int autodict_add_token(AutoDict *ad, const uint8_t *data, size_t len) {
  if (!ad || !data || len == 0 || len > AUTODICT_MAX_TOKEN_LEN)
    return -1;
  if (ad->count >= AUTODICT_MAX_TOKENS)
    return -1;

  for (size_t i = 0; i < ad->count; i++) {
    if (ad->tokens[i].len == len &&
        memcmp(ad->tokens[i].data, data, len) == 0) {
      ad->tokens[i].score++;
      return 0;
    }
  }

  DictToken *t = &ad->tokens[ad->count++];
  memcpy(t->data, data, len);
  t->len = len;
  t->score = 1;
  return 0;
}

static int extract_mach_o_text(const uint8_t *data, size_t file_size,
                               const uint8_t **text_out, size_t *text_size,
                               uint64_t *text_addr) {
  if (file_size < sizeof(struct mach_header_64))
    return -1;

  struct mach_header_64 *hdr = (struct mach_header_64 *)data;
  if (hdr->magic != MH_MAGIC_64)
    return -1;

  const uint8_t *cmd_ptr = data + sizeof(struct mach_header_64);

  for (uint32_t i = 0; i < hdr->ncmds; i++) {
    struct load_command *lc = (struct load_command *)cmd_ptr;

    if (lc->cmd == LC_SEGMENT_64) {
      struct segment_command_64 *seg = (struct segment_command_64 *)cmd_ptr;

      if (strcmp(seg->segname, "__TEXT") == 0) {
        struct section_64 *sec =
            (struct section_64 *)(cmd_ptr + sizeof(struct segment_command_64));

        for (uint32_t j = 0; j < seg->nsects; j++) {
          if (strcmp(sec[j].sectname, "__text") == 0) {
            *text_out = data + sec[j].offset;
            *text_size = sec[j].size;
            *text_addr = sec[j].addr;
            return 0;
          }
        }
      }
    }
    cmd_ptr += lc->cmdsize;
  }
  return -1;
}

static int extract_mach_o_cstrings(AutoDict *ad, const uint8_t *data,
                                   size_t file_size) {
  struct mach_header_64 *hdr = (struct mach_header_64 *)data;
  if (hdr->magic != MH_MAGIC_64)
    return -1;

  const uint8_t *cmd_ptr = data + sizeof(struct mach_header_64);

  for (uint32_t i = 0; i < hdr->ncmds; i++) {
    struct load_command *lc = (struct load_command *)cmd_ptr;

    if (lc->cmd == LC_SEGMENT_64) {
      struct segment_command_64 *seg = (struct segment_command_64 *)cmd_ptr;
      struct section_64 *sec =
          (struct section_64 *)(cmd_ptr + sizeof(struct segment_command_64));

      for (uint32_t j = 0; j < seg->nsects; j++) {
        if (strcmp(sec[j].sectname, "__cstring") == 0 ||
            strcmp(sec[j].sectname, "__const") == 0) {

          const uint8_t *str_data = data + sec[j].offset;
          size_t str_size = sec[j].size;

          autodict_extract_strings(ad, str_data, str_size);
        }
      }
    }
    cmd_ptr += lc->cmdsize;
  }
  return 0;
}

int autodict_extract_cmp_operands(AutoDict *ad, const uint8_t *code, size_t len,
                                  uint64_t base) {
  if (!ad || !code)
    return -1;

  int found = 0;

  for (size_t off = 0; off + 4 <= len; off += 4) {
    uint32_t insn = *(uint32_t *)(code + off);

    if ((insn & 0x7F800000) == 0x71000000) {
      uint32_t imm12 = BITS(insn, 21, 10);
      uint32_t shift = BITS(insn, 23, 22) ? 12 : 0;
      uint32_t value = imm12 << shift;

      if (value >= 0x20 && value <= 0x7E) {
      } else {
        uint8_t buf[4];
        memcpy(buf, &value, 4);
        autodict_add_token(ad, buf, 4);
        found++;
      }
    }

    if ((insn & 0x9F000000) == 0x10000000) {
      int64_t immlo = BITS(insn, 30, 29);
      int64_t immhi = BITS(insn, 23, 5);
      int64_t imm = (immhi << 2) | immlo;
      if (imm & 0x100000)
        imm |= 0xFFFFFFFFFFE00000ULL;

      uint64_t target = base + off + imm;

      if (target >= base && target < base + len) {
        const uint8_t *ptr = code + (target - base);
        size_t max_len = len - (target - base);
        if (max_len > 8)
          max_len = 8;

        for (size_t l = 4; l <= max_len; l += 4) {
          autodict_add_token(ad, ptr, l);
          found++;
        }
      }
    }

    if ((insn & 0x9F000000) == 0x90000000) {
      int64_t immlo = BITS(insn, 30, 29);
      int64_t immhi = BITS(insn, 23, 5);
      if (immhi & 0x40000)
        immhi |= 0xFFFFFFFFFFF80000ULL;

      uint64_t target = (base & ~0xFFFULL) + ((immhi << 14) | (immlo << 12));

      uint8_t buf[8];
      memcpy(buf, &target, 8);
      autodict_add_token(ad, buf, 8);
      autodict_add_token(ad, buf, 4);
      found++;
    }

    if ((insn & 0x7F800000) == 0x52800000) {
      uint32_t imm16 = BITS(insn, 20, 5);
      uint32_t hw = BITS(insn, 22, 21);
      uint64_t value = (uint64_t)imm16 << (hw * 16);

      if (value > 0xFF) {
        uint8_t buf[8];
        memcpy(buf, &value, 8);
        size_t blen = (value > 0xFFFFFFFF) ? 8 : (value > 0xFFFF) ? 4 : 2;
        autodict_add_token(ad, buf, blen);
        found++;
      }
    }
  }

  return found;
}

int autodict_extract_strings(AutoDict *ad, const uint8_t *data, size_t len) {
  if (!ad || !data)
    return -1;

  int found = 0;
  size_t str_start = 0;
  int in_string = 0;

  for (size_t i = 0; i < len; i++) {
    int printable = (data[i] >= 0x20 && data[i] <= 0x7E) || data[i] == '\t' ||
                    data[i] == '\n' || data[i] == '\r';

    if (printable && !in_string) {
      str_start = i;
      in_string = 1;
    } else if (!printable && in_string) {
      size_t str_len = i - str_start;
      if (str_len >= 4 && str_len <= AUTODICT_MAX_TOKEN_LEN) {
        autodict_add_token(ad, data + str_start, str_len);
        found++;
      }
      in_string = 0;
    }
  }

  return found;
}

int autodict_extract_from_binary(AutoDict *ad, const char *binary_path) {
  if (!ad || !binary_path)
    return -1;

  int fd = open(binary_path, O_RDONLY);
  if (fd < 0)
    return -1;

  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    return -1;
  }

  uint8_t *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (data == MAP_FAILED)
    return -1;

  const uint8_t *text;
  size_t text_size;
  uint64_t text_addr;

  int total = 0;

  if (extract_mach_o_text(data, st.st_size, &text, &text_size, &text_addr) ==
      0) {
    ad->text_base = text_addr;
    ad->text_size = text_size;

    total += autodict_extract_cmp_operands(ad, text, text_size, text_addr);
  }

  total += extract_mach_o_cstrings(ad, data, st.st_size);

  munmap(data, st.st_size);
  return total;
}

const DictToken *autodict_get_token(AutoDict *ad, size_t index) {
  if (!ad || index >= ad->count)
    return NULL;
  return &ad->tokens[index];
}

int autodict_apply_to_input(AutoDict *ad, uint8_t *input, size_t *len,
                            size_t max_len) {
  if (!ad || !input || !len || ad->count == 0)
    return -1;

  size_t idx = rand() % ad->count;
  const DictToken *t = &ad->tokens[idx];

  if (*len + t->len > max_len)
    return -1;

  size_t pos = rand() % (*len + 1);

  if (pos + t->len <= *len) {
    memcpy(input + pos, t->data, t->len);
  } else {
    memmove(input + pos + t->len, input + pos, *len - pos);
    memcpy(input + pos, t->data, t->len);
    *len += t->len;
  }

  return 0;
}
