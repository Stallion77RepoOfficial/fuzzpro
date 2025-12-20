#include "fuzzer.h"
#include "autodict.h"
#include "constraint.h"
#include "forkserver.h"
#include "lafintel.h"
#include "macho.h"
#include "solver.h"
#include "ssa.h"
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static const int8_t interesting_8[] = {-128, -1, 0, 1, 16, 32, 64, 100, 127};
static const int16_t interesting_16[] = {-32768, -129, 128,  255,  256,
                                         512,    1000, 1024, 4096, 32767};
static const int32_t interesting_32[] = {-2147483648, -100663046, -32769,
                                         32768,       65535,      65536,
                                         100663045,   2147483647};

static const uint8_t count_class[256] = {
    0,   1,   2,   4,   8,   8,   8,   8,   16,  16,  16,  16,  16,  16,  16,
    16,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128};

uint64_t get_time_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

uint64_t hash_input(const uint8_t *data, size_t size) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < size; i++) {
    h ^= data[i];
    h *= 0x100000001b3ULL;
  }
  return h;
}

Corpus *corpus_create(size_t capacity) {
  Corpus *c = calloc(1, sizeof(Corpus));
  if (!c)
    return NULL;
  c->entries = calloc(capacity, sizeof(CorpusEntry));
  if (!c->entries) {
    free(c);
    return NULL;
  }
  c->capacity = capacity;
  return c;
}

void corpus_destroy(Corpus *c) {
  if (!c)
    return;
  for (size_t i = 0; i < c->count; i++) {
    free(c->entries[i].data);
  }
  free(c->entries);
  free(c);
}

int corpus_add(Corpus *c, const uint8_t *data, size_t size, uint64_t hash,
               int cov) {
  if (!c || c->count >= c->capacity)
    return -1;
  CorpusEntry *e = &c->entries[c->count];
  e->data = malloc(size);
  if (!e->data)
    return -1;
  memcpy(e->data, data, size);
  e->size = size;
  e->capacity = size;
  e->hash = hash ? hash : hash_input(data, size);
  e->has_new_cov = cov;
  e->depth = 0;
  c->count++;
  return 0;
}

int corpus_load_dir(Corpus *c, const char *path) {
  DIR *d = opendir(path);
  if (!d)
    return -1;
  struct dirent *ent;
  int count = 0;
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;
    char fpath[1024];
    snprintf(fpath, sizeof(fpath), "%s/%s", path, ent->d_name);
    struct stat st;
    if (stat(fpath, &st) < 0 || !S_ISREG(st.st_mode))
      continue;
    if (st.st_size > FUZZPRO_MAX_INPUT_SIZE)
      continue;
    int fd = open(fpath, O_RDONLY);
    if (fd < 0)
      continue;
    uint8_t *buf = malloc(st.st_size);
    if (buf && read(fd, buf, st.st_size) == st.st_size) {
      corpus_add(c, buf, st.st_size, 0, 0);
      count++;
    }
    free(buf);
    close(fd);
  }
  closedir(d);
  return count;
}

CorpusEntry *corpus_select(Corpus *c) {
  if (!c || c->count == 0)
    return NULL;
  size_t total_score = 0;
  for (size_t i = 0; i < c->count; i++) {
    total_score += c->entries[i].favored ? 10 : 1;
  }
  size_t r = rand() % total_score;
  size_t acc = 0;
  for (size_t i = 0; i < c->count; i++) {
    acc += c->entries[i].favored ? 10 : 1;
    if (acc > r)
      return &c->entries[i];
  }
  return &c->entries[c->count - 1];
}

void corpus_update_scores(Corpus *c) {
  if (!c)
    return;
  for (size_t i = 0; i < c->count; i++) {
    c->entries[i].favored =
        (c->entries[i].has_new_cov || c->entries[i].size < 100);
  }
}

CrashDB *crashdb_create(size_t capacity) {
  CrashDB *db = calloc(1, sizeof(CrashDB));
  if (!db)
    return NULL;
  db->crashes = calloc(capacity, sizeof(CrashInfo));
  db->hashes = calloc(capacity, sizeof(uint64_t));
  if (!db->crashes || !db->hashes) {
    free(db->crashes);
    free(db->hashes);
    free(db);
    return NULL;
  }
  db->capacity = capacity;
  return db;
}

void crashdb_destroy(CrashDB *db) {
  if (!db)
    return;
  for (size_t i = 0; i < db->count; i++) {
    free(db->crashes[i].input);
  }
  free(db->crashes);
  free(db->hashes);
  free(db);
}

int crashdb_is_unique(CrashDB *db, uint64_t hash) {
  if (!db)
    return 1;
  for (size_t i = 0; i < db->count; i++) {
    if (db->hashes[i] == hash)
      return 0;
  }
  return 1;
}

int crashdb_add(CrashDB *db, CrashInfo *info) {
  if (!db || db->count >= db->capacity)
    return -1;
  if (!crashdb_is_unique(db, info->hash))
    return 0;
  CrashInfo *c = &db->crashes[db->count];
  memcpy(c, info, sizeof(CrashInfo));
  c->input = malloc(info->input_size);
  if (c->input)
    memcpy(c->input, info->input, info->input_size);
  c->timestamp = time(NULL);
  db->hashes[db->count] = info->hash;
  db->count++;
  return 1;
}

int crashdb_save(CrashDB *db, const char *dir) {
  if (!db || !dir)
    return -1;
  mkdir(dir, 0755);
  for (size_t i = 0; i < db->count; i++) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/crash_%zu_sig%d", dir, i,
             db->crashes[i].signal);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      write(fd, db->crashes[i].input, db->crashes[i].input_size);
      close(fd);
    }
  }
  return (int)db->count;
}

Coverage *coverage_create(size_t map_size) {
  Coverage *cov = calloc(1, sizeof(Coverage));
  if (!cov)
    return NULL;
  cov->bitmap = calloc(1, map_size);
  cov->virgin_bits = malloc(map_size);
  if (!cov->bitmap || !cov->virgin_bits) {
    free(cov->bitmap);
    free(cov->virgin_bits);
    free(cov);
    return NULL;
  }
  memset(cov->virgin_bits, 0xFF, map_size);
  cov->map_size = map_size;
  return cov;
}

void coverage_destroy(Coverage *cov) {
  if (!cov)
    return;
  free(cov->bitmap);
  free(cov->virgin_bits);
  free(cov);
}

void coverage_reset(Coverage *cov) {
  if (cov && cov->bitmap)
    memset(cov->bitmap, 0, cov->map_size);
}

void coverage_classify(uint8_t *trace, size_t size) {
  for (size_t i = 0; i < size; i++) {
    trace[i] = count_class[trace[i]];
  }
}

int coverage_has_new(Coverage *cov, const uint8_t *trace) {
  if (!cov || !trace)
    return 0;
  int ret = 0;
  for (size_t i = 0; i < cov->map_size; i++) {
    if (trace[i] && (trace[i] & cov->virgin_bits[i])) {
      ret = (cov->virgin_bits[i] == 0xFF) ? 2 : 1;
      if (ret == 2)
        break;
    }
  }
  return ret;
}

void coverage_update(Coverage *cov, const uint8_t *trace) {
  if (!cov || !trace)
    return;
  for (size_t i = 0; i < cov->map_size; i++) {
    if (trace[i]) {
      cov->virgin_bits[i] &= ~trace[i];
      if (cov->bitmap[i] == 0)
        cov->new_edges++;
      cov->bitmap[i] |= trace[i];
    }
  }
  cov->total_edges = 0;
  for (size_t i = 0; i < cov->map_size; i++) {
    if (cov->bitmap[i])
      cov->total_edges++;
  }
  cov->coverage_pct = (100.0 * cov->total_edges) / cov->map_size;
}

double coverage_get_pct(Coverage *cov) { return cov ? cov->coverage_pct : 0.0; }

CmpLog *cmplog_create(size_t capacity) {
  CmpLog *cl = calloc(1, sizeof(CmpLog));
  if (!cl)
    return NULL;
  cl->entries = calloc(capacity, sizeof(CmpLogEntry));
  cl->map = calloc(1, FUZZPRO_CMPLOG_MAP_SIZE);
  if (!cl->entries || !cl->map) {
    free(cl->entries);
    free(cl->map);
    free(cl);
    return NULL;
  }
  cl->capacity = capacity;
  return cl;
}

void cmplog_destroy(CmpLog *cl) {
  if (!cl)
    return;
  free(cl->entries);
  free(cl->map);
  free(cl);
}

void cmplog_reset(CmpLog *cl) {
  if (!cl)
    return;
  cl->count = 0;
  memset(cl->map, 0, FUZZPRO_CMPLOG_MAP_SIZE);
}

void cmplog_add(CmpLog *cl, uint64_t addr, uint64_t a1, uint64_t a2, int size) {
  if (!cl || cl->count >= cl->capacity)
    return;
  CmpLogEntry *e = &cl->entries[cl->count++];
  e->addr = addr;
  e->arg1 = a1;
  e->arg2 = a2;
  e->size = size;
}

void cmplog_apply_mutations(CmpLog *cl, uint8_t *input, size_t *size) {
  if (!cl || !input || cl->count == 0)
    return;
  for (size_t i = 0; i < cl->count && i < 16; i++) {
    CmpLogEntry *e = &cl->entries[i];
    if (e->size <= 0 || e->size > 8)
      continue;
    for (size_t pos = 0; pos + e->size <= *size; pos++) {
      uint64_t val = 0;
      memcpy(&val, input + pos, e->size);
      if (val == e->arg1) {
        memcpy(input + pos, &e->arg2, e->size);
        return;
      }
    }
  }
}

MutationScheduler *mutscheduler_create(void) {
  MutationScheduler *ms = calloc(1, sizeof(MutationScheduler));
  if (!ms)
    return NULL;
  for (int i = 0; i < MUT_COUNT; i++) {
    ms->weights[i] = 1.0;
    ms->enabled[i] = 1;
  }
  ms->weights[MUT_HAVOC] = 5.0;
  ms->weights[MUT_BITFLIP] = 3.0;
  ms->weights[MUT_ARITH8] = 2.0;
  return ms;
}

void mutscheduler_destroy(MutationScheduler *ms) { free(ms); }

MutationType mutscheduler_select(MutationScheduler *ms) {
  if (!ms)
    return MUT_HAVOC;
  double total = 0;
  for (int i = 0; i < MUT_COUNT; i++) {
    if (ms->enabled[i])
      total += ms->weights[i];
  }
  double r = (rand() / (double)RAND_MAX) * total;
  double acc = 0;
  for (int i = 0; i < MUT_COUNT; i++) {
    if (!ms->enabled[i])
      continue;
    acc += ms->weights[i];
    if (acc >= r)
      return (MutationType)i;
  }
  return MUT_HAVOC;
}

void mutscheduler_reward(MutationScheduler *ms, MutationType mt, int success) {
  if (!ms || mt >= MUT_COUNT)
    return;
  ms->attempts[mt]++;
  if (success)
    ms->successes[mt]++;
}

void mutscheduler_update_weights(MutationScheduler *ms) {
  if (!ms)
    return;
  for (int i = 0; i < MUT_COUNT; i++) {
    if (ms->attempts[i] > 100) {
      double rate = (double)ms->successes[i] / ms->attempts[i];
      ms->weights[i] = 0.5 + rate * 10.0;
      if (ms->weights[i] < 0.1)
        ms->weights[i] = 0.1;
      if (ms->weights[i] > 20.0)
        ms->weights[i] = 20.0;
    }
  }
}

Dictionary *dict_create(void) {
  Dictionary *d = calloc(1, sizeof(Dictionary));
  if (!d)
    return NULL;
  d->capacity = 1024;
  d->words = calloc(d->capacity, sizeof(uint8_t *));
  d->lengths = calloc(d->capacity, sizeof(size_t));
  return d;
}

void dict_destroy(Dictionary *d) {
  if (!d)
    return;
  for (size_t i = 0; i < d->count; i++)
    free(d->words[i]);
  free(d->words);
  free(d->lengths);
  free(d);
}

void dict_add(Dictionary *d, const uint8_t *word, size_t len) {
  if (!d || d->count >= d->capacity || len == 0)
    return;
  d->words[d->count] = malloc(len);
  if (!d->words[d->count])
    return;
  memcpy(d->words[d->count], word, len);
  d->lengths[d->count] = len;
  d->count++;
}

int dict_load(Dictionary *d, const char *path) {
  if (!d || !path)
    return -1;
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;
  char line[1024];
  int count = 0;
  while (fgets(line, sizeof(line), f)) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      len--;
    if (len > 0) {
      dict_add(d, (uint8_t *)line, len);
      count++;
    }
  }
  fclose(f);
  return count;
}

const uint8_t *dict_random(Dictionary *d, size_t *len) {
  if (!d || d->count == 0)
    return NULL;
  size_t idx = rand() % d->count;
  *len = d->lengths[idx];
  return d->words[idx];
}

static void mutate_flip_bit(uint8_t *buf, size_t size) {
  if (size == 0)
    return;
  size_t pos = rand() % size;
  int bit = rand() % 8;
  buf[pos] ^= (1 << bit);
}

static void mutate_flip_byte(uint8_t *buf, size_t size) {
  if (size == 0)
    return;
  buf[rand() % size] ^= 0xFF;
}

static void mutate_arith(uint8_t *buf, size_t size, int width) {
  if (size < (size_t)width)
    return;
  size_t pos = rand() % (size - width + 1);
  int delta = (rand() % 70) - 35;
  if (width == 1) {
    buf[pos] += delta;
  } else if (width == 2) {
    uint16_t *p = (uint16_t *)(buf + pos);
    *p += delta;
  } else if (width == 4) {
    uint32_t *p = (uint32_t *)(buf + pos);
    *p += delta;
  }
}

static void mutate_interesting(uint8_t *buf, size_t size, int width) {
  if (size < (size_t)width)
    return;
  size_t pos = rand() % (size - width + 1);
  if (width == 1) {
    buf[pos] = interesting_8[rand() % (sizeof(interesting_8) /
                                       sizeof(interesting_8[0]))];
  } else if (width == 2) {
    int16_t *p = (int16_t *)(buf + pos);
    *p = interesting_16[rand() %
                        (sizeof(interesting_16) / sizeof(interesting_16[0]))];
  } else if (width == 4) {
    int32_t *p = (int32_t *)(buf + pos);
    *p = interesting_32[rand() %
                        (sizeof(interesting_32) / sizeof(interesting_32[0]))];
  }
}

static void mutate_overwrite(uint8_t *buf, size_t size) {
  if (size < 2)
    return;
  size_t len = 1 + rand() % (size / 2);
  size_t src = rand() % (size - len);
  size_t dst = rand() % (size - len);
  memmove(buf + dst, buf + src, len);
}

static void mutate_insert(uint8_t *buf, size_t *size, size_t max_size) {
  if (*size >= max_size)
    return;
  size_t len = 1 + rand() % 16;
  if (*size + len > max_size)
    len = max_size - *size;
  size_t pos = rand() % (*size + 1);
  memmove(buf + pos + len, buf + pos, *size - pos);
  for (size_t i = 0; i < len; i++)
    buf[pos + i] = rand() % 256;
  *size += len;
}

static void mutate_delete(uint8_t *buf, size_t *size) {
  if (*size < 2)
    return;
  size_t len = 1 + rand() % (*size / 2);
  if (len >= *size)
    len = *size - 1;
  size_t pos = rand() % (*size - len);
  memmove(buf + pos, buf + pos + len, *size - pos - len);
  *size -= len;
}

static void mutate_clone(uint8_t *buf, size_t *size, size_t max_size) {
  if (*size < 2 || *size >= max_size)
    return;
  size_t len = 1 + rand() % (*size / 2);
  if (*size + len > max_size)
    len = max_size - *size;
  size_t src = rand() % (*size - len);
  size_t dst = rand() % *size;
  memmove(buf + dst + len, buf + dst, *size - dst);
  memmove(buf + dst, buf + src, len);
  *size += len;
}

void mutate_splice(uint8_t *buf, size_t *size, const uint8_t *other,
                   size_t other_size) {
  if (!other || other_size == 0 || *size == 0)
    return;
  size_t pos1 = rand() % *size;
  size_t pos2 = rand() % other_size;
  size_t new_size = pos1 + (other_size - pos2);
  if (new_size > FUZZPRO_MAX_INPUT_SIZE)
    new_size = FUZZPRO_MAX_INPUT_SIZE;
  memcpy(buf + pos1, other + pos2, new_size - pos1);
  *size = new_size;
}

void mutate_dictionary(uint8_t *buf, size_t *size, size_t max_size,
                       Dictionary *d) {
  if (!d || d->count == 0)
    return;
  size_t wlen;
  const uint8_t *word = dict_random(d, &wlen);
  if (!word)
    return;
  if (rand() % 2 && *size >= wlen) {
    size_t pos = rand() % (*size - wlen + 1);
    memcpy(buf + pos, word, wlen);
  } else if (*size + wlen <= max_size) {
    size_t pos = rand() % (*size + 1);
    memmove(buf + pos + wlen, buf + pos, *size - pos);
    memcpy(buf + pos, word, wlen);
    *size += wlen;
  }
}

void mutate_cmplog(uint8_t *buf, size_t *size, CmpLog *cl) {
  cmplog_apply_mutations(cl, buf, size);
}

void mutate_havoc(uint8_t *buf, size_t *size, size_t max_size) {
  int ops = 1 + rand() % 16;
  for (int i = 0; i < ops; i++) {
    int op = rand() % 10;
    switch (op) {
    case 0:
      mutate_flip_bit(buf, *size);
      break;
    case 1:
      mutate_flip_byte(buf, *size);
      break;
    case 2:
      mutate_arith(buf, *size, 1);
      break;
    case 3:
      mutate_arith(buf, *size, 2);
      break;
    case 4:
      mutate_arith(buf, *size, 4);
      break;
    case 5:
      mutate_interesting(buf, *size, 1);
      break;
    case 6:
      mutate_interesting(buf, *size, 2);
      break;
    case 7:
      mutate_overwrite(buf, *size);
      break;
    case 8:
      mutate_insert(buf, size, max_size);
      break;
    case 9:
      mutate_delete(buf, size);
      break;
    }
  }
}

void mutate_input(uint8_t *buf, size_t *size, size_t max_size, int depth) {
  for (int d = 0; d < depth; d++) {
    mutate_havoc(buf, size, max_size);
  }
}

Fuzzer *fuzzer_create(FuzzConfig *config) {
  if (!config || !config->target_path)
    return NULL;

  Fuzzer *fz = calloc(1, sizeof(Fuzzer));
  if (!fz)
    return NULL;

  memcpy(&fz->config, config, sizeof(FuzzConfig));

  fz->corpus = corpus_create(FUZZPRO_MAX_CORPUS);
  fz->crashes = crashdb_create(FUZZPRO_MAX_CRASHES);
  fz->coverage = coverage_create(FUZZPRO_MAP_SIZE);
  fz->cmplog = cmplog_create(4096);
  fz->dict = dict_create();
  fz->scheduler = mutscheduler_create();

  if (!fz->corpus || !fz->crashes || !fz->coverage) {
    fuzzer_destroy(fz);
    return NULL;
  }

  fz->current_input = malloc(FUZZPRO_MAX_INPUT_SIZE);
  if (!fz->current_input) {
    fuzzer_destroy(fz);
    return NULL;
  }

  if (config->corpus_dir) {
    corpus_load_dir(fz->corpus, config->corpus_dir);
  }

  if (fz->corpus->count == 0) {
    uint8_t seed[] = "FUZZPRO";
    corpus_add(fz->corpus, seed, sizeof(seed) - 1, 0, 0);
  }

  if (config->dict_path) {
    dict_load(fz->dict, config->dict_path);
  }

  AutoDict *autodict = autodict_create();
  if (autodict) {
    int tokens = autodict_extract_from_binary(autodict, config->target_path);
    if (tokens > 0) {
      for (size_t i = 0; i < autodict->count && i < 256; i++) {
        const DictToken *t = autodict_get_token(autodict, i);
        if (t && t->len > 0) {
          dict_add(fz->dict, t->data, t->len);
        }
      }
    }
    autodict_destroy(autodict);
  }

  fz->target_info = macho_parse(config->target_path);
  fz->stats.start_time = get_time_ms();

  return fz;
}

void fuzzer_destroy(Fuzzer *fz) {
  if (!fz)
    return;
  corpus_destroy(fz->corpus);
  crashdb_destroy(fz->crashes);
  coverage_destroy(fz->coverage);
  cmplog_destroy(fz->cmplog);
  dict_destroy(fz->dict);
  mutscheduler_destroy(fz->scheduler);
  free(fz->current_input);
  if (fz->target_info)
    macho_free(fz->target_info);
  free(fz);
}

void fuzzer_stop(Fuzzer *fz) {
  if (fz)
    fz->running = 0;
}

static void fuzzer_print_stats(Fuzzer *fz) {
  uint64_t elapsed = get_time_ms() - fz->stats.start_time;
  if (elapsed > 0) {
    fz->stats.execs_per_sec = (fz->stats.total_execs * 1000) / elapsed;
  }
  printf("\r[*] execs: %llu | crashes: %llu | cov: %.2f%% | corpus: %zu | "
         "speed: %llu/s",
         fz->stats.total_execs, fz->stats.unique_crashes,
         fz->stats.coverage_pct, fz->corpus->count, fz->stats.execs_per_sec);
  fflush(stdout);
}

static int fuzzer_execute(Fuzzer *fz, const uint8_t *input, size_t size,
                          int *crashed) {
  char input_file[] = "/tmp/fuzzpro_XXXXXX";
  int fd = mkstemp(input_file);
  if (fd < 0)
    return -1;
  write(fd, input, size);
  close(fd);

  pid_t pid = fork();
  if (pid < 0) {
    unlink(input_file);
    return -1;
  }

  if (pid == 0) {
    int null_fd = open("/dev/null", O_RDWR);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    close(null_fd);

    int in_fd = open(input_file, O_RDONLY);
    dup2(in_fd, STDIN_FILENO);
    close(in_fd);

    alarm(fz->config.timeout_ms / 1000 + 1);
    execl(fz->config.target_path, fz->config.target_path, NULL);
    _exit(1);
  }

  int status;
  waitpid(pid, &status, 0);
  unlink(input_file);

  *crashed = 0;
  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS || sig == SIGFPE ||
        sig == SIGILL) {
      *crashed = sig;
    }
  }

  return 0;
}

int fuzzer_run(Fuzzer *fz) {
  if (!fz)
    return -1;

  fz->running = 1;
  fz->stats.start_time = get_time_ms();

  printf("\n");
  printf("  ███████╗██╗   ██╗███████╗███████╗██████╗ ██████╗  ██████╗ \n");
  printf("  ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔══██╗██╔══██╗██╔═══██╗\n");
  printf("  █████╗  ██║   ██║  ███╔╝   ███╔╝ ██████╔╝██████╔╝██║   ██║\n");
  printf("  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔═══╝ ██╔══██╗██║   ██║\n");
  printf("  ██║     ╚██████╔╝███████╗███████╗██║     ██║  ██║╚██████╔╝\n");
  printf("  ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ \n");
  printf("                                                    v%s\n",
         FUZZPRO_VERSION);
  printf("\n");
  printf("[*] Target: %s\n", fz->config.target_path);
  printf("[*] Corpus: %zu inputs\n", fz->corpus->count);
  printf("[*] Strategy: %s\n",
         fz->config.strategy == FUZZ_STRATEGY_COVERAGE ? "Coverage" : "Random");
  printf("[*] Starting fuzzing...\n\n");

  uint64_t last_print = 0;
  int iterations = fz->config.iterations;

  while (fz->running &&
         (iterations == 0 || fz->stats.total_execs < (uint64_t)iterations)) {
    CorpusEntry *entry = corpus_select(fz->corpus);
    if (!entry)
      break;

    memcpy(fz->current_input, entry->data, entry->size);
    fz->current_input_size = entry->size;

    MutationType mt = mutscheduler_select(fz->scheduler);

    switch (mt) {
    case MUT_BITFLIP:
      mutate_flip_bit(fz->current_input, fz->current_input_size);
      break;
    case MUT_BYTEFLIP:
      mutate_flip_byte(fz->current_input, fz->current_input_size);
      break;
    case MUT_ARITH8:
      mutate_arith(fz->current_input, fz->current_input_size, 1);
      break;
    case MUT_ARITH16:
      mutate_arith(fz->current_input, fz->current_input_size, 2);
      break;
    case MUT_ARITH32:
      mutate_arith(fz->current_input, fz->current_input_size, 4);
      break;
    case MUT_INTEREST8:
      mutate_interesting(fz->current_input, fz->current_input_size, 1);
      break;
    case MUT_INTEREST16:
      mutate_interesting(fz->current_input, fz->current_input_size, 2);
      break;
    case MUT_INTEREST32:
      mutate_interesting(fz->current_input, fz->current_input_size, 4);
      break;
    case MUT_INSERT:
      mutate_insert(fz->current_input, &fz->current_input_size,
                    FUZZPRO_MAX_INPUT_SIZE);
      break;
    case MUT_DELETE:
      mutate_delete(fz->current_input, &fz->current_input_size);
      break;
    case MUT_CLONE:
      mutate_clone(fz->current_input, &fz->current_input_size,
                   FUZZPRO_MAX_INPUT_SIZE);
      break;
    case MUT_SPLICE:
      if (fz->corpus->count > 1) {
        CorpusEntry *other = corpus_select(fz->corpus);
        if (other && other != entry) {
          mutate_splice(fz->current_input, &fz->current_input_size, other->data,
                        other->size);
        }
      }
      break;
    case MUT_DICTIONARY:
      mutate_dictionary(fz->current_input, &fz->current_input_size,
                        FUZZPRO_MAX_INPUT_SIZE, fz->dict);
      break;
    case MUT_CMPLOG:
      mutate_cmplog(fz->current_input, &fz->current_input_size, fz->cmplog);
      break;
    case MUT_HAVOC:
    default: {
      if (rand() % 10 == 0 && fz->dict->count > 0) {
        LafState *laf = laf_create();
        if (laf) {
          for (size_t i = 0; i < fz->dict->count && i < 16; i++) {
            size_t wlen = fz->dict->lengths[i];
            if (wlen >= 4) {
              uint32_t target = 0;
              memcpy(&target, fz->dict->words[i], wlen < 4 ? wlen : 4);
              uint32_t current = 0;
              if (fz->current_input_size >= 4) {
                memcpy(&current, fz->current_input, 4);
              }
              laf_analyze_compare(laf, current, target, 4);
            }
          }
          laf_apply_split_mutation(laf, fz->current_input,
                                   &fz->current_input_size,
                                   FUZZPRO_MAX_INPUT_SIZE);
          laf_destroy(laf);
        }
      }
      mutate_havoc(fz->current_input, &fz->current_input_size,
                   FUZZPRO_MAX_INPUT_SIZE);
      break;
    }
    }

    int crashed = 0;
    fuzzer_execute(fz, fz->current_input, fz->current_input_size, &crashed);
    fz->stats.total_execs++;

    int new_cov = 0;
    uint64_t hash = hash_input(fz->current_input, fz->current_input_size);

    if (crashed) {
      fz->stats.total_crashes++;
      CrashInfo info = {.pc = 0,
                        .signal = crashed,
                        .input = fz->current_input,
                        .input_size = fz->current_input_size,
                        .hash = hash};
      if (crashdb_add(fz->crashes, &info)) {
        fz->stats.unique_crashes++;
        printf("\n[!] NEW CRASH: signal=%d hash=0x%llx\n", crashed,
               (unsigned long long)hash);
        mutscheduler_reward(fz->scheduler, mt, 1);
        new_cov = 1;
      }
    }

    if (new_cov || (fz->stats.total_execs % 100 == 0 && rand() % 10 == 0)) {
      corpus_add(fz->corpus, fz->current_input, fz->current_input_size, hash,
                 new_cov);
      mutscheduler_reward(fz->scheduler, mt, 1);
    }

    if (fz->stats.total_execs % 1000 == 0) {
      corpus_update_scores(fz->corpus);
      mutscheduler_update_weights(fz->scheduler);
    }

    uint64_t now = get_time_ms();
    if (now - last_print >= 100) {
      fuzzer_print_stats(fz);
      last_print = now;
    }
  }

  printf("\n\n[*] Fuzzing complete.\n");
  printf("[*] Total executions: %llu\n", fz->stats.total_execs);
  printf("[*] Unique crashes: %llu\n", fz->stats.unique_crashes);
  printf("[*] Corpus size: %zu\n", fz->corpus->count);

  if (fz->config.crash_dir && fz->crashes->count > 0) {
    crashdb_save(fz->crashes, fz->config.crash_dir);
    printf("[*] Crashes saved to: %s\n", fz->config.crash_dir);
  }

  return 0;
}
