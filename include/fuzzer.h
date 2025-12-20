#ifndef FUZZPRO_FUZZER_H
#define FUZZPRO_FUZZER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define FUZZPRO_VERSION "3.0"
#define FUZZPRO_MAP_SIZE (1 << 16)
#define FUZZPRO_MAX_INPUT_SIZE (1 << 20)
#define FUZZPRO_MAX_CORPUS 10000
#define FUZZPRO_MAX_CRASHES 1000
#define FUZZPRO_PERSISTENT_RUNS 1000
#define FUZZPRO_CMPLOG_MAP_SIZE 65536

typedef enum {
  FUZZ_STRATEGY_RANDOM = 0,
  FUZZ_STRATEGY_COVERAGE,
  FUZZ_STRATEGY_DIRECTED
} FuzzStrategy;

typedef enum {
  MUT_BITFLIP = 0,
  MUT_BYTEFLIP,
  MUT_ARITH8,
  MUT_ARITH16,
  MUT_ARITH32,
  MUT_INTEREST8,
  MUT_INTEREST16,
  MUT_INTEREST32,
  MUT_OVERWRITE,
  MUT_INSERT,
  MUT_DELETE,
  MUT_CLONE,
  MUT_SPLICE,
  MUT_HAVOC,
  MUT_DICTIONARY,
  MUT_CMPLOG,
  MUT_COUNT
} MutationType;

typedef struct {
  uint8_t *data;
  size_t size;
  size_t capacity;
  uint64_t hash;
  uint64_t exec_us;
  uint64_t hit_count;
  int has_new_cov;
  int favored;
  int depth;
} CorpusEntry;

typedef struct {
  CorpusEntry *entries;
  size_t count;
  size_t capacity;
  size_t current_idx;
} Corpus;

typedef struct {
  uint64_t pc;
  int signal;
  uint64_t fault_addr;
  uint8_t *input;
  size_t input_size;
  uint64_t hash;
  time_t timestamp;
} CrashInfo;

typedef struct {
  CrashInfo *crashes;
  size_t count;
  size_t capacity;
  uint64_t *hashes;
} CrashDB;

typedef struct {
  uint64_t addr;
  uint64_t arg1;
  uint64_t arg2;
  uint8_t size;
  uint8_t type;
} CmpLogEntry;

typedef struct {
  CmpLogEntry *entries;
  size_t count;
  size_t capacity;
  uint8_t *map;
} CmpLog;

typedef struct {
  uint8_t *bitmap;
  uint8_t *virgin_bits;
  size_t map_size;
  uint64_t total_edges;
  uint64_t new_edges;
  double coverage_pct;
} Coverage;

typedef struct {
  double weights[MUT_COUNT];
  uint64_t successes[MUT_COUNT];
  uint64_t attempts[MUT_COUNT];
  int enabled[MUT_COUNT];
} MutationScheduler;

typedef struct {
  uint8_t **words;
  size_t *lengths;
  size_t count;
  size_t capacity;
} Dictionary;

typedef struct {
  uint64_t total_execs;
  uint64_t total_crashes;
  uint64_t unique_crashes;
  uint64_t total_timeouts;
  uint64_t execs_per_sec;
  uint64_t last_new_cov;
  uint64_t start_time;
  uint64_t corpus_size;
  double coverage_pct;
  uint64_t cur_input_len;
} FuzzStats;

typedef struct FuzzConfig {
  const char *target_path;
  char **target_argv;
  const char *corpus_dir;
  const char *crash_dir;
  const char *dict_path;

  int timeout_ms;
  int mem_limit_mb;
  int iterations;
  int mutation_depth;
  int persistent_mode;
  int use_cmplog;
  int minimize_crashes;

  FuzzStrategy strategy;
} FuzzConfig;

typedef struct Fuzzer {
  FuzzConfig config;

  Corpus *corpus;
  CrashDB *crashes;
  Coverage *coverage;
  CmpLog *cmplog;
  Dictionary *dict;
  MutationScheduler *scheduler;
  FuzzStats stats;

  uint8_t *current_input;
  size_t current_input_size;

  int running;
  int forksrv_pid;
  int ctrl_fd[2];
  int status_fd[2];

  void *target_info;
} Fuzzer;

Fuzzer *fuzzer_create(FuzzConfig *config);
void fuzzer_destroy(Fuzzer *fz);
int fuzzer_run(Fuzzer *fz);
void fuzzer_stop(Fuzzer *fz);

Corpus *corpus_create(size_t initial_capacity);
void corpus_destroy(Corpus *c);
int corpus_add(Corpus *c, const uint8_t *data, size_t size, uint64_t hash,
               int cov);
int corpus_load_dir(Corpus *c, const char *path);
CorpusEntry *corpus_select(Corpus *c);
void corpus_update_scores(Corpus *c);

CrashDB *crashdb_create(size_t capacity);
void crashdb_destroy(CrashDB *db);
int crashdb_add(CrashDB *db, CrashInfo *info);
int crashdb_is_unique(CrashDB *db, uint64_t hash);
int crashdb_save(CrashDB *db, const char *dir);

Coverage *coverage_create(size_t map_size);
void coverage_destroy(Coverage *cov);
void coverage_reset(Coverage *cov);
int coverage_has_new(Coverage *cov, const uint8_t *trace);
void coverage_update(Coverage *cov, const uint8_t *trace);
double coverage_get_pct(Coverage *cov);
void coverage_classify(uint8_t *trace, size_t size);

CmpLog *cmplog_create(size_t capacity);
void cmplog_destroy(CmpLog *cl);
void cmplog_reset(CmpLog *cl);
void cmplog_add(CmpLog *cl, uint64_t addr, uint64_t a1, uint64_t a2, int size);
void cmplog_apply_mutations(CmpLog *cl, uint8_t *input, size_t *size);

MutationScheduler *mutscheduler_create(void);
void mutscheduler_destroy(MutationScheduler *ms);
MutationType mutscheduler_select(MutationScheduler *ms);
void mutscheduler_reward(MutationScheduler *ms, MutationType mt, int success);
void mutscheduler_update_weights(MutationScheduler *ms);

Dictionary *dict_create(void);
void dict_destroy(Dictionary *d);
int dict_load(Dictionary *d, const char *path);
void dict_add(Dictionary *d, const uint8_t *word, size_t len);
const uint8_t *dict_random(Dictionary *d, size_t *len);

void mutate_input(uint8_t *buf, size_t *size, size_t max_size, int depth);
void mutate_havoc(uint8_t *buf, size_t *size, size_t max_size);
void mutate_splice(uint8_t *buf, size_t *size, const uint8_t *other,
                   size_t other_size);
void mutate_dictionary(uint8_t *buf, size_t *size, size_t max_size,
                       Dictionary *d);
void mutate_cmplog(uint8_t *buf, size_t *size, CmpLog *cl);

uint64_t hash_input(const uint8_t *data, size_t size);
uint64_t get_time_ms(void);
void minimize_input(uint8_t *buf, size_t *size,
                    int (*test_fn)(const uint8_t *, size_t));

#endif
