#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arm64dis.h"
#include "exploit.h"
#include "fuzzer.h"
#include "macho.h"

static Fuzzer *g_fuzzer = NULL;

static void signal_handler(int sig) {
  (void)sig;
  if (g_fuzzer) {
    printf("\n[*] Caught signal, stopping...\n");
    fuzzer_stop(g_fuzzer);
  }
}

static void print_usage(const char *prog) {
  printf("FuzzPro v%s - ARM64 macOS Binary Fuzzer\n\n", FUZZPRO_VERSION);
  printf("Usage: %s [options] <target_binary>\n\n", prog);
  printf("Options:\n");
  printf("  -i, --iterations <n>    Number of iterations (0 = infinite)\n");
  printf("  -t, --timeout <ms>      Execution timeout in milliseconds\n");
  printf("  -d, --depth <1-10>      Mutation depth/intensity\n");
  printf("  -c, --corpus <dir>      Input corpus directory\n");
  printf("  -o, --output <dir>      Crash output directory\n");
  printf("  -D, --dict <file>       Dictionary file for mutations\n");
  printf("  -C, --coverage          Enable coverage-guided mode\n");
  printf("  -L, --cmplog            Enable compare logging\n");
  printf("  -v, --verbose           Verbose output\n");
  printf("  -h, --help              Show this help\n");
  printf("\nUtility modes:\n");
  printf("  --parse <binary>        Parse and display Mach-O info\n");
  printf("  --disasm <binary>       Disassemble entry point\n");
  printf("  --exploit <binary>      Static analysis exploit generation\n");
  printf("\nExamples:\n");
  printf("  %s -i 1000 -C ./target\n", prog);
  printf("  %s -c corpus/ -o crashes/ -t 1000 ./target\n", prog);
}

static void cmd_parse_macho(const char *path) {
  MachOInfo *info = macho_parse(path);
  if (!info) {
    fprintf(stderr, "Failed to parse: %s\n", path);
    return;
  }
  macho_print_info(info);
  macho_free(info);
}

static void cmd_disasm_entry(const char *path) {
  MachOInfo *info = macho_parse(path);
  if (!info) {
    fprintf(stderr, "Failed to parse: %s\n", path);
    return;
  }

  printf("[*] Disassembling entry point: 0x%llx\n\n",
         (unsigned long long)info->entry_point);

  int64_t offset = macho_va_to_offset(info, info->entry_point);
  if (offset < 0) {
    fprintf(stderr, "Could not find entry point in file\n");
    macho_free(info);
    return;
  }

  uint8_t code[128];
  if (macho_read_bytes(info, offset, code, sizeof(code)) < 0) {
    fprintf(stderr, "Could not read code\n");
    macho_free(info);
    return;
  }

  A64Instruction insns[32];
  int count =
      a64_disasm_buffer(code, sizeof(code), info->entry_point, insns, 32);

  for (int i = 0; i < count; i++) {
    char line[128];
    a64_format(&insns[i], line, sizeof(line));
    printf("%s\n", line);
    if (insns[i].is_return)
      break;
  }

  macho_free(info);
}

int main(int argc, char *argv[]) {
  FuzzConfig config = {0};
  config.iterations = 0;
  config.timeout_ms = 1000;
  config.mutation_depth = 5;
  config.strategy = FUZZ_STRATEGY_RANDOM;
  config.crash_dir = "crashes";
  config.use_cmplog = 0;

  static struct option long_options[] = {
      {"iterations", required_argument, 0, 'i'},
      {"timeout", required_argument, 0, 't'},
      {"depth", required_argument, 0, 'd'},
      {"corpus", required_argument, 0, 'c'},
      {"output", required_argument, 0, 'o'},
      {"dict", required_argument, 0, 'D'},
      {"coverage", no_argument, 0, 'C'},
      {"cmplog", no_argument, 0, 'L'},
      {"verbose", no_argument, 0, 'v'},
      {"help", no_argument, 0, 'h'},
      {"parse", required_argument, 0, 'P'},
      {"disasm", required_argument, 0, 'A'},
      {"exploit", required_argument, 0, 'E'},
      {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "i:t:d:c:o:D:CLvh", long_options,
                            NULL)) != -1) {
    switch (opt) {
    case 'i':
      config.iterations = atoi(optarg);
      break;
    case 't':
      config.timeout_ms = atoi(optarg);
      break;
    case 'd':
      config.mutation_depth = atoi(optarg);
      if (config.mutation_depth < 1)
        config.mutation_depth = 1;
      if (config.mutation_depth > 10)
        config.mutation_depth = 10;
      break;
    case 'c':
      config.corpus_dir = optarg;
      break;
    case 'o':
      config.crash_dir = optarg;
      break;
    case 'D':
      config.dict_path = optarg;
      break;
    case 'C':
      config.strategy = FUZZ_STRATEGY_COVERAGE;
      break;
    case 'L':
      config.use_cmplog = 1;
      break;
    case 'v':
      break;
    case 'P':
      cmd_parse_macho(optarg);
      return 0;
    case 'A':
      cmd_disasm_entry(optarg);
      return 0;
    case 'E': {
      ExploitGen *eg = exploitgen_create(optarg);
      if (eg) {
        exploitgen_analyze(eg);
        ExploitPlan *plan = exploitgen_plan(eg);
        if (plan) {
          exploitgen_generate_payload(eg, plan);
          exploitgen_test_payload(eg, optarg);
          free(plan);
        }
        exploitgen_destroy(eg);
      }
      return 0;
    }
    case 'h':
    default:
      print_usage(argv[0]);
      return opt == 'h' ? 0 : 1;
    }
  }

  if (optind >= argc) {
    fprintf(stderr, "Error: No target binary specified\n\n");
    print_usage(argv[0]);
    return 1;
  }

  config.target_path = argv[optind];

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  Fuzzer *fuzzer = fuzzer_create(&config);
  if (!fuzzer) {
    fprintf(stderr, "Failed to initialize fuzzer\n");
    return 1;
  }

  g_fuzzer = fuzzer;
  int result = fuzzer_run(fuzzer);
  fuzzer_destroy(fuzzer);

  return result;
}
