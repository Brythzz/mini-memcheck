#include <stdio.h>
#include <syslog.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <execinfo.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>

#include "mini-memcheck.h"

/* -------------- Utils -------------- */

#define LIB_PATH "/usr/lib/"
static bool is_lib(const char *filename) { // this is a hack
  size_t n = strlen(LIB_PATH);
  return strncmp(filename, LIB_PATH, n) == 0;
}

static void printmsg(const char *format, ...) {
  fprintf(stderr, "==%d== ", getpid());

  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

static void fetch_caller_info(const char **filename, const void **instruction) {
  static const size_t stacksize = 128;
  static const char *internal = "mini-memcheck";

  void *callstack[stacksize];
  Dl_info info;

  int frames = backtrace(callstack, stacksize);
  for (int frame = 0; frame < frames; ++frame) {
    void *addr = callstack[frame];
    if (!dladdr(addr, &info)) {
      // Couldn't resolve the calling object
      return;
    }
    assert(info.dli_fname != NULL);
    if (strstr(info.dli_fname, internal) == NULL) {
      *filename = info.dli_fname;
      *instruction = addr;
      break;
    }
  }
}

static void resolve_addr2line(char *symbol, char *source, const char *filename,
                              const void *instruction) {
  int fds[2];
  if (pipe(fds) < 0 ||
        fcntl(fds[0], F_DUPFD_CLOEXEC) ||
        fcntl(fds[1], F_DUPFD_CLOEXEC)) {
    return;
  }

  pid_t child = fork();
  if (child < 0)
    return;

  if (!child) {
    // In the child:
    // Call "addr2line -f -s -e <filename> <instruction>" and send the stdout to
    // our parent via the pipe (this is a hack (: )).
    char inst_str[128];
    snprintf(inst_str, sizeof(inst_str), "%p", instruction);

    char fn_buf[1024];
    strncpy(fn_buf, filename, sizeof(fn_buf));
    fn_buf[sizeof(fn_buf) - 1] = '\0';

    char *command = "addr2line";
    char *env[] = {"DYLD_INSERT_LIBRARIES=", NULL};

    dup2(fds[1], STDOUT_FILENO);
    close(STDERR_FILENO);
    execle(command, command, "-f", "-s", "-e", fn_buf, inst_str, NULL, env);
    exit(1);
  } else {
    // In the parent:
    // Wait on our child, then read the output of addr2line from the pipe, then
    // extract the symbol and source info.
    int status;
    close(fds[1]);
    if (waitpid(child, &status, 0) < 0)
      return;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
      return;

    char util_buffer[1024];
    ssize_t len = read(fds[0], util_buffer, sizeof(util_buffer));
    util_buffer[len] = '\0';
    close(fds[0]);

    char *source_info = strchr(util_buffer, '\n');
    if (!source_info)
      return;

    *source_info++ = '\0';
    if (source_info[strlen(source_info) - 1] == '\n')
      source_info[strlen(source_info) - 1] = '\0';
    if (strncmp(source_info, "??:", 3))
      strcpy(source, source_info);

    if (strcmp(util_buffer, "??"))
      strcpy(symbol, util_buffer);
  }
}

static void resolve(char *output, const char *filename, const void *instruction,
                    size_t bufsize) {
  char symbol[1024] = "??";
  char source[1024] = "??:0";

  Dl_info info;
  if (dladdr(instruction, &info) && info.dli_sname != NULL) {
    strncpy(symbol, info.dli_sname, sizeof(symbol));
    symbol[sizeof(symbol) - 1] = '\0';
  }

  snprintf(source, sizeof(source), "%s:%p", filename, instruction);

  resolve_addr2line(symbol, source, filename, instruction);

  snprintf(output, bufsize, "%s (%s)", symbol, source);
}

/* -------------- Library -------------- */

__attribute__((constructor))
static void print_greeting(int argc, const char **argv) {
  printmsg("Mini-Memcheck\n");
  syslog(LOG_ERR, "Dylib injection successful in %s\n", argv[0]);
}

__attribute__((destructor))
static void print_leak_info() {
  meta_data *leak_info, *garbage_collector;
  size_t total_leak = 0;
  char buffer[512] = "";

  setvbuf(stdout, NULL, _IONBF, 0);

  printmsg("\n");
  leak_info = head;
  if (leak_info != NULL) {
    printmsg("LEAK REPORT:\n");
  }
  while (leak_info != NULL) {
    total_leak += leak_info->request_size;
    resolve(buffer, leak_info->filename, leak_info->instruction,
            sizeof(buffer));
    printmsg("   Leak origin: %s\n", buffer);
    printmsg("   Leak size: %zu bytes\n", leak_info->request_size);
    printmsg("   Leak memory address: %p\n", leak_info + 1);
    printmsg("\n");
    garbage_collector = leak_info;
    leak_info = leak_info->next;
    free(garbage_collector);
  }

  printmsg("Program made %zu bad call(s) to free or realloc.\n",
           invalid_addresses);
  printmsg("\n");
  printmsg("HEAP SUMMARY:\n");
  printmsg("   Total memory requested: %zu bytes\n", total_memory_requested);
  printmsg("   Total memory freed: %zu bytes\n", total_memory_freed);
  if (total_leak != 0) {
    printmsg("   Total leak: %zu bytes\n", total_leak);
  } else {
    printmsg("   No leaks, all memory freed. Congratulations!\n");
  }

  assert(total_leak == total_memory_requested - total_memory_freed);
}

/* -------------- Injection -------------- */

#define MEM_FUNC_SETUP                            \
  const char *filename = "<unknown>";             \
  const void *instruction = NULL;                 \
  fetch_caller_info(&filename, &instruction);

typedef struct interpose_s {
  void *new_func;
  void *orig_func;
} interpose_t;

static void *malloc_wrapper(size_t size);
static void *calloc_wrapper(size_t count, size_t size);
static void *realloc_wrapper(void *ptr, size_t size);
static void free_wrapper(void *ptr);

__attribute__((used)) static const interpose_t interposing_functions[] \
__attribute__ ((section("__DATA, __interpose"))) = {
  { (void *)malloc_wrapper, (void *)malloc },
  { (void *)calloc_wrapper, (void *)calloc },
  { (void *)realloc_wrapper, (void *)realloc },
  { (void *)free_wrapper, (void *)free }
};

static void *malloc_wrapper(size_t size) {
  MEM_FUNC_SETUP
  if (is_lib(filename))
    return malloc(size);

  return mini_malloc(size, filename, instruction);
}

static void *calloc_wrapper(size_t count, size_t size) {
  MEM_FUNC_SETUP
  if (is_lib(filename))
    return calloc(count, size);

  return mini_calloc(count, size, filename, instruction);
}

static void *realloc_wrapper(void *ptr, size_t size) {
  MEM_FUNC_SETUP
  if (is_lib(filename))
    return realloc(ptr, size);

  return mini_realloc(ptr, size, filename, instruction);
}

static void free_wrapper(void *ptr) {
  MEM_FUNC_SETUP
  if (is_lib(filename))
    free(ptr);
  else
    mini_free(ptr);
}

