#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syslimits.h>

extern char** environ;

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s program [<args> ...]\n", argv[0]);
    return 1;
  }

  const char *library = "/mini-memcheck.dylib";
  char current[PATH_MAX + 1] = "./mini-memcheck";

  char preload[PATH_MAX + 1] = "DYLD_INSERT_LIBRARIES=";
  strncat(preload, dirname(current), PATH_MAX - strlen(preload));
  strncat(preload, library, PATH_MAX - strlen(preload));

  char *env[] = {preload, NULL};
  char **en = (char **)env;
  environ = en;
  execv(argv[1], argv + 1);

  perror(argv[1]);
  return 2;
}
