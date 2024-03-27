#include <stdlib.h>

int main(void) {
  int *ptr = malloc(50);
  free (ptr);

  return 0;
}
