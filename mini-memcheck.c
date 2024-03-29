#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "mini-memcheck.h"

meta_data *head = NULL;
size_t total_memory_requested = 0;
size_t total_memory_freed = 0;
size_t invalid_addresses = 0;

void *mini_malloc(size_t request_size, const char *filename,
                  const void *instruction) {
  if (request_size <= 0) return NULL;

  meta_data *ptr = malloc(sizeof(meta_data) + request_size);
  if (ptr == NULL) return NULL;

  ptr->request_size = request_size;
  ptr->filename = filename;
  ptr->instruction = instruction;
  ptr->next = head;

  head = ptr;
  total_memory_requested += request_size;

  // the cast is important!
  return (void *)ptr + sizeof(meta_data);
}

void *mini_calloc(size_t num_elements, size_t element_size,
                  const char *filename, const void *instruction) {
  int size = num_elements * element_size;
  // we need to cast the pointer be able to set bytes
  char *ptr = mini_malloc(size, filename, instruction);
  memset(ptr, 0, size);

  return (void*)ptr;
}

meta_data *get_pred(void *ptr) {
  meta_data *node = head;
  meta_data *shifted = ptr - sizeof(meta_data);

  while(node != NULL) {
    if(node->next == shifted)
      return node;

    node = node->next;
  }

  return NULL;
}

void *mini_realloc(void *ptr, size_t request_size, const char *filename,
                   const void *instruction) {
  if (ptr == NULL)
    return mini_malloc(request_size, filename, instruction);

  if (request_size == 0) {
    mini_free(ptr);
    return NULL;
  }

  if (ptr != head && get_pred(ptr) == NULL) {
    invalid_addresses++;
    return NULL;
  }

  meta_data *prev_meta = ptr - sizeof(meta_data);
  meta_data *new_meta = realloc(prev_meta, request_size + sizeof(meta_data));
  if (new_meta != NULL) {
    int diff = request_size - new_meta->request_size;
    new_meta->request_size = request_size;
    new_meta->filename = filename;
    new_meta->instruction = instruction;

    if (diff > 0) total_memory_requested += diff;
    else total_memory_freed += -diff;
  }

  return (void *)new_meta + sizeof(meta_data);
}

// We check whether the adress sizeof(meta_data) bytes before is in the linked list
void mini_free(void *ptr) {
  meta_data *shifted = ptr - sizeof(meta_data);

  if (shifted == head) {
    head = shifted->next;
    total_memory_freed += shifted->request_size;

    free(shifted);
  } else {
    meta_data *pred = get_pred(ptr);
    if (pred == NULL) {
      invalid_addresses++;
      return;
    }

    pred->next = shifted->next;
    total_memory_freed += shifted->request_size;
    free(shifted);
  }
}
