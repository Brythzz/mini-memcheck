#ifndef INCLUDED_MINI_MEMCHECK_H
#define INCLUDED_MINI_MEMCHECK_H

#include <stddef.h>
#include <stdlib.h>

typedef struct meta_data {
  // Number of bytes of heap memory the user requested from malloc.
  size_t request_size;
  // Name of the file where the memory request came from.
  const char *filename;
  // Address of the instruction that requested this memory. This will be used
  // later to find the function name and line number.
  const void *instruction;
  // Pointer to the next instance of meta_data in the list.
  struct meta_data *next;
} meta_data;

/*
 * Global head of the linked list of meta_data. This is used in mini-memcheck.c
 * as a global pointer to the head of the list.
 */
extern meta_data *head;

/*
 * The total memory requested (in bytes) by the program, not including the
 * overhead for meta_data.
 *
 * Note: This number only increases throughout the lifetime of the program.
 */
extern size_t total_memory_requested;

/*
 * The total memory freed (in bytes) by the program, not including the overhead
 * for meta_data.
 *
 * Note: This number only increases throughout the lifetime of the program.
 */
extern size_t total_memory_freed;

/*
 * The number of times the user tried to free or realloc an invalid address.
 *
 * Note: An invalid free or realloc happens when a user calls free() or
 * realloc() on an address that is not in the meta_data linked list, EXCEPT for
 * NULL (which is always valid for free).
 */
extern size_t invalid_addresses;

/*
 * Wrap a call to malloc.
 *
 * This malloc creates a meta_data object and inserts it into the head of the
 * list. You have to allocate enough to hold both the user's requested amount of
 * memory and he meta_data structure. You should only call malloc once in this
 * function.
 *
 * On success, this function returns a pointer to the allocated memory block.
 * This should be the start of the user's memory, and not the meta_data.
 */
void *mini_malloc(size_t request_size, const char *filename,
                  const void *instruction);

/*
 * Wrap a call to calloc.
 *
 * This works just like malloc, but zeros out the allocated memory.
 *
 * You may call calloc, malloc, or mini_malloc in this function, but you should
 * only do it once.
 */
void *mini_calloc(size_t num_elements, size_t element_size,
                  const char *filename, const void *instruction);

/*
 * Wrap a call to realloc.
 *
 * If the given pointer is NULL, you should treat this like a call to
 * mini_malloc. If the requested size is 0, you should treat this like a call to
 * mini_free and return NULL. If the pointer is NULL and the size is 0, the
 * behaviour is undefined.
 *
 * In all other cases, you should use realloc to resize an existing allocation,
 * and then update the existing meta_data structure with the new values.
 * Remember to update total_memory_requested and total_memory_freed if needed.
 *
 * If the user tries to realloc an invalid pointer, increment invalid_addresses
 * and return NULL.
 */
void *mini_realloc(void *ptr, size_t request_size, const char *filename,
                   const void *instruction);

/*
 * Wrap a call to free.
 *
 * This free will also remove the meta_data node from the list, assuming it is a
 * valid pointer.
 *
 * Unlike regular free, you should not crash when given an invalid pointer.
 * Instead, increment invalid_addresses.
 *
 * Invalid pointers include pointers that you did not return from mini_malloc,
 * mini_calloc, or mini_realloc, and double frees.
 */
void mini_free(void *ptr);

#endif // INCLUDED_MINI_MEMCHECK_H
