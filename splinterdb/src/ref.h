#ifndef __REF__H
#define __REF__H

#define HASH_SIZE 16
typedef struct page_reference {
  uint64 addr;
  char hash[HASH_SIZE];
} page_reference;

#endif
