#ifndef __SIG__
#define __SIG__

#include "allocator.h"

extern uint64 hash_compute_count;
extern uint64 hash_compute_branch_count;
extern uint64 hash_compute_log_count;
extern uint64 hash_compute_filter_count;
extern uint64 hash_compute_cow_btree_pack_count;
extern uint64 total_ns_compute_hash;

void init_hash_counters();
void print_hash_counters();
int trunk_hmac(char *data, int data_len, char *sig, int sig_len, enum page_type type);
void print_sig(char *data, int data_len, char *info);
#endif
