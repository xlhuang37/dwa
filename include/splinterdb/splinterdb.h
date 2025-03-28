// Copyright 2018-2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 * splinterdb.h --
 *
 *     The public API for SplinterDB
 *
 *     A data_config must be provided at the time of create/open.
 *     See default_data_config.h for a basic reference implementation.
 */

#ifndef _SPLINTERDB_H_
#define _SPLINTERDB_H_

#include "splinterdb/data.h"


// Hack to accomodate encoding variable-length keys
// This will go away once real variable-length key support lands in trunk.c
#define SPLINTERDB_MAX_KEY_SIZE (MAX_KEY_SIZE - 1)


// Get a version string for this build of SplinterDB
// Currently a git tag
const char *
splinterdb_get_version();

// Configuration options for SplinterDB
typedef struct {
   // required configuration
   const char *filename;
   uint64      cache_size;
   uint64      disk_size;

   // data_config is a required field that defines how your data should be
   // read and written in SplinterDB.  See data.h for details.
   // For a simple reference implementation, see default_data_config.h
   data_config *data_cfg;


   // optional advanced config below
   // if unset, defaults will be used
   void *heap_handle;
   void *heap_id;

   uint64 page_size;
   uint64 extent_size;

   // io
   int    io_flags;
   uint32 io_perms;
   uint64 io_async_queue_depth;

   // cache
   bool        cache_use_stats;
   const char *cache_logfile;

   // btree
   uint64 btree_rough_count_height;

   // filter
   uint64 filter_remainder_size;
   uint64 filter_index_size;

   // log
   bool use_log;

   // splinter
   uint64 memtable_capacity;
   uint64 fanout;
   uint64 max_branches_per_node;
   uint64 use_stats;
   uint64 reclaim_threshold;
} splinterdb_config;

// Opaque handle to an opened instance of SplinterDB
typedef struct splinterdb splinterdb;

// Create a new SplinterDB instance, erasing any existing file or block device.
//
// The library will allocate and own the memory for splinterdb
// and will free it on splinterdb_close().
//
// It is ok for the caller to stack-allocate cfg, since it is not retained
int
splinterdb_create(const splinterdb_config *cfg, splinterdb **kvs);

// Open an existing splinterdb from a file/device on disk
//
// The library will allocate and own the memory for splinterdb
// and will free it on splinterdb_close().
//
// It is ok for the caller to stack-allocate cfg, since it is not retained
int
splinterdb_open(const splinterdb_config *cfg, splinterdb **kvs);

// Close a splinterdb
//
// This will flush all data to disk and release all resources
void
splinterdb_close(splinterdb *kvs);

// Register the current thread so that it can be used with splinterdb.
// This causes scratch space to be allocated for the thread.
//
// Any thread that uses a splinterdb must first be registered with it.
//
// The only exception is the initial thread which called create or open,
// as that thread is implicitly registered.  Re-registering it will leak memory.
//
// A thread should not be registered more than once; that would leak memory.
//
// splinterdb_close will use scratch space, so the thread that calls it must
// have been registered (or implicitly registered by being the initial thread).
//
// Note: There is currently a limit of MAX_THREADS registered at a given time
void
splinterdb_register_thread(splinterdb *kvs);

// Deregister the current thread and free its scratch space.
//
// Call this function before exiting a registered thread.
// Otherwise, you'll leak memory.
void
splinterdb_deregister_thread(splinterdb *kvs);

// Insert a key and value.
// Relies on data_config->encode_message
int
splinterdb_insert(const splinterdb *kvsb, slice key, slice value);

// Delete a given key and any associated value / messages
int
splinterdb_delete(const splinterdb *kvsb, slice key);

// Insert a key and value.
// Relies on data_config->encode_message
int
splinterdb_update(const splinterdb *kvsb, slice key, slice delta);

// Lookups

// Size of opaque data required to hold a lookup result
#define SPLINTERDB_LOOKUP_BUFSIZE (6 * sizeof(void *))

// A lookup result is stored and parsed from here
//
// Once initialized, a splinterdb_lookup_result may be used for multiple
// lookups. It is not safe to use from multiple threads.
typedef struct {
   char opaque[SPLINTERDB_LOOKUP_BUFSIZE];
} splinterdb_lookup_result;

// Initialize a lookup result object.
//
// If buffer is NULL, then the library will allocate and manage memory.
//
// If the caller provides a buffer, that will be used, unless a lookup
// requires a larger buffer, at which time the library will allocate.
// Regardless, the library will never free a buffer supplied by the application.
void
splinterdb_lookup_result_init(const splinterdb         *kvs,        // IN
                              splinterdb_lookup_result *result,     // IN/OUT
                              uint64                    buffer_len, // IN
                              char                     *buffer      // IN
);

// Release any resources used by result
//
// This will never free a buffer passed to splinterdb_lookup_result_init
void
splinterdb_lookup_result_deinit(splinterdb_lookup_result *result); // IN

// Returns true if the result was found
bool
splinterdb_lookup_found(const splinterdb_lookup_result *result); // IN

// Decode the value from a found result
int
splinterdb_lookup_result_value(const splinterdb               *kvs,
                               const splinterdb_lookup_result *result, // IN
                               slice                          *value   // OUT
);


// Lookup the message for a given key
//
// result must have first been initialized using splinterdb_lookup_result_init
int
splinterdb_lookup(const splinterdb         *kvs,   // IN
                  slice                     key,   // IN
                  splinterdb_lookup_result *result // IN/OUT
);


/*
Iterator API (range query)

This API is modeled after the RocksDB Iterator and is intended to allow drop-in
replacement for most scenarios.

This documentation is heavily inspired by
  https://github.com/facebook/rocksdb/wiki/Iterator

The biggest difference is that RocksDB's Iterator exposes a Seek(key) method,
while SplinterDB expects the starting key to be provided at the time the
iterator is initialized.

Similar to RocksDB, if there is no error, then status()==0.  If status() != 0,
then valid() == false.  In other words, valid()==true implies status()== 0,
which means it is safe to proceed with other operations without checking
status().

On the other hand, if valid() == false, then there are two possibilities:
(1) We reached the end of the data without error. In this case, status() == 0;
(2) there is an error. In this case status() != 0;

Be sure to check status() whenever valid() is false.

Iterators must be cleaned up via deinit.  Live iterators will block
other operations from the same thread, including close.

Known issue: a live iterator may block inserts and deletes from the same thread.


Sample application code:

   splinterdb_iterator* it;
   int rc = splinterdb_iterator_init(kvs, &it, NULL_SLICE);
   if (rc != 0) { ... handle error ... }

   slice key, value;

   for(; splinterdb_iterator_valid(it); splinterdb_iterator_next(it)) {
      splinterdb_iterator_get_current(it, &key, &value);
      // do something with key and value...
   }

   // loop exit may mean error, or just that we've reached the end of the range
   rc = splinterdb_iterator_status(it);
   if (rc != 0) { ... handle error ... }

   // Release resources acquired by the iterator
   // If you skip this, other operations, including close(), may hang.
   splinterdb_iterator_deinit(it);
*/

typedef struct splinterdb_iterator splinterdb_iterator;

// Initialize a new iterator, starting at the given key
//
// If start_key is NULL_SLICE, the iterator will start before the minimum key
int
splinterdb_iterator_init(const splinterdb     *kvs,      // IN
                         splinterdb_iterator **iter,     // OUT
                         slice                 start_key // IN
);

// Deinitialize an iterator
//
// Failing to do this may cause hangs.
void
splinterdb_iterator_deinit(splinterdb_iterator *iter);

// Checks that the iterator status is OK (no errors) and that get_current()
// will succeed. If false, there are two possibilities:
// 1. Iterator has passed the final item.  In this case, status() == 0
// 2. Iterator has encountered an error.  In this case, status() != 0
bool
splinterdb_iterator_valid(splinterdb_iterator *iter);

// Attempts to advance the iterator to the next item.
// Any error will cause valid() == false and be visible with status()
void
splinterdb_iterator_next(splinterdb_iterator *iter);

// Sets *key and *value to the locations of the current item
// Callers must not modify that memory pointed to by the slice
//
// If valid() == false, then behavior is undefined.
// Always check valid() before calling this function.
void
splinterdb_iterator_get_current(splinterdb_iterator *iter, // IN
                                slice               *key,  // OUT
                                slice               *value // OUT
);

// Returns an error encountered from iteration, or 0 if successful.
//
// End-of-range is not an error
int
splinterdb_iterator_status(const splinterdb_iterator *iter);

/*
 * Statistics Printing
 *
 * Must set the use_stats config option.
 *
 * Prints insertion or lookup statistics. Both print cache statistics.
 *
 * Reset statistics clears all statistics, including cache statistics.
 */

void
splinterdb_stats_print_insertion(const splinterdb *kvs);

void
splinterdb_stats_print_lookup(const splinterdb *kvs);

void
splinterdb_stats_reset(splinterdb *kvs);


#endif // _SPLINTERDB_H_
