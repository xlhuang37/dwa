// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 * -----------------------------------------------------------------------------
 * btree_stress_test.c - Basic BTree multi-threaded stress test
 *
 * Exercises the BTree APIs, with larger data volumes, and multiple threads.
 * -----------------------------------------------------------------------------
 */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include "splinterdb/public_platform.h"
#include "unit_tests.h"
#include "ctest.h" // This is required for all test-case files.

#include "functional/test.h"
#include "splinterdb/data.h"
#include "../config.h"
#include "io.h"
#include "rc_allocator.h"
#include "clockcache.h"
#include "btree_private.h"
#include "btree_test_common.h"

typedef struct insert_thread_params {
   cache           *cc;
   btree_config    *cfg;
   platform_heap_id heap_id;
   btree_scratch   *scratch;
   mini_allocator  *mini;
   page_reference   root_ref;
   int              start;
   int              end;
   platform_heap_id hid;
} insert_thread_params;

// Function Prototypes
static void
insert_thread(void *arg);

static void
insert_tests(cache           *cc,
             btree_config    *cfg,
             platform_heap_id heap_id,
             btree_scratch   *scratch,
             mini_allocator  *mini,
             page_reference  *root_ref,
             int              start,
             int              end,
             platform_heap_id hid);

static int
query_tests(cache           *cc,
            btree_config    *cfg,
            platform_heap_id hid,
            page_type        type,
            page_reference  *root_ref,
            int              nkvs);

static int
iterator_tests(cache           *cc,
               btree_config    *cfg,
               page_reference  *root_ref,
               int              nkvs,
               platform_heap_id hid,
               page_type        type);

static page_reference
pack_tests(cache           *cc,
           btree_config    *cfg,
           platform_heap_id hid,
           uint64           root_addr,
           uint64           nkvs);

static slice
gen_key(btree_config *cfg, uint64 i, uint8 *buffer, size_t length);

static uint64
ungen_key(slice key);

static message
gen_msg(btree_config *cfg, uint64 i, uint8 *buffer, size_t length);

/*
 * Global data declaration macro:
 */
CTEST_DATA(btree_stress)
{
   // This part of the data structures is common to what we need
   // to set up a Splinter instance, as is done in
   // btree_test.c
   master_config       master_cfg;
   data_config        *data_cfg;
   io_config           io_cfg;
   rc_allocator_config allocator_cfg;
   clockcache_config   cache_cfg;
   btree_scratch       test_scratch;
   btree_config        dbtree_cfg;

   // To create a heap for io, allocator, cache and splinter
   platform_heap_handle hh;
   platform_heap_id     hid;

   // Stuff needed to setup and exercise multiple threads.
   platform_io_handle io;
   uint8              num_bg_threads[NUM_TASK_TYPES];
   task_system       *ts;
   rc_allocator       al;
   clockcache         cc;
};

// Setup function for suite, called before every test in suite
CTEST_SETUP(btree_stress)
{
   config_set_defaults(&data->master_cfg);
   data->master_cfg.cache_capacity = GiB_TO_B(5);
   data->data_cfg                  = test_data_config;

   if (!SUCCESS(
          config_parse(&data->master_cfg, 1, Ctest_argc, (char **)Ctest_argv))
       || !init_data_config_from_master_config(data->data_cfg,
                                               &data->master_cfg)
       || !init_io_config_from_master_config(&data->io_cfg, &data->master_cfg)
       || !init_rc_allocator_config_from_master_config(
          &data->allocator_cfg, &data->master_cfg, &data->io_cfg)
       || !init_clockcache_config_from_master_config(
          &data->cache_cfg, &data->master_cfg, &data->io_cfg)
       || !init_btree_config_from_master_config(&data->dbtree_cfg,
                                                &data->master_cfg,
                                                &data->cache_cfg.super,
                                                data->data_cfg))
   {
      ASSERT_TRUE(FALSE, "Failed to parse args\n");
   }

   // Create a heap for io, allocator, cache and splinter
   if (!SUCCESS(platform_heap_create(
          platform_get_module_id(), 1 * GiB, &data->hh, &data->hid)))
   {
      ASSERT_TRUE(FALSE, "Failed to init heap\n");
   }
   // Setup execution of concurrent threads
   ZERO_ARRAY(data->num_bg_threads);
   if (!SUCCESS(io_handle_init(&data->io, &data->io_cfg, data->hh, data->hid))
       || !SUCCESS(task_system_create(data->hid,
                                      &data->io,
                                      &data->ts,
                                      data->master_cfg.use_stats,
                                      FALSE,
                                      data->num_bg_threads,
                                      sizeof(btree_scratch)))
       || !SUCCESS(rc_allocator_init(&data->al,
                                     &data->allocator_cfg,
                                     (io_handle *)&data->io,
                                     data->hh,
                                     data->hid,
                                     platform_get_module_id()))
       || !SUCCESS(clockcache_init(&data->cc,
                                   &data->cache_cfg,
                                   (io_handle *)&data->io,
                                   (allocator *)&data->al,
                                   "test",
                                   data->ts,
                                   data->hh,
                                   data->hid,
                                   platform_get_module_id())))
   {
      ASSERT_TRUE(
         FALSE,
         "Failed to init io or task system or rc_allocator or clockcache\n");
   }
}

// Optional teardown function for suite, called after every test in suite
CTEST_TEARDOWN(btree_stress) {}

/*
 * -------------------------------------------------------------------------
 * Test case to exercise random inserts of large volumes of data, across
 * multiple threads. This test case verifies that registration of threads
 * to Splinter is working stably.
 */

CTEST2(btree_stress, test_random_inserts_concurrent)
{
   int nkvs     = 1000000;
   int nthreads = 8;

   mini_allocator mini;

   page_reference root_ref = btree_create(
      (cache *)&data->cc, &data->dbtree_cfg, &mini, PAGE_TYPE_MEMTABLE);

   platform_heap_id      hid     = platform_get_heap_id();
   insert_thread_params *params  = TYPED_ARRAY_ZALLOC(hid, params, nthreads);
   platform_thread      *threads = TYPED_ARRAY_ZALLOC(hid, threads, nthreads);

   for (uint64 i = 0; i < nthreads; i++) {
      params[i].cc        = (cache *)&data->cc;
      params[i].cfg       = &data->dbtree_cfg;
      params[i].heap_id   = data->hid;
      params[i].scratch   = TYPED_MALLOC(data->hid, params[i].scratch);
      params[i].mini      = &mini;
      params[i].root_ref  = root_ref;
      params[i].start     = i * (nkvs / nthreads);
      params[i].end = i < nthreads - 1 ? (i + 1) * (nkvs / nthreads) : nkvs;
   }

   for (uint64 i = 0; i < nthreads; i++) {
      platform_status ret = task_thread_create("insert thread",
                                               insert_thread,
                                               &params[i],
                                               0,
                                               data->ts,
                                               data->hid,
                                               &threads[i]);
      ASSERT_TRUE(SUCCESS(ret));
      // insert_tests((cache *)&cc, &dbtree_cfg, &test_scratch, &mini,
      // root_addr, 0, nkvs);
   }

   for (uint64 thread_no = 0; thread_no < nthreads; thread_no++) {
      platform_thread_join(threads[thread_no]);
   }

   int rc = query_tests((cache *)&data->cc,
                        &data->dbtree_cfg,
                        data->hid,
                        PAGE_TYPE_MEMTABLE,
                        &root_ref,
                        nkvs);
   ASSERT_NOT_EQUAL(0, rc, "Invalid tree\n");

   if (!iterator_tests(
          (cache *)&data->cc, &data->dbtree_cfg, &root_ref, nkvs, data->hid, PAGE_TYPE_MEMTABLE))
   {
      platform_default_log("invalid ranges in original tree\n");
   }

   /* platform_default_log("\n\n\n"); */
   /* btree_print_tree((cache *)&cc, &dbtree_cfg, root_addr); */

   page_reference packed_root_ref = pack_tests(
      (cache *)&data->cc, &data->dbtree_cfg, data->hid, root_ref.addr, nkvs);
   if (0 < nkvs && !packed_root_ref.addr) {
      ASSERT_TRUE(FALSE, "Pack failed.\n");
   }
   platform_default_log("tree pack is done\n");

   /* platform_default_log("\n\n\n"); */
   /* btree_print_tree((cache *)&cc, &dbtree_cfg,
    * packed_root_addr); */
   /* platform_default_log("\n\n\n"); */

   rc = query_tests((cache *)&data->cc,
                    &data->dbtree_cfg,
                    data->hid,
                    PAGE_TYPE_BRANCH,
                    &packed_root_ref,
                    nkvs);
   ASSERT_NOT_EQUAL(0, rc, "Invalid tree\n");

   rc = iterator_tests(
      (cache *)&data->cc, &data->dbtree_cfg, &packed_root_ref, nkvs, data->hid, PAGE_TYPE_BRANCH);
   ASSERT_NOT_EQUAL(0, rc, "Invalid ranges in packed tree\n");

   // Release memory allocated in this test case
   for (uint64 i = 0; i < nthreads; i++) {
      platform_free(data->hid, params[i].scratch);
   }
   platform_free(hid, params);
   platform_free(hid, threads);
}

/*
 * ********************************************************************************
 * Define minions and helper functions used by this test suite.
 * ********************************************************************************
 */
static void
insert_thread(void *arg)
{
   insert_thread_params *params = (insert_thread_params *)arg;
   insert_tests(params->cc,
                params->cfg,
                params->heap_id,
                params->scratch,
                params->mini,
                &params->root_ref,
                params->start,
                params->end,
                params->hid);
}

static void
insert_tests(cache           *cc,
             btree_config    *cfg,
             platform_heap_id heap_id,
             btree_scratch   *scratch,
             mini_allocator  *mini,
             page_reference  *root_ref,
             int              start,
             int              end,
             platform_heap_id hid)
{
   uint64 generation;
   bool   was_unique;

   int    keybuf_size = btree_page_size(cfg);
   int    msgbuf_size = btree_page_size(cfg);
   uint8 *keybuf      = TYPED_MALLOC_MANUAL(hid, keybuf, keybuf_size);
   uint8 *msgbuf      = TYPED_MALLOC_MANUAL(hid, msgbuf, msgbuf_size);

   for (uint64 i = start; i < end; i++) {
      if (!SUCCESS(btree_insert(cc,
                                cfg,
                                heap_id,
                                scratch,
                                root_ref->addr,
                                mini,
                                gen_key(cfg, i, keybuf, keybuf_size),
                                gen_msg(cfg, i, msgbuf, msgbuf_size),
                                &generation,
                                &was_unique)))
      {
         ASSERT_TRUE(FALSE, "Failed to insert 4-byte %ld\n", i);
      }
   }
   platform_free(heap_id, keybuf);
   platform_free(heap_id, msgbuf);
}

static slice
gen_key(btree_config *cfg, uint64 i, uint8 *buffer, size_t length)
{
   uint64 keylen = sizeof(i) + (i % 100);
   platform_assert(keylen + sizeof(i) <= length);
   memset(buffer, 0, keylen);
   uint64 j = i * 23232323731ULL + 99382474567ULL;
   memcpy(buffer, &j, sizeof(j));
   return slice_create(keylen, buffer);
}

static uint64
ungen_key(slice key)
{
   if (slice_length(key) < sizeof(uint64)) {
      return 0;
   }

   uint64 k;
   memcpy(&k, key.data, sizeof(k));
   return (k - 99382474567ULL) * 14122572041603317147ULL;
}

static message
gen_msg(btree_config *cfg, uint64 i, uint8 *buffer, size_t length)
{
   data_handle *dh      = (data_handle *)buffer;
   uint64       datalen = sizeof(i) + (i % (btree_page_size(cfg) / 3));

   platform_assert(datalen + sizeof(i) <= length);
   dh->ref_count = 1;
   memset(dh->data, 0, datalen);
   memcpy(dh->data, &i, sizeof(i));
   return message_create(MESSAGE_TYPE_INSERT,
                         slice_create(sizeof(data_handle) + datalen, buffer));
}

static int
query_tests(cache           *cc,
            btree_config    *cfg,
            platform_heap_id hid,
            page_type        type,
            page_reference  *root_ref,
            int              nkvs)
{
   uint8 *keybuf = TYPED_MALLOC_MANUAL(hid, keybuf, btree_page_size(cfg));
   uint8 *msgbuf = TYPED_MALLOC_MANUAL(hid, msgbuf, btree_page_size(cfg));
   memset(msgbuf, 0, btree_page_size(cfg));

   merge_accumulator result;
   merge_accumulator_init(&result, hid);

   for (uint64 i = 0; i < nkvs; i++) {
      btree_lookup(cc,
                   cfg,
                   root_ref,
                   type,
                   gen_key(cfg, i, keybuf, btree_page_size(cfg)),
                   &result);
      if (!btree_found(&result)
          || message_lex_cmp(merge_accumulator_to_message(&result),
                             gen_msg(cfg, i, msgbuf, btree_page_size(cfg))))
      {
         ASSERT_TRUE(FALSE, "Failure on lookup %lu\n", i);
      }
   }

   merge_accumulator_deinit(&result);
   platform_free(hid, keybuf);
   platform_free(hid, msgbuf);
   return 1;
}

static int
iterator_tests(cache           *cc,
               btree_config    *cfg,
               page_reference  *root_ref,
               int              nkvs,
               platform_heap_id hid,
               page_type        type)
{
   btree_iterator dbiter;

   btree_iterator_init(cc,
                       cfg,
                       &dbiter,
                       root_ref,
                       type,
                       NULL_SLICE,
                       NULL_SLICE,
                       FALSE,
                       0);

   iterator *iter = (iterator *)&dbiter;

   uint64 seen = 0;
   bool   at_end;
   uint8 *prevbuf = TYPED_MALLOC_MANUAL(hid, prevbuf, btree_page_size(cfg));
   slice  prev    = NULL_SLICE;
   uint8 *keybuf  = TYPED_MALLOC_MANUAL(hid, keybuf, btree_page_size(cfg));
   uint8 *msgbuf  = TYPED_MALLOC_MANUAL(hid, msgbuf, btree_page_size(cfg));

   while (SUCCESS(iterator_at_end(iter, &at_end)) && !at_end) {
      slice   key;
      message msg;

      iterator_get_curr(iter, &key, &msg);
      uint64 k = ungen_key(key);
      ASSERT_TRUE(k < nkvs);

      int rc = 0;
      rc = slice_lex_cmp(key, gen_key(cfg, k, keybuf, btree_page_size(cfg)));
      ASSERT_EQUAL(0, rc);

      rc = message_lex_cmp(msg, gen_msg(cfg, k, msgbuf, btree_page_size(cfg)));
      ASSERT_EQUAL(0, rc);

      ASSERT_TRUE(slice_is_null(prev) || slice_lex_cmp(prev, key) < 0);

      seen++;
      prev.data = prevbuf;
      slice_copy_contents(prevbuf, key);
      prev.length = key.length;

      if (!SUCCESS(iterator_advance(iter))) {
         break;
      }
   }

   ASSERT_EQUAL(nkvs, seen);

   btree_iterator_deinit(&dbiter);
   platform_free(hid, prevbuf);
   platform_free(hid, keybuf);
   platform_free(hid, msgbuf);

   return 1;
}

static page_reference
pack_tests(cache           *cc,
           btree_config    *cfg,
           platform_heap_id hid,
           uint64           root_addr,
           uint64           nkvs)
{
   btree_iterator dbiter;
   iterator      *iter = (iterator *)&dbiter;

   page_reference ref = {.addr = root_addr};
   btree_iterator_init(cc,
                       cfg,
                       &dbiter,
                       &ref,
                       PAGE_TYPE_MEMTABLE,
                       NULL_SLICE,
                       NULL_SLICE,
                       FALSE,
                       0);

   btree_pack_req req;
   btree_pack_req_init(&req, cc, cfg, iter, nkvs, UINT64_MAX, NULL, 0, hid);

   if (!SUCCESS(btree_pack(&req))) {
      ASSERT_TRUE(FALSE, "Pack failed! req.num_tuples = %d\n", req.num_tuples);
   } else {
      platform_default_log("Packed %lu items ", req.num_tuples);
   }

   btree_pack_req_deinit(&req, hid);

   return req.root_ref;
}
