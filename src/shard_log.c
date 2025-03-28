// Copyright 2018-2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 *-----------------------------------------------------------------------------
 * shard_log.c --
 *
 *     This file contains the implementation for a sharded write-ahead log.
 *-----------------------------------------------------------------------------
 */

#include "platform.h"

#include "shard_log.h"
#include "data_internal.h"

#include "poison.h"

#include "sig.h"

#define SHARD_WAIT     1
#define SHARD_UNMAPPED UINT64_MAX

//static uint64 shard_log_magic_idx = 0;

int
shard_log_write(log_handle *log, slice key, message msg, uint64 generation);
uint64
shard_log_addr(log_handle *log);
uint64
shard_log_meta_addr(log_handle *log);
uint64
shard_log_magic(log_handle *log);

static log_ops shard_log_ops = {
   .write     = shard_log_write,
   .addr      = shard_log_addr,
   .meta_addr = shard_log_meta_addr,
   .magic     = shard_log_magic,
};

void
shard_log_iterator_get_curr(iterator *itor, slice *key, message *msg);
platform_status
shard_log_iterator_at_end(iterator *itor, bool *at_end);
platform_status
shard_log_iterator_advance(iterator *itor);

const static iterator_ops shard_log_iterator_ops = {
   .get_curr = shard_log_iterator_get_curr,
   .at_end   = shard_log_iterator_at_end,
   .advance  = shard_log_iterator_advance,
   .print    = NULL,
};

static inline uint64
shard_log_page_size(shard_log_config *cfg)
{
   return cache_config_page_size(cfg->cache_cfg);
}

static inline uint64
shard_log_pages_per_extent(shard_log_config *cfg)
{
   return cache_config_pages_per_extent(cfg->cache_cfg);
}

static inline checksum128
shard_log_checksum(shard_log_config *cfg, page_handle *page)
{
   //return platform_checksum128(
   //   page->data + 16, shard_log_page_size(cfg) - 16, cfg->seed);
   checksum128 sig;
   trunk_hmac(page->data + HASH_SIZE, shard_log_page_size(cfg) - HASH_SIZE, (char*)&sig, HASH_SIZE, PAGE_TYPE_LOG);
   return sig;
}

static inline shard_log_thread_data *
shard_log_get_thread_data(shard_log *log, threadid thr_id)
{
   return &log->thread_data[thr_id];
}

page_handle *
shard_log_alloc(shard_log *log, uint64 *next_extent)
{
   uint64 addr = mini_alloc(&log->mini, 0, NULL_SLICE, next_extent);
   return cache_alloc(log->cc, addr, PAGE_TYPE_LOG);
}

platform_status
shard_log_init(shard_log *log, cache *cc, uint64 log_gen_id, shard_log_config *cfg)
{
   memset(log, 0, sizeof(shard_log));
   log->cc        = cc;
   log->cfg       = cfg;
   log->super.ops = &shard_log_ops;

   //uint64 magic_idx = __sync_fetch_and_add(&shard_log_magic_idx, 1);
   uint64 magic_idx = log_gen_id;
   log->magic = platform_checksum64(&magic_idx, sizeof(uint64), cfg->seed);

   allocator      *al = cache_allocator(cc);
   platform_status rc = allocator_alloc(al, &log->meta_head, PAGE_TYPE_LOG);
   platform_assert_status_ok(rc);

   for (threadid thr_i = 0; thr_i < MAX_THREADS; thr_i++) {
      shard_log_thread_data *thread_data =
         shard_log_get_thread_data(log, thr_i);
      thread_data->addr   = SHARD_UNMAPPED;
      thread_data->offset = 0;
      thread_data->page   = NULL;
   }

   // the log uses an unkeyed mini allocator
   log->addr = mini_init(&log->mini,
                         cc,
                         log->cfg->data_cfg,
                         log->meta_head,
                         0,
                         1,
                         PAGE_TYPE_LOG,
                         FALSE);
   platform_default_log("%s: addr: %lu meta_head: %lu\n", __func__, log->addr,
    log->meta_head);

   return STATUS_OK;
}

void
shard_log_zap(shard_log *log)
{
   cache *cc = log->cc;

   for (threadid i = 0; i < MAX_THREADS; i++) {
      shard_log_thread_data *thread_data = shard_log_get_thread_data(log, i);
      if (thread_data->page) {
         cache_unlock(cc, thread_data->page);
         cache_unclaim(cc, thread_data->page);
         cache_unget(cc, thread_data->page);
      }
      thread_data->addr                  = SHARD_UNMAPPED;
      thread_data->offset                = 0;
      thread_data->page                  = NULL;
   }

   mini_unkeyed_dec_ref(cc, log->meta_head, PAGE_TYPE_LOG, FALSE);
}

/*
 * -------------------------------------------------------------------------
 * Header for a key/message pair stored in the sharded log: Disk-resident
 * structure. Appears on pages of page type == PAGE_TYPE_LOG
 * -------------------------------------------------------------------------
 */
struct ONDISK log_entry {
   uint64 generation;
   uint16 keylen;
   uint16 messagelen;
   uint8  msg_type;
   char   contents[];
};

static char *
log_entry_key_cursor(log_entry *le)
{
   return le->contents;
}

static char *
log_entry_message_cursor(log_entry *le)
{
   return le->contents + le->keylen;
}

static slice
log_entry_key(log_entry *le)
{
   return slice_create(le->keylen, le->contents);
}

static message
log_entry_message(log_entry *le)
{
   return message_create(
      le->msg_type, slice_create(le->messagelen, le->contents + le->keylen));
}

static uint64
log_entry_size(slice key, message msg)
{
   return sizeof(log_entry) + slice_length(key) + message_length(msg);
}

static uint64
sizeof_log_entry(log_entry *le)
{
   return sizeof(log_entry) + le->keylen + le->messagelen;
}

static log_entry *
first_log_entry(char *page)
{
   return (log_entry *)(page + sizeof(shard_log_hdr));
}

static bool
terminal_log_entry(shard_log_config *cfg, char *page, log_entry *le)
{
   return page + shard_log_page_size(cfg) - (char *)le < sizeof(log_entry)
          || (le->keylen == 0 && le->messagelen == 0);
}

static log_entry *
log_entry_next(log_entry *le)
{
   return (log_entry *)((char *)le + sizeof_log_entry(le));
}

static int
get_new_page_for_thread(shard_log             *log,
                        shard_log_thread_data *thread_data,
                        page_handle          **page)
{
   uint64 next_extent;

   *page                 = shard_log_alloc(log, &next_extent);
   thread_data->addr     = (*page)->disk_addr;
   shard_log_hdr *hdr    = (shard_log_hdr *)(*page)->data;
   hdr->magic            = log->magic;
   hdr->next_extent_addr = next_extent;
   hdr->num_entries      = 0;
   thread_data->offset   = sizeof(shard_log_hdr);
   thread_data->page     = *page;
   return 0;
}

static bool shard_log_page_authenticate(shard_log_config *cfg, page_handle *page)
{
   shard_log_hdr *hdr    = (shard_log_hdr *)page->data;
   checksum128 checksum;
   trunk_hmac(page->data + HASH_SIZE,
              shard_log_page_size(cfg) - HASH_SIZE,
              (char*)&checksum, HASH_SIZE, PAGE_TYPE_LOG);
   if (0 != memcmp(&checksum, &hdr->checksum, HASH_SIZE)) {
      //char buf[64] = { 0 };
      //snprintf(buf, 64, "hdr checksum addr=%lu:\n", page->disk_addr);
      //print_sig((char*)&hdr->checksum, HASH_SIZE, buf);
      //snprintf(buf, 64, "computed checksum:\n");
      //print_sig((char*)&checksum, HASH_SIZE, buf);
      return FALSE;
   }
   return TRUE;
}

int
shard_log_write(log_handle *logh, slice key, message msg, uint64 generation)
{
   shard_log             *log = (shard_log *)logh;
   cache                 *cc  = log->cc;
   shard_log_thread_data *thread_data =
      shard_log_get_thread_data(log, platform_get_tid());

   page_handle *page;
   if (thread_data->addr == SHARD_UNMAPPED) {
      if (get_new_page_for_thread(log, thread_data, &page)) {
         return -1;
      }
   } else {
     page_reference ref = { .addr = thread_data->addr };
     page        = cache_get_no_auth(cc, &ref, TRUE, PAGE_TYPE_LOG);
     //bool pass_auth = shard_log_page_authenticate(log->cfg, page);
     //platform_assert(pass_auth);
     uint64 wait = 1;
     while (!cache_claim(cc, page)) {
       platform_sleep(wait);
       wait = wait > 1024 ? wait : 2 * wait;
     }
     cache_lock(cc, page);
      page = thread_data->page;
      platform_assert(page != NULL);
   }

   shard_log_hdr *hdr    = (shard_log_hdr *)page->data;
   log_entry     *cursor = (log_entry *)(page->data + thread_data->offset);
   uint64         new_entry_size = log_entry_size(key, msg);
   uint64 free_space = shard_log_page_size(log->cfg) - thread_data->offset;
   debug_assert(new_entry_size
                <= shard_log_page_size(log->cfg) - sizeof(shard_log_hdr));

   if (free_space < new_entry_size) {
      memset(cursor, 0, free_space);
      hdr->checksum = shard_log_checksum(log->cfg, page);
      //char buf[64] = { 0 };
      //snprintf(buf, 64, "hdr checksum addr=%lu:\n", page->disk_addr);
      //print_sig((char*)&hdr->checksum, HASH_SIZE, buf);
      cache_unlock(cc, page);
      cache_unclaim(cc, page);
      cache_page_sync(cc, page, FALSE, PAGE_TYPE_LOG);
      cache_unget(cc, page);

      if (get_new_page_for_thread(log, thread_data, &page)) {
         return -1;
      }
      cursor = (log_entry *)(page->data + thread_data->offset);
      hdr    = (shard_log_hdr *)page->data;
   }

   cursor->generation = generation;
   cursor->keylen     = slice_length(key);
   cursor->messagelen = message_length(msg);
   cursor->msg_type   = message_class(msg);
   memmove(log_entry_key_cursor(cursor), slice_data(key), slice_length(key));
   memmove(
      log_entry_message_cursor(cursor), message_data(msg), message_length(msg));
   hdr->num_entries++;

   thread_data->offset += new_entry_size;
   debug_assert(thread_data->offset <= shard_log_page_size(log->cfg));

   // Caclculate the hash for every write
   // hdr->checksum = shard_log_checksum(log->cfg, page);
   //char buf[64] = { 0 };
   //snprintf(buf, 64, "hdr checksum addr=%lu:\n", page->disk_addr);
   //print_sig((char*)&hdr->checksum, HASH_SIZE, buf);
   cache_unlock(cc, page);
   cache_unclaim(cc, page);
   cache_unget(cc, page);

   return 0;
}

uint64
shard_log_addr(log_handle *logh)
{
   shard_log *log = (shard_log *)logh;
   return log->addr;
}

uint64
shard_log_meta_addr(log_handle *logh)
{
   shard_log *log = (shard_log *)logh;
   return log->meta_head;
}

uint64
shard_log_magic(log_handle *logh)
{
   shard_log *log = (shard_log *)logh;
   return log->magic;
}

bool
shard_log_valid(shard_log_config *cfg, page_handle *page, uint64 magic)
{
   shard_log_hdr *hdr = (shard_log_hdr *)page->data;
   return hdr->magic == magic
          && platform_checksum_is_equal(hdr->checksum,
                                        shard_log_checksum(cfg, page));
}

uint64
shard_log_next_extent_addr(shard_log_config *cfg, page_handle *page)
{
   shard_log_hdr *hdr = (shard_log_hdr *)page->data;
   return hdr->next_extent_addr;
}

int
shard_log_compare(const void *p1, const void *p2, void *unused)
{
   log_entry **le1 = (log_entry **)p1;
   log_entry **le2 = (log_entry **)p2;
   return (*le1)->generation - (*le2)->generation;
}

log_handle *
log_create(cache *cc, log_config *lcfg, uint64 log_gen_id, platform_heap_id hid)
{
   shard_log_config *cfg  = (shard_log_config *)lcfg;
   shard_log        *slog = TYPED_MALLOC(hid, slog);
   platform_status   rc   = shard_log_init(slog, cc, log_gen_id, cfg);
   platform_assert(SUCCESS(rc));
   return (log_handle *)slog;
}

platform_status
shard_log_iterator_init(cache              *cc,
                        shard_log_config   *cfg,
                        platform_heap_id    hid,
                        uint64              addr,
                        uint64              magic,
                        shard_log_iterator *itor)
{
   page_handle *page;
   uint64       i;
   uint64       pages_per_extent = shard_log_pages_per_extent(cfg);
   uint64       page_addr;
   uint64       num_valid_pages = 0;
   uint64       extent_addr;
   uint64       next_extent_addr;

   memset(itor, 0, sizeof(shard_log_iterator));
   itor->super.ops = &shard_log_iterator_ops;
   itor->cfg       = cfg;

   // traverse the log extents and calculate the required space
   extent_addr = addr;
   while (extent_addr != 0 && cache_get_ref(cc, extent_addr) > 0) {
      cache_prefetch(cc, extent_addr, PAGE_TYPE_FILTER);
      next_extent_addr = 0;
      for (i = 0; i < pages_per_extent; i++) {
         page_addr = extent_addr + i * shard_log_page_size(cfg);
         page_reference ref = { .addr = page_addr };
         page      = cache_get_no_auth(cc, &ref, TRUE, PAGE_TYPE_LOG);
         bool pass_auth = shard_log_page_authenticate(cfg, page);
         if (pass_auth && shard_log_valid(cfg, page, magic)) {
            num_valid_pages++;
            itor->num_entries += ((shard_log_hdr *)page->data)->num_entries;
            next_extent_addr = shard_log_next_extent_addr(cfg, page);
         }
         cache_unget(cc, page);
      }
      extent_addr = next_extent_addr;
   }

   itor->contents = TYPED_ARRAY_MALLOC(
      hid, itor->contents, num_valid_pages * shard_log_page_size(cfg));
   itor->entries = TYPED_ARRAY_MALLOC(hid, itor->entries, itor->num_entries);

   // traverse the log extents again and copy the kv pairs
   log_entry *cursor    = (log_entry *)itor->contents;
   uint64     entry_idx = 0;
   extent_addr          = addr;
   while (extent_addr != 0 && cache_get_ref(cc, extent_addr) > 0) {
      cache_prefetch(cc, extent_addr, PAGE_TYPE_FILTER);
      next_extent_addr = 0;
      for (i = 0; i < pages_per_extent; i++) {
         page_addr = extent_addr + i * shard_log_page_size(cfg);
         page_reference ref = { .addr = page_addr };
         page      = cache_get_no_auth(cc, &ref, TRUE, PAGE_TYPE_LOG);
         bool pass_auth = shard_log_page_authenticate(cfg, page);
         if (pass_auth && shard_log_valid(cfg, page, magic)) {
            for (log_entry *le = first_log_entry(page->data);
                 !terminal_log_entry(cfg, page->data, le);
                 le = log_entry_next(le))
            {
               memmove(cursor, le, sizeof_log_entry(le));
               itor->entries[entry_idx] = cursor;
               entry_idx++;
               cursor = log_entry_next(cursor);
            }
            next_extent_addr = shard_log_next_extent_addr(cfg, page);
         }
         cache_unget(cc, page);
      }
      extent_addr = next_extent_addr;
   }

   // sort by generation
   log_entry *tmp;
   platform_sort_slow(itor->entries,
                      itor->num_entries,
                      sizeof(log_entry *),
                      shard_log_compare,
                      NULL,
                      &tmp);

   return STATUS_OK;
}

void
shard_log_iterator_deinit(platform_heap_id hid, shard_log_iterator *itor)
{
   platform_free(hid, itor->contents);
   platform_free(hid, itor->entries);
}

void
shard_log_iterator_get_curr(iterator *itorh, slice *key, message *msg)
{
   shard_log_iterator *itor = (shard_log_iterator *)itorh;
   *key                     = log_entry_key(itor->entries[itor->pos]);
   *msg                     = log_entry_message(itor->entries[itor->pos]);
}

platform_status
shard_log_iterator_at_end(iterator *itorh, bool *at_end)
{
   shard_log_iterator *itor = (shard_log_iterator *)itorh;
   *at_end                  = itor->pos == itor->num_entries;

   return STATUS_OK;
}

platform_status
shard_log_iterator_advance(iterator *itorh)
{
   shard_log_iterator *itor = (shard_log_iterator *)itorh;
   itor->pos++;
   return STATUS_OK;
}

/*
 *-----------------------------------------------------------------------------
 * shard_log_config_init --
 *
 *      Initialize shard_log config values
 *-----------------------------------------------------------------------------
 */
void
shard_log_config_init(shard_log_config *log_cfg,
                      cache_config     *cache_cfg,
                      data_config      *data_cfg)
{
   ZERO_CONTENTS(log_cfg);
   log_cfg->cache_cfg = cache_cfg;
   log_cfg->data_cfg  = data_cfg;
   log_cfg->seed      = HASH_SEED;
}

void
shard_log_print(shard_log *log)
{
   cache            *cc               = log->cc;
   uint64            extent_addr      = log->addr;
   shard_log_config *cfg              = log->cfg;
   uint64            magic            = log->magic;
   data_config      *dcfg             = cfg->data_cfg;
   uint64            pages_per_extent = shard_log_pages_per_extent(cfg);

   while (extent_addr != 0 && cache_get_ref(cc, extent_addr) > 0) {
      cache_prefetch(cc, extent_addr, PAGE_TYPE_FILTER);
      uint64 next_extent_addr = 0;
      for (uint64 i = 0; i < pages_per_extent; i++) {
         uint64       page_addr = extent_addr + i * shard_log_page_size(cfg);
         page_reference ref = {.addr = page_addr };
         page_handle *page      = cache_get_no_auth(cc, &ref, TRUE, PAGE_TYPE_LOG);
         bool pass_auth = shard_log_page_authenticate(cfg, page);
         if (pass_auth && shard_log_valid(cfg, page, magic)) {
            next_extent_addr = shard_log_next_extent_addr(cfg, page);
            for (log_entry *le = first_log_entry(page->data);
                 !terminal_log_entry(cfg, page->data, le);
                 le = log_entry_next(le))
            {
               platform_default_log("%s -- %s : %lu\n",
                                    key_string(dcfg, log_entry_key(le)),
                                    message_string(dcfg, log_entry_message(le)),
                                    le->generation);
            }
         }
         cache_unget(cc, page);
      }
      extent_addr = next_extent_addr;
   }
}

