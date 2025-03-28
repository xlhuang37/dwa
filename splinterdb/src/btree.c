// Copyright 2018-2021 VMware, Inc. All rights reserved. -- VMware Confidential
// SPDX-License-Identifier: Apache-2.0

#include "btree_private.h"
#include "poison.h"
#include "ref.h"
#include "sig.h"
#include "platform.h"

#ifdef AUTH_DEBUG
#include <sys/mman.h>
#endif

/******************************************************************
 * Structure of a BTree node: Disk-resident structure:
 *
 *                                 hdr->next_entry
 *                                               |
 *   0                                           v     page_size
 *   -----------------------------------------------------------
 *   | header | offsets table ---> | empty space | <--- entries|
 *   -----------------------------------------------------------
 *
 *  header: struct btree_hdr{}
 *  entry : struct leaf_entry{}
 *
 * The arrows indicate that the offsets table grows to the left
 * and the entries grow to the right.
 *
 * Entries are not physically sorted in a node.  The offsets table
 * gives the offset of each entry, in key order.
 *
 * Offsets are from byte 0 of the node.
 *
 * New entries are placed in the empty space.
 *
 * When an entry is replaced with a physically smaller entry, the
 * replacement is performed in place.  When an entry is replaced with
 * a physically larger entry, then the new entry is stored in the
 * empty space.

 * A node may have free space fragmentation after some entries have
 * been replaced.  Defragmenting the node rebuilds it with no
 * free-space fragmentation.
 *
 * When a node runs out of free space, we measure its dead space.
 * If dead space is:
 *  - below a threshold, we split the node.
 *  - above the threshold, then we defragment the node instead of splitting it.
 *******************************************************************/

/* Threshold for splitting instead of defragmenting. */
#define BTREE_SPLIT_THRESHOLD(page_size) ((page_size) / 2)

/* After a split, the free space in the left node may be fragmented.
 * If there's less than this much contiguous free space, then we also
 * defrag the left node.
 */
#define BTREE_DEFRAGMENT_THRESHOLD(page_size) ((page_size) / 4)

#define BTREE_INITIAL_PREFETCHING_DISTANCE(pages_per_extent)   \
   ((pages_per_extent) / 4)

char  positive_infinity_buffer;
slice positive_infinity = {0, &positive_infinity_buffer};

/*
 * Branches keep track of the number of keys and the total size of
 * all keys and messages in their subtrees.  But memtables do not
 * (because it is difficult to maintain this information during
 * insertion).  However, the current implementation uses the same
 * data structure for both memtables and branches.  So memtables
 * store BTREE_UNKNOWN_COUNTER for these counters.
 */
#define BTREE_UNKNOWN_COUNTER (0x7fffffffUL)


static inline uint8
btree_height(const btree_hdr *hdr)
{
   return hdr->height;
}

static inline table_entry
btree_get_table_entry(btree_hdr *hdr, int i)
{
   debug_assert(i < hdr->num_entries);
   return hdr->offsets[i];
}

static inline table_index
btree_num_entries(const btree_hdr *hdr)
{
   return hdr->num_entries;
}

static inline void
btree_increment_height(btree_hdr *hdr)
{
   hdr->height++;
}

static inline void
btree_reset_node_entries(const btree_config *cfg, btree_hdr *hdr)
{
   hdr->num_entries = 0;
   hdr->next_entry  = btree_page_size(cfg);
}


static inline uint64
index_entry_size(const slice key)
{
   return sizeof(index_entry) + slice_length(key);
}

static inline uint64
leaf_entry_size(const slice key, const message msg)
{
   return sizeof(leaf_entry) + slice_length(key) + message_length(msg);
}

static inline uint64
leaf_entry_key_size(const leaf_entry *entry)
{
   return entry->key_size;
}


static inline uint64
leaf_entry_message_size(const leaf_entry *entry)
{
   return entry->message_size;
}

#ifdef AUTH_DEBUG
static int
iterator_tests(cache           *cc,
               btree_config    *cfg,
               page_reference  *root_ref,
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

   bool   at_end;

   while (SUCCESS(iterator_at_end(iter, &at_end)) && !at_end) {
      slice   key;
      message msg;

      iterator_get_curr(iter, &key, &msg);

      if (!SUCCESS(iterator_advance(iter))) {
         break;
      }
   }

   btree_iterator_deinit(&dbiter);
   return 1;
}
#endif

/*********************************************************
 * Code for tracing operations involving a particular key
 *********************************************************/

// #define BTREE_KEY_TRACING

#ifdef BTREE_KEY_TRACING
static char trace_key[24] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void
log_trace_key(slice key, char *msg)
{
   if (slice_lex_cmp(key, slice_create(sizeof(trace_key), trace_key)) == 0) {
      platform_log("BTREE_TRACE_KEY: %s\n", msg);
   }
}

/* Output msg if this leaf contains the trace_key */
void
log_trace_leaf(const btree_config *cfg, const btree_hdr *hdr, char *msg)
{
   for (int i = 0; i < hdr->num_entries; i++) {
      slice key = btree_get_tuple_key(cfg, hdr, i);
      log_trace_key(key, msg);
   }
}
#else
#   define log_trace_key(key, msg)
#   define log_trace_leaf(cfg, hdr, msg)
#endif /* BTREE_KEY_TRACING */


/**************************************
 * Basic get/set on index nodes
 **************************************/

static inline void
btree_fill_index_entry(const btree_config *cfg,
                       btree_hdr          *hdr,
                       index_entry        *entry,
                       slice               new_pivot_key,
                       uint64              new_addr,
                       uint32              kv_pairs,
                       uint32              key_bytes,
                       uint32              message_bytes)
{
   debug_assert((void *)hdr <= (void *)entry);
   debug_assert(diff_ptr(hdr, entry) + index_entry_size(new_pivot_key)
                <= btree_page_size(cfg));
   memcpy(entry->key, slice_data(new_pivot_key), slice_length(new_pivot_key));
   entry->key_size                            = slice_length(new_pivot_key);
   entry->key_indirect                        = FALSE;
   entry->pivot_data.child_ref.addr           = new_addr;
   entry->pivot_data.num_kvs_in_subtree       = kv_pairs;
   entry->pivot_data.key_bytes_in_subtree     = key_bytes;
   entry->pivot_data.message_bytes_in_subtree = message_bytes;
}

bool
btree_set_index_entry(const btree_config *cfg,
                      btree_hdr          *hdr,
                      table_index         k,
                      slice               new_pivot_key,
                      uint64              new_addr,
                      int64               kv_pairs,
                      int64               key_bytes,
                      int64               message_bytes)
{
   platform_assert(
      k <= hdr->num_entries, "k=%d, num_entries=%d\n", k, hdr->num_entries);
   uint64 new_num_entries = k < hdr->num_entries ? hdr->num_entries : k + 1;

   if (k < hdr->num_entries) {
      index_entry *old_entry = btree_get_index_entry(cfg, hdr, k);
      if (hdr->next_entry == diff_ptr(hdr, old_entry)
          && (diff_ptr(hdr, &hdr->offsets[new_num_entries])
                 + index_entry_size(new_pivot_key)
              <= hdr->next_entry + sizeof_index_entry(old_entry)))
      {
         /* special case to avoid creating fragmentation:
          * the old entry is the physically first entry in the node
          * and the new entry will fit in the space avaiable from the old
          * entry plus the free space preceding the old_entry.
          * In this case, just reset next_entry so we can insert the new entry.
          */
         hdr->next_entry += sizeof_index_entry(old_entry);
      } else if (index_entry_size(new_pivot_key)
                 <= sizeof_index_entry(old_entry)) {
         /* old_entry is not the physically first in the node,
          * but new entry will fit inside it.
          */
         btree_fill_index_entry(cfg,
                                hdr,
                                old_entry,
                                new_pivot_key,
                                new_addr,
                                kv_pairs,
                                key_bytes,
                                message_bytes);
         return TRUE;
      }
      /* Fall through */
   }

   if (hdr->next_entry < diff_ptr(hdr, &hdr->offsets[new_num_entries])
                            + index_entry_size(new_pivot_key))
   {
      return FALSE;
   }

   index_entry *new_entry = pointer_byte_offset(
      hdr, hdr->next_entry - index_entry_size(new_pivot_key));
   btree_fill_index_entry(cfg,
                          hdr,
                          new_entry,
                          new_pivot_key,
                          new_addr,
                          kv_pairs,
                          key_bytes,
                          message_bytes);

   hdr->offsets[k]  = diff_ptr(hdr, new_entry);
   hdr->num_entries = new_num_entries;
   hdr->next_entry  = diff_ptr(hdr, new_entry);
   return TRUE;
}

static inline bool
btree_insert_index_entry(const btree_config *cfg,
                         btree_hdr          *hdr,
                         uint32              k,
                         slice               new_pivot_key,
                         uint64              new_addr,
                         int64               kv_pairs,
                         int64               key_bytes,
                         int64               message_bytes)
{
   bool succeeded = btree_set_index_entry(cfg,
                                          hdr,
                                          hdr->num_entries,
                                          new_pivot_key,
                                          new_addr,
                                          kv_pairs,
                                          key_bytes,
                                          message_bytes);
   if (succeeded) {
      node_offset this_entry_offset = hdr->offsets[hdr->num_entries - 1];
      memmove(&hdr->offsets[k + 1],
              &hdr->offsets[k],
              (hdr->num_entries - k - 1) * sizeof(hdr->offsets[0]));
      hdr->offsets[k] = this_entry_offset;
   }
   return succeeded;
}


/**************************************
 * Basic get/set on leaf nodes
 **************************************/

static inline void
btree_fill_leaf_entry(const btree_config *cfg,
                      btree_hdr          *hdr,
                      leaf_entry         *entry,
                      slice               key,
                      message             msg)
{
   debug_assert(pointer_byte_offset(entry, leaf_entry_size(key, msg))
                <= pointer_byte_offset(hdr, btree_page_size(cfg)));
   memcpy(entry->key_and_message, slice_data(key), slice_length(key));
   memcpy(entry->key_and_message + slice_length(key),
          message_data(msg),
          message_length(msg));
   entry->key_size     = slice_length(key);
   entry->key_indirect = FALSE;
   entry->type         = message_class(msg);
   /* This assertion ensures that entry->type is large enough to hold type. */
   debug_assert(entry->type == message_class(msg),
                "entry->type not large enough to hold message_class");
   entry->message_size     = message_length(msg);
   entry->message_indirect = FALSE;
}

static inline bool
btree_can_set_leaf_entry(const btree_config *cfg,
                         const btree_hdr    *hdr,
                         table_index         k,
                         slice               new_key,
                         message             new_message)
{
   if (hdr->num_entries < k)
      return FALSE;

   if (k < hdr->num_entries) {
      leaf_entry *old_entry = btree_get_leaf_entry(cfg, hdr, k);
      if (leaf_entry_size(new_key, new_message) <= sizeof_leaf_entry(old_entry))
      {
         return TRUE;
      }
      /* Fall through */
   }

   uint64 new_num_entries = k < hdr->num_entries ? hdr->num_entries : k + 1;
   if (hdr->next_entry < diff_ptr(hdr, &hdr->offsets[new_num_entries])
                            + leaf_entry_size(new_key, new_message))
   {
      return FALSE;
   }

   return TRUE;
}

bool
btree_set_leaf_entry(const btree_config *cfg,
                     btree_hdr          *hdr,
                     table_index         k,
                     slice               new_key,
                     message             new_message)
{
   if (k < hdr->num_entries) {
      leaf_entry *old_entry = btree_get_leaf_entry(cfg, hdr, k);
      if (leaf_entry_size(new_key, new_message) <= sizeof_leaf_entry(old_entry))
      {
         btree_fill_leaf_entry(cfg, hdr, old_entry, new_key, new_message);
         return TRUE;
      }
      /* Fall through */
   }

   platform_assert(k <= hdr->num_entries);
   uint64 new_num_entries = k < hdr->num_entries ? hdr->num_entries : k + 1;
   if (hdr->next_entry < diff_ptr(hdr, &hdr->offsets[new_num_entries])
                            + leaf_entry_size(new_key, new_message))
   {
      return FALSE;
   }

   leaf_entry *new_entry = pointer_byte_offset(
      hdr, hdr->next_entry - leaf_entry_size(new_key, new_message));
   platform_assert(
      (void *)&hdr->offsets[new_num_entries] <= (void *)new_entry,
      "Offset addr 0x%p for index, new_num_entries=%lu is incorrect."
      " It should be <= new_entry=0x%p\n",
      &hdr->offsets[new_num_entries],
      new_num_entries,
      new_entry);
   btree_fill_leaf_entry(cfg, hdr, new_entry, new_key, new_message);

   hdr->offsets[k]  = diff_ptr(hdr, new_entry);
   hdr->num_entries = new_num_entries;
   hdr->next_entry  = diff_ptr(hdr, new_entry);
   platform_assert(0 < hdr->num_entries);

   return TRUE;
}


/* Set up the hash of a node in the parent node's pivot data*/
static inline void
btree_set_child_hash(cache *cc,
                     const btree_config *cfg,
                     btree_node *node,
                     uint64 child_addr,
                     char *hash,
                     table_index k,
                     int line)
{
   index_entry *entry = btree_get_index_entry(cfg, node->hdr, k);
   debug_assert(child_addr == entry->pivot_data.child_ref.addr);
   memcpy(entry->pivot_data.child_ref.hash, hash, HASH_SIZE);
}

static inline bool
btree_insert_leaf_entry(const btree_config *cfg,
                        btree_hdr          *hdr,
                        table_index         k,
                        slice               new_key,
                        message             new_message)
{
   debug_assert(k <= hdr->num_entries);
   bool succeeded =
      btree_set_leaf_entry(cfg, hdr, hdr->num_entries, new_key, new_message);
   if (succeeded) {
      node_offset this_entry_offset = hdr->offsets[hdr->num_entries - 1];
      debug_assert(k + 1 <= hdr->num_entries);
      memmove(&hdr->offsets[k + 1],
              &hdr->offsets[k],
              (hdr->num_entries - k - 1) * sizeof(hdr->offsets[0]));
      hdr->offsets[k] = this_entry_offset;
   }
   return succeeded;
}

/*
 *-----------------------------------------------------------------------------
 * btree_find_pivot --
 *
 *      Returns idx such that
 *          - -1 <= idx < num_entries
 *          - forall i | 0 <= i <= idx         :: key_i <= key
 *          - forall i | idx < i < num_entries :: key   <  key_i
 *      Also
 *          - *found == 0 || *found == 1
 *          - *found == 1 <==> (0 <= idx && key_idx == key)
 *-----------------------------------------------------------------------------
 */
/*
 * The C code below is a translation of the following verified dafny
implementation.

method bsearch(s: seq<int>, k: int) returns (idx: int, f: bool)
  requires forall i, j | 0 <= i < j < |s| :: s[i] < s[j]
  ensures -1 <= idx < |s|
  ensures forall i | 0 <= i <= idx :: s[i] <= k
  ensures forall i | idx < i < |s| :: k < s[i]
  ensures f <==> (0 <= idx && s[idx] == k)
{
  var lo := 0;
  var hi := |s|;

  f := false;

  while lo < hi
    invariant 0 <= lo <= hi <= |s|
    invariant forall i | 0 <= i < lo :: s[i] <= k
    invariant forall i | hi <= i < |s| :: k < s[i]
    invariant f <==> (0 < lo && s[lo-1] == k)
  {
    var mid := (lo + hi) / 2;
    if s[mid] <= k {
      lo := mid + 1;
      f := s[mid] == k;
    } else {
      hi := mid;
    }
  }

  idx := lo - 1;
}

*/
int64
btree_find_pivot(const btree_config *cfg,
                 const btree_hdr    *hdr,
                 slice               key,
                 bool               *found)
{
   int64 lo = 0, hi = btree_num_entries(hdr);

   if (slice_is_null(key)) {
      return -1;
   }

   *found = 0;

   while (lo < hi) {
      int64 mid = (lo + hi) / 2;
      int   cmp = btree_key_compare(cfg, btree_get_pivot(cfg, hdr, mid), key);
      if (cmp == 0) {
         *found = 1;
         return mid;
      } else if (cmp < 0) {
         lo = mid + 1;
      } else {
         hi = mid;
      }
   }

   return lo - 1;
}

/*
 *-----------------------------------------------------------------------------
 * btree_find_tuple --
 *
 *      Returns idx such that
 *          - -1 <= idx < num_entries
 *          - forall i | 0 <= i <= idx         :: key_i <= key
 *          - forall i | idx < i < num_entries :: key   <  key_i
 *      Also
 *          - *found == 0 || *found == 1
 *          - *found == 1 <==> (0 <= idx && key_idx == key)
 *-----------------------------------------------------------------------------
 */
/*
 * The C code below is a translation of the same dafny implementation as above.
 */
static inline int64
btree_find_tuple(const btree_config *cfg,
                 const btree_hdr    *hdr,
                 slice               key,
                 bool               *found)
{
   int64 lo = 0, hi = btree_num_entries(hdr);

   *found = 0;

   while (lo < hi) {
      int64 mid = (lo + hi) / 2;
      int cmp = btree_key_compare(cfg, btree_get_tuple_key(cfg, hdr, mid), key);
      if (cmp == 0) {
         *found = 1;
         return mid;
      } else if (cmp < 0) {
         lo = mid + 1;
      } else {
         hi = mid;
      }
   }

   return lo - 1;
}

/*
 *-----------------------------------------------------------------------------
 * btree_leaf_incorporate_tuple
 *
 *   Adds the given key and value to node (must be a leaf).
 *
 * This is broken into several pieces to avoid repeated work during
 * exceptional cases.
 *
 * - create_incorporate_spec() computes everything needed to update
 *   the leaf, i.e. the index of the key, whether it is replacing an
 *   existing entry, and the merged message if it is.
 *
 * - can_perform_incorporate_spec says whether the leaf has enough
 *   room to actually perform the incorporation.
 *
 * - perform_incorporate_spec() does what it says.
 *
 * - incorporate_tuple() is a convenience wrapper.
 *-----------------------------------------------------------------------------
 */
static inline int
btree_merge_tuples(const btree_config *cfg,
                   slice               key,
                   message             old_data,
                   merge_accumulator  *new_data)
{
   return data_merge_tuples(cfg->data_cfg, key, old_data, new_data);
}

static message
spec_message(const leaf_incorporate_spec *spec)
{
   if (spec->old_entry_state == ENTRY_DID_NOT_EXIST) {
      return spec->msg.new_message;
   } else {
      return merge_accumulator_to_message(&spec->msg.merged_message);
   }
}

platform_status
btree_create_leaf_incorporate_spec(const btree_config    *cfg,
                                   platform_heap_id       heap_id,
                                   btree_hdr             *hdr,
                                   slice                  key,
                                   message                msg,
                                   leaf_incorporate_spec *spec)
{
   spec->key = key;
   bool found;
   spec->idx             = btree_find_tuple(cfg, hdr, key, &found);
   spec->old_entry_state = found ? ENTRY_STILL_EXISTS : ENTRY_DID_NOT_EXIST;
   if (!found) {
      spec->msg.new_message = msg;
      spec->idx++;
      return STATUS_OK;
   } else {
      leaf_entry *entry      = btree_get_leaf_entry(cfg, hdr, spec->idx);
      message     oldmessage = leaf_entry_message(entry);
      bool        success;
      success = merge_accumulator_init_from_message(
         &spec->msg.merged_message, heap_id, msg);
      if (!success) {
         return STATUS_NO_MEMORY;
      }
      if (btree_merge_tuples(cfg, key, oldmessage, &spec->msg.merged_message)) {
         merge_accumulator_deinit(&spec->msg.merged_message);
         return STATUS_NO_MEMORY;
      } else {
         return STATUS_OK;
      }
   }
}

void
destroy_leaf_incorporate_spec(leaf_incorporate_spec *spec)
{
   if (spec->old_entry_state != ENTRY_DID_NOT_EXIST) {
      merge_accumulator_deinit(&spec->msg.merged_message);
   }
}

static inline bool
btree_can_perform_leaf_incorporate_spec(const btree_config          *cfg,
                                        btree_hdr                   *hdr,
                                        const leaf_incorporate_spec *spec)
{
   if (spec->old_entry_state == ENTRY_DID_NOT_EXIST) {
      return btree_can_set_leaf_entry(
         cfg, hdr, btree_num_entries(hdr), spec->key, spec->msg.new_message);
   } else if (spec->old_entry_state == ENTRY_STILL_EXISTS) {
      message merged = merge_accumulator_to_message(&spec->msg.merged_message);
      return btree_can_set_leaf_entry(cfg, hdr, spec->idx, spec->key, merged);
   } else {
      debug_assert(spec->old_entry_state == ENTRY_HAS_BEEN_REMOVED);
      message merged = merge_accumulator_to_message(&spec->msg.merged_message);
      return btree_can_set_leaf_entry(
         cfg, hdr, btree_num_entries(hdr), spec->key, merged);
   }
}

bool
btree_try_perform_leaf_incorporate_spec(const btree_config          *cfg,
                                        btree_hdr                   *hdr,
                                        const leaf_incorporate_spec *spec,
                                        uint64                      *generation)
{
   bool success;
   switch (spec->old_entry_state) {
      case ENTRY_DID_NOT_EXIST:
         success = btree_insert_leaf_entry(
            cfg, hdr, spec->idx, spec->key, spec->msg.new_message);
         break;
      case ENTRY_STILL_EXISTS:
      {
         message merged =
            merge_accumulator_to_message(&spec->msg.merged_message);
         success = btree_set_leaf_entry(cfg, hdr, spec->idx, spec->key, merged);
         break;
      }
      case ENTRY_HAS_BEEN_REMOVED:
      {
         message merged =
            merge_accumulator_to_message(&spec->msg.merged_message);
         success =
            btree_insert_leaf_entry(cfg, hdr, spec->idx, spec->key, merged);
         break;
      }
      default:
         platform_assert(
            FALSE,
            "Unknown btree leaf_incorporate_spec->old_entry_state %d",
            spec->old_entry_state);
   }

   if (success) {
      *generation = hdr->generation++;
   }
   return success;
}

/*
 *-----------------------------------------------------------------------------
 * btree_defragment_leaf --
 *
 *      Defragment a node.  If spec != NULL, then we also remove the old
 *      entry that will be replaced by the insert, if such an old entry exists.
 *
 *      If spec is NULL or if no old entry exists, then we just defrag the node.
 *-----------------------------------------------------------------------------
 */
void
btree_defragment_leaf(const btree_config    *cfg, // IN
                      btree_scratch         *scratch,
                      btree_hdr             *hdr,
                      leaf_incorporate_spec *spec) // IN/OUT
{
   btree_hdr *scratch_hdr = (btree_hdr *)scratch->defragment_node.scratch_node;
   memcpy(scratch_hdr, hdr, btree_page_size(cfg));
   btree_reset_node_entries(cfg, hdr);
   uint64 dst_idx = 0;
   for (int64 i = 0; i < btree_num_entries(scratch_hdr); i++) {
      if (spec && spec->old_entry_state == ENTRY_STILL_EXISTS && spec->idx == i)
      {
         spec->old_entry_state = ENTRY_HAS_BEEN_REMOVED;
      } else {
         leaf_entry     *entry = btree_get_leaf_entry(cfg, scratch_hdr, i);
         debug_only bool success =
            btree_set_leaf_entry(cfg,
                                 hdr,
                                 dst_idx++,
                                 leaf_entry_key_slice(entry),
                                 leaf_entry_message(entry));
         debug_assert(success);
      }
   }
}

static inline void
btree_truncate_leaf(const btree_config *cfg, // IN
                    btree_hdr          *hdr, // IN
                    uint64              target_entries)   // IN
{
   uint64 new_next_entry = btree_page_size(cfg);

   for (uint64 i = 0; i < target_entries; i++) {
      if (hdr->offsets[i] < new_next_entry)
         new_next_entry = hdr->offsets[i];
   }

   hdr->num_entries = target_entries;
   hdr->next_entry  = new_next_entry;
}

/*
 *-----------------------------------------------------------------------------
 * btree_split_leaf --
 *
 *      Splits the node at left_addr into a new node at right_addr.
 *
 *      Assumes write lock on both nodes.
 *-----------------------------------------------------------------------------
 */

static leaf_splitting_plan initial_plan = {0, FALSE};


static bool
most_of_entry_is_on_left_side(uint64 total_bytes,
                              uint64 left_bytes,
                              uint64 entry_size)
{
   return left_bytes + sizeof(table_entry) + entry_size
          < (total_bytes + sizeof(table_entry) + entry_size) / 2;
}

/* Figure out how many entries we can put on the left side.
 * Basically, we split the node as evenly as possible by bytes.
 * The old node had total_bytes of entries (and table entries).
 * The new nodes will have as close as possible to total_bytes / 2 bytes.
 * We iterate over each entry and, if most of its bytes fall on
 * left side of total_bytes / 2, then we can put it on the left side.
 *
 * Note that the loop is split into two (see build_leaf_splitting_plan)
 * so we can handle the entry for the key being inserted specially.
 * Specifically, if the key being inserted replaces an existing key,
 * then we need to skip over the entry for the existing key.
 */
static uint64
plan_move_more_entries_to_left(const btree_config  *cfg,
                               const btree_hdr     *hdr,
                               uint64               max_entries,
                               uint64               total_bytes,
                               uint64               left_bytes,
                               leaf_splitting_plan *plan) // IN/OUT
{
   leaf_entry *entry;
   while (plan->split_idx < max_entries
          && (entry = btree_get_leaf_entry(cfg, hdr, plan->split_idx))
          && most_of_entry_is_on_left_side(
             total_bytes, left_bytes, sizeof_leaf_entry(entry)))
   {
      left_bytes += sizeof(table_entry) + sizeof_leaf_entry(entry);
      plan->split_idx++;
   }
   return left_bytes;
}

/*
 * Choose a splitting point so that we are guaranteed to be able to
 * insert the given key-message pair into the correct node after the
 * split. Assumes all leaf entries are at most half the total free
 * space in an empty leaf.
 */
leaf_splitting_plan
btree_build_leaf_splitting_plan(const btree_config          *cfg, // IN
                                const btree_hdr             *hdr,
                                const leaf_incorporate_spec *spec) // IN
{
   /* Split the content by bytes -- roughly half the bytes go to the
      right node.  So count the bytes, including the new entry to be
      inserted. */
   uint64 num_entries = btree_num_entries(hdr);
   uint64 entry_size  = leaf_entry_size(spec->key, spec_message(spec));
   uint64 total_bytes = entry_size;

   for (uint64 i = 0; i < num_entries; i++) {
      if (i != spec->idx || spec->old_entry_state != ENTRY_STILL_EXISTS) {
         leaf_entry *entry = btree_get_leaf_entry(cfg, hdr, i);
         total_bytes += sizeof_leaf_entry(entry);
      }
   }
   uint64 new_num_entries = num_entries;
   new_num_entries += spec->old_entry_state == ENTRY_STILL_EXISTS ? 0 : 1;
   total_bytes += new_num_entries * sizeof(table_entry);

   /* Now figure out the number of entries to move, and figure out how
      much free space will be created in the left_hdr by the split. */
   uint64              left_bytes = 0;
   leaf_splitting_plan plan       = initial_plan;

   /* Figure out how many of the items to the left of spec.idx can be
      put into the left node. */
   left_bytes = plan_move_more_entries_to_left(
      cfg, hdr, spec->idx, total_bytes, left_bytes, &plan);

   /* Figure out whether our new entry can go into the left node.  If it
      can't, then no subsequent entries can, either, so we're done. */
   if (plan.split_idx == spec->idx
       && most_of_entry_is_on_left_side(total_bytes, left_bytes, entry_size))
   {
      left_bytes += sizeof(table_entry) + entry_size;
      plan.insertion_goes_left = TRUE;
   } else {
      return plan;
   }
   if (spec->old_entry_state == ENTRY_STILL_EXISTS) {
      /* If our new entry is replacing an existing entry, then skip
         that entry in our planning. */
      plan.split_idx++;
   }

   /* Figure out how many more entries after spec.idx can go into the
      left node. */
   plan_move_more_entries_to_left(
      cfg, hdr, num_entries, total_bytes, left_bytes, &plan);

   return plan;
}

static inline slice
btree_splitting_pivot(const btree_config          *cfg, // IN
                      const btree_hdr             *hdr,
                      const leaf_incorporate_spec *spec,
                      leaf_splitting_plan          plan)
{
   if (plan.split_idx == spec->idx
       && spec->old_entry_state != ENTRY_STILL_EXISTS
       && !plan.insertion_goes_left)
   {
      return spec->key;
   } else {
      return btree_get_tuple_key(cfg, hdr, plan.split_idx);
   }
}

static inline void
btree_split_leaf_build_right_node(const btree_config    *cfg,      // IN
                                  const btree_hdr       *left_hdr, // IN
                                  leaf_incorporate_spec *spec,     // IN
                                  leaf_splitting_plan    plan,     // IN
                                  btree_hdr             *right_hdr,
                                  uint64                *generation) // IN/OUT
{
   /* Build the right node. */
   memmove(right_hdr, left_hdr, sizeof(*right_hdr));
   right_hdr->generation++;
   btree_reset_node_entries(cfg, right_hdr);
   uint64 num_left_entries = btree_num_entries(left_hdr);
   uint64 dst_idx          = 0;
   for (uint64 i = plan.split_idx; i < num_left_entries; i++) {
      if (spec->old_entry_state == ENTRY_STILL_EXISTS && i == spec->idx) {
         spec->old_entry_state = ENTRY_HAS_BEEN_REMOVED;
      } else {
         leaf_entry *entry = btree_get_leaf_entry(cfg, left_hdr, i);
         btree_set_leaf_entry(cfg,
                              right_hdr,
                              dst_idx,
                              leaf_entry_key_slice(entry),
                              leaf_entry_message(entry));
         dst_idx++;
      }
   }

   if (!plan.insertion_goes_left) {
      spec->idx -= plan.split_idx;
      bool incorporated = btree_try_perform_leaf_incorporate_spec(
         cfg, right_hdr, spec, generation);
      platform_assert(incorporated);
   }
}

static inline void
btree_split_leaf_cleanup_left_node(const btree_config    *cfg, // IN
                                   btree_scratch         *scratch,
                                   btree_hdr             *left_hdr, // IN
                                   leaf_incorporate_spec *spec,     // IN
                                   leaf_splitting_plan    plan,
                                   uint64                 right_addr) // IN
{
   left_hdr->next_ref.addr = right_addr;
   btree_truncate_leaf(cfg, left_hdr, plan.split_idx);
   left_hdr->generation++;
   if (plan.insertion_goes_left
       && !btree_can_perform_leaf_incorporate_spec(cfg, left_hdr, spec))
   {
      btree_defragment_leaf(cfg, scratch, left_hdr, spec);
   }
}

/*
 *-----------------------------------------------------------------------------
 * btree_split_index --
 *
 *      Splits the node at left_addr into a new node at right_addr.
 *
 *      Assumes write lock on both nodes.
 *-----------------------------------------------------------------------------
 */
static inline bool
btree_index_is_full(const btree_config *cfg, // IN
                    const btree_hdr    *hdr)    // IN
{
   return hdr->next_entry < diff_ptr(hdr, &hdr->offsets[hdr->num_entries + 2])
                               + sizeof(index_entry) + MAX_INLINE_KEY_SIZE;
}

static inline uint64
btree_choose_index_split(const btree_config *cfg, // IN
                         const btree_hdr    *hdr)    // IN
{
   /* Split the content by bytes -- roughly half the bytes go to the
      right node.  So count the bytes. */
   uint64 total_entry_bytes = 0;
   for (uint64 i = 0; i < btree_num_entries(hdr); i++) {
      index_entry *entry = btree_get_index_entry(cfg, hdr, i);
      total_entry_bytes += sizeof_index_entry(entry);
   }

   /* Now figure out the number of entries to move, and figure out how
      much free space will be created in the left_hdr by the split. */
   uint64 target_left_entries  = 0;
   uint64 new_left_entry_bytes = 0;
   while (new_left_entry_bytes < total_entry_bytes / 2) {
      index_entry *entry = btree_get_index_entry(cfg, hdr, target_left_entries);
      new_left_entry_bytes += sizeof_index_entry(entry);
      target_left_entries++;
   }
   return target_left_entries;
}

static inline void
btree_split_index_build_right_node(const btree_config *cfg,        // IN
                                   const btree_hdr    *left_hdr,   // IN
                                   uint64     target_left_entries, // IN
                                   btree_hdr *right_hdr)           // IN/OUT
{
   uint64 target_right_entries =
      btree_num_entries(left_hdr) - target_left_entries;

   /* Build the right node. */
   memmove(right_hdr, left_hdr, sizeof(*right_hdr));
   right_hdr->generation++;
   btree_reset_node_entries(cfg, right_hdr);
   for (uint64 i = 0; i < target_right_entries; i++) {
      index_entry *entry =
         btree_get_index_entry(cfg, left_hdr, target_left_entries + i);
      bool succeeded =
         btree_set_index_entry(cfg,
                               right_hdr,
                               i,
                               index_entry_key_slice(entry),
                               index_entry_child_ref(entry).addr,
                               entry->pivot_data.num_kvs_in_subtree,
                               entry->pivot_data.key_bytes_in_subtree,
                               entry->pivot_data.message_bytes_in_subtree);
      platform_assert(succeeded);
   }
}

/*
 *-----------------------------------------------------------------------------
 * btree_defragment_index --
 *
 *      Defragment a node
 *-----------------------------------------------------------------------------
 */
void
btree_defragment_index(const btree_config *cfg, // IN
                       btree_scratch      *scratch,
                       btree_hdr          *hdr) // IN
{
   btree_hdr *scratch_hdr = (btree_hdr *)scratch->defragment_node.scratch_node;
   memcpy(scratch_hdr, hdr, btree_page_size(cfg));
   btree_reset_node_entries(cfg, hdr);
   for (uint64 i = 0; i < btree_num_entries(scratch_hdr); i++) {
      index_entry *entry = btree_get_index_entry(cfg, scratch_hdr, i);
      bool         succeeded =
         btree_set_index_entry(cfg,
                               hdr,
                               i,
                               index_entry_key_slice(entry),
                               index_entry_child_ref(entry).addr,
                               entry->pivot_data.num_kvs_in_subtree,
                               entry->pivot_data.key_bytes_in_subtree,
                               entry->pivot_data.message_bytes_in_subtree);
      platform_assert(succeeded);
   }
}

static inline void
btree_truncate_index(const btree_config *cfg, // IN
                     btree_scratch      *scratch,
                     btree_hdr          *hdr, // IN
                     uint64              target_entries)   // IN
{
   uint64 new_next_entry = btree_page_size(cfg);
   for (uint64 i = 0; i < target_entries; i++) {
      if (hdr->offsets[i] < new_next_entry) {
         new_next_entry = hdr->offsets[i];
      }
   }

   hdr->num_entries = target_entries;
   hdr->next_entry  = new_next_entry;
   hdr->generation++;

   if (new_next_entry < BTREE_DEFRAGMENT_THRESHOLD(btree_page_size(cfg))) {
      btree_defragment_index(cfg, scratch, hdr);
   }
}

/*
 *-----------------------------------------------------------------------------
 * btree_alloc --
 *
 *      Allocates a node from the preallocator. Will refill it if there are no
 *      more nodes available for the given height.
 *-----------------------------------------------------------------------------
 */
bool
btree_alloc(cache          *cc,
            mini_allocator *mini,
            uint64          height,
            slice           key,
            uint64         *next_extent,
            page_type       type,
            btree_node     *node)
{
   node->ref.addr = mini_alloc(mini, height, key, next_extent);
   debug_assert(node->ref.addr != 0);
   node->page = cache_alloc(cc, node->ref.addr, type);
   // If this btree is for a memetable
   // then pin all pages belong to it
   if (type == PAGE_TYPE_MEMTABLE) {
      cache_pin(cc, node->page);
   }
   node->hdr = (btree_hdr *)(node->page->data);
   platform_assert(node->ref.addr == node->page->disk_addr);
   return TRUE;
}

/*
 *-----------------------------------------------------------------------------
 * btree_node_[get,release] --
 *
 *      Gets the node with appropriate lock or releases the lock.
 *-----------------------------------------------------------------------------
 */
static inline void
btree_node_get(cache              *cc,
               const btree_config *cfg,
               btree_node         *node,
               page_type           type,
               bool *              succeed)
{
   debug_assert(node->ref.addr != 0);
   node->page = cache_get(cc, &node->ref, TRUE, type, succeed);
   node->hdr  = (btree_hdr *)(node->page->data);
}

static inline void
btree_node_get_no_auth(cache              *cc,
                       const btree_config *cfg,
                       btree_node         *node,
                       page_type           type,
                       bool *              succeed)
{
   debug_assert(node->ref.addr != 0);
   node->page = cache_get_no_auth(cc, &node->ref, TRUE, type);
   node->hdr  = (btree_hdr *)(node->page->data);
}

static inline bool
btree_node_claim(cache              *cc,  // IN
                 const btree_config *cfg, // IN
                 btree_node         *node)        // IN
{
   return cache_claim(cc, node->page);
}

static inline void
btree_node_lock(cache              *cc,  // IN
                const btree_config *cfg, // IN
                btree_node         *node)        // IN
{
   cache_lock(cc, node->page);
   cache_mark_dirty(cc, node->page);
}

static inline void
btree_node_unlock_dynamic(cache              *cc,   // IN
                          const btree_config *cfg,  // IN
                          btree_node         *node) // IN
{
   cache_unlock(cc, node->page);
}

static inline void
btree_verify_child(cache *cc, const btree_config *cfg, btree_node *node)
{
   int height = btree_height(node->hdr);
   if (height > 0) {
      uint64 nentries   = btree_num_entries(node->hdr);
      int i = 0;
      for (i = 0; i < nentries; i++) {
         page_reference child_ref = btree_get_child_ref(cfg, node->hdr, i);
         btree_node child;
         child.ref = child_ref;
         btree_node_get(cc, cfg, &child, PAGE_TYPE_BRANCH, NULL);
         btree_node_unget(cc, cfg, &child);
      }
   }
}

// XXX: we should take advantage of the argument `ref`
// and put the calculated hash in ref directly to reduce memory copy
static inline void
btree_node_unlock(cache              *cc,   // IN
                  const btree_config *cfg,  // IN
                  btree_node         *node, // IN
                  int line,                 // IN
                  page_reference     *ref)  // OUT
{
   platform_assert(node->ref.addr == node->page->disk_addr);
   // 1. calculate the hash and store the hash in clockcache_entry->sig
   // platform_default_log("%s: node->page->disk_addr=%ld, tid=%ld\n", __func__, node->page->disk_addr, platform_get_tid());
   cache_hash(cc, node->page, node->ref.addr);
   // 2. copy the hash from clockcache_entry->sig to node->ref.hash
   memcpy(node->ref.hash, cache_get_page_hash(cc, node->page), HASH_SIZE);
#ifdef AUTH_DEBUG
   btree_verify_child(cc, cfg, node);
#endif
   cache_unlock(cc, node->page);
}

static inline void
btree_node_unclaim(cache              *cc,  // IN
                   const btree_config *cfg, // IN
                   btree_node         *node)        // IN
{
   cache_unclaim(cc, node->page);
}

void
btree_node_unget(cache              *cc,  // IN
                 const btree_config *cfg, // IN
                 btree_node         *node)        // IN
{
   cache_unget(cc, node->page);
   node->page = NULL;
   node->hdr  = NULL;
}

static inline void
btree_node_full_unlock_dynamic(cache              *cc,   // IN
                               const btree_config *cfg,  // IN
                               btree_node         *node) // IN
{
   btree_node_unlock_dynamic(cc, cfg, node);
   btree_node_unclaim(cc, cfg, node);
   btree_node_unget(cc, cfg, node);
}

static inline void
btree_node_full_unlock(cache              *cc,   // IN
                       const btree_config *cfg,  // IN
                       btree_node         *node, // IN
                       page_reference *ref, int line)      // OUT
{
#ifdef AUTH_DEBUG
   int r = mprotect(node->page->data, 4096, PROT_READ);
   platform_assert(r == 0);
#endif
   btree_node_unlock(cc, cfg, node, line, ref);
   btree_node_unclaim(cc, cfg, node);
   btree_node_unget(cc, cfg, node);
}

static inline void
btree_node_get_from_cache_ctxt(const btree_config *cfg,  // IN
                               cache_async_ctxt   *ctxt, // IN
                               btree_node         *node)         // OUT
{
   node->ref.addr = ctxt->page->disk_addr;
   node->page = ctxt->page;
   node->hdr  = (btree_hdr *)node->page->data;
}


static inline bool
btree_addrs_share_extent(const btree_config *cfg,
                         uint64              left_addr,
                         uint64              right_addr)
{
   return cache_config_pages_share_extent(
      cfg->cache_cfg, right_addr, left_addr);
}

static inline uint64
btree_get_extent_base_addr(const btree_config *cfg, btree_node *node)
{
   return cache_config_extent_base_addr(cfg->cache_cfg, node->ref.addr);
}

static inline uint64
btree_root_to_meta_addr(const btree_config *cfg,
                        uint64              root_addr,
                        uint64              meta_page_no)
{
   return root_addr + (meta_page_no + 1) * btree_page_size(cfg);
}


/*----------------------------------------------------------
 * Creating and destroying B-trees.
 *----------------------------------------------------------
 */


page_reference
btree_create(cache              *cc,
             const btree_config *cfg,
             mini_allocator     *mini,
             page_type           type)
{
   // get a free node for the root
   // we don't use the next_addr arr for this, since the root doesn't
   // maintain constant height
   allocator      *al = cache_allocator(cc);
   uint64          base_addr;
   platform_status rc = allocator_alloc(al, &base_addr, type);
   platform_assert_status_ok(rc);
   page_handle *root_page = cache_alloc(cc, base_addr, type);
   bool         pinned    = (type == PAGE_TYPE_MEMTABLE);

   // set up the root
   btree_node root;
   root.page = root_page;
   root.ref.addr = base_addr;
   root.hdr  = (btree_hdr *)root_page->data;

   btree_init_hdr(cfg, root.hdr);

   cache_mark_dirty(cc, root.page);

   // If this btree is for a memetable
   // then pin all pages belong to it
   if (pinned) {
      cache_pin(cc, root.page);
   }

   // calculate the hash and store it in `root.ref`
   cache_hash(cc, root_page, root_page->disk_addr);
   memcpy(root.ref.hash, cache_get_page_hash(cc, root_page), HASH_SIZE);
   // release root
   cache_unlock(cc, root_page);
   cache_unclaim(cc, root_page);
   cache_unget(cc, root_page);

   // set up the mini allocator
   mini_init(mini,
             cc,
             cfg->data_cfg,
             root.ref.addr + btree_page_size(cfg),
             0,
             BTREE_MAX_HEIGHT,
             type,
             type == PAGE_TYPE_BRANCH);

   return root.ref;
}

void
btree_inc_ref_range(cache              *cc,
                    const btree_config *cfg,
                    uint64              root_addr,
                    const slice         start_key,
                    const slice         end_key)
{
   uint64 meta_page_addr = btree_root_to_meta_addr(cfg, root_addr, 0);
   if (!slice_is_null(start_key) && !slice_is_null(end_key)) {
      debug_assert(btree_key_compare(cfg, start_key, end_key) < 0);
   }
   mini_keyed_inc_ref(
      cc, cfg->data_cfg, PAGE_TYPE_BRANCH, meta_page_addr, start_key, end_key);

   //platform_default_log("============ Print btree_ref count start ============\n");
   //mini_keyed_print(cc, cfg->data_cfg, meta_page_addr, PAGE_TYPE_BRANCH);
   //platform_default_log("============ Print btree_ref count end ============\n");
}

void
btree_print_ref(cache              *cc,
                const btree_config *cfg,
                uint64              root_addr,
                const slice         start_key,
                const slice         end_key)
{
}

bool
btree_dec_ref_range(cache              *cc,
                    const btree_config *cfg,
                    uint64              root_addr,
                    const slice         start_key,
                    const slice         end_key,
                    page_type           type)
{
   debug_assert(type == PAGE_TYPE_BRANCH);

   if (!slice_is_null(start_key) && !slice_is_null(end_key)) {
      platform_assert(btree_key_compare(cfg, start_key, end_key) < 0);
   }

   uint64 meta_page_addr = btree_root_to_meta_addr(cfg, root_addr, 0);

   //platform_default_log("============ Print btree_ref count start ============\n");
   //mini_keyed_print(cc, cfg->data_cfg, meta_page_addr, PAGE_TYPE_BRANCH);
   //platform_default_log("============ Print btree_ref count end ============\n");

   bool ret = mini_keyed_dec_ref(
      cc, cfg->data_cfg, PAGE_TYPE_BRANCH, meta_page_addr, start_key, end_key);

   return ret;
}

bool
btree_dec_ref(cache              *cc,
              const btree_config *cfg,
              uint64              root_addr,
              page_type           type)
{
   platform_assert(type == PAGE_TYPE_MEMTABLE);
   uint64 meta_head = btree_root_to_meta_addr(cfg, root_addr, 0);
   uint8  ref       = mini_unkeyed_dec_ref(cc, meta_head, type, TRUE);
   return ref == 0;
}

void
btree_block_dec_ref(cache *cc, btree_config *cfg, uint64 root_addr)
{
   uint64 meta_head = btree_root_to_meta_addr(cfg, root_addr, 0);
   mini_block_dec_ref(cc, meta_head);
}

void
btree_unblock_dec_ref(cache *cc, btree_config *cfg, uint64 root_addr)
{
   uint64 meta_head = btree_root_to_meta_addr(cfg, root_addr, 0);
   mini_unblock_dec_ref(cc, meta_head);
}

/**********************************************************************
 * The process of splitting a child leaf is divided into four steps in
 * order to minimize the amount of time that we hold write-locks on
 * the parent and child:
 *
 * 0. Start with claims on parent and child.
 *
 * 1. Allocate a node for the right child.  Hold a write lock on the
 *    new node.
 *
 * 2. btree_add_pivot.  Insert a new pivot in the parent for
 *    the new child.  This step requires a write-lock on the parent.
 *    The parent can be completely unlocked as soon as this step is
 *    complete.
 *
 * 3. btree_split_{leaf,index}_build_right_node
 *    Fill in the contents of the right child.  No lock on parent
 *    required.
 *
 * 4. btree_truncate_{leaf,index}
 *    Truncate (and optionally defragment) the old child.  This is the
 *    only step that requires a write-lock on the old child.
 *
 * Note: if we wanted to maintain rank information in the parent when
 * splitting one of its children, we could do that by holding the lock
 * on the parent a bit longer.  But we don't need that in the
 * memtable, so not bothering for now.
 */

/* Requires:
   - claim on parent
   - claim on child
   Upon completion:
   - all nodes unlocked
   - the insertion is complete
*/
static inline int
btree_split_child_leaf(cache                 *cc,
                       const btree_config    *cfg,
                       mini_allocator        *mini,
                       btree_scratch         *scratch,
                       btree_node            *parent,
                       uint64                 index_of_child_in_parent,
                       btree_node            *child,
                       leaf_incorporate_spec *spec,
                       uint64                *generation) // OUT
{
   btree_node right_child;

   /* p: claim, c: claim, rc: - */

   leaf_splitting_plan plan =
      btree_build_leaf_splitting_plan(cfg, child->hdr, spec);

   /* p: claim, c: claim, rc: - */

   btree_alloc(cc,
               mini,
               btree_height(child->hdr),
               NULL_SLICE,
               NULL,
#ifdef SGX_TEST
               PAGE_TYPE_BRANCH,
#else
               PAGE_TYPE_MEMTABLE,
#endif
               &right_child);

   /* p: claim, c: claim, rc: write */

   btree_node_lock(cc, cfg, parent);
   {
      /* limit the scope of pivot_key, since subsequent mutations of the nodes
       * may invalidate the memory it points to. */
      slice pivot_key = btree_splitting_pivot(cfg, child->hdr, spec, plan);
      bool  success   = btree_insert_index_entry(cfg,
                                              parent->hdr,
                                              index_of_child_in_parent + 1,
                                              pivot_key,
                                              right_child.ref.addr,
                                              BTREE_UNKNOWN_COUNTER,
                                              BTREE_UNKNOWN_COUNTER,
                                              BTREE_UNKNOWN_COUNTER);
      platform_assert(success);
   }
   btree_node_full_unlock_dynamic(cc, cfg, parent);

   /* p: fully unlocked, c: claim, rc: write */

   btree_split_leaf_build_right_node(
      cfg, child->hdr, spec, plan, right_child.hdr, generation);

   /* p: fully unlocked, c: claim, rc: write */

   btree_node_full_unlock_dynamic(cc, cfg, &right_child);

   /* p: fully unlocked, c: claim, rc: fully unlocked */

   btree_node_lock(cc, cfg, child);
   btree_split_leaf_cleanup_left_node(
      cfg, scratch, child->hdr, spec, plan, right_child.ref.addr);
   if (plan.insertion_goes_left) {
      bool incorporated = btree_try_perform_leaf_incorporate_spec(
         cfg, child->hdr, spec, generation);
      platform_assert(incorporated);
   }
   btree_node_full_unlock_dynamic(cc, cfg, child);

   /* p: fully unlocked, c: fully unlocked, rc: fully unlocked */

   return 0;
}

/* Requires:
   - claim on parent
   - claim on child
   Upon completion:
   - all nodes fully unlocked
   - insertion is complete
*/
static inline int
btree_defragment_or_split_child_leaf(cache              *cc,
                                     const btree_config *cfg,
                                     mini_allocator     *mini,
                                     btree_scratch      *scratch,
                                     btree_node         *parent,
                                     uint64      index_of_child_in_parent,
                                     btree_node *child,
                                     leaf_incorporate_spec *spec,
                                     uint64                *generation) // OUT
{
   uint64 nentries   = btree_num_entries(child->hdr);
   uint64 live_bytes = 0;

   log_trace_leaf(cfg, child->hdr, "btree_defragment_or_split_child_leaf");

   for (uint64 i = 0; i < nentries; i++) {
      if (spec->old_entry_state != ENTRY_STILL_EXISTS || i != spec->idx) {
         leaf_entry *entry = btree_get_leaf_entry(cfg, child->hdr, i);
         live_bytes += sizeof_leaf_entry(entry);
      }
   }
   uint64 total_space_required =
      live_bytes + leaf_entry_size(spec->key, spec_message(spec))
      + (nentries + spec->old_entry_state == ENTRY_STILL_EXISTS ? 0 : 1)
           * sizeof(index_entry);

   if (total_space_required < BTREE_SPLIT_THRESHOLD(btree_page_size(cfg))) {
      btree_node_unclaim(cc, cfg, parent);
      btree_node_unget(cc, cfg, parent);
      btree_node_lock(cc, cfg, child);
      btree_defragment_leaf(cfg, scratch, child->hdr, spec);
      bool incorporated = btree_try_perform_leaf_incorporate_spec(
         cfg, child->hdr, spec, generation);
      platform_assert(incorporated);
      btree_node_full_unlock_dynamic(cc, cfg, child);
   } else {
      btree_split_child_leaf(cc,
                             cfg,
                             mini,
                             scratch,
                             parent,
                             index_of_child_in_parent,
                             child,
                             spec,
                             generation);
   }

   return 0;
}

/*
 * Splitting a child index follows a similar pattern as splitting a child leaf.
 * The main difference is that we assume we start with write-locks on the parent
 *  and child (which fits better with the flow of the overall insert algorithm).
 */

/* Requires:
   - lock on parent
   - lock on child
   Upon completion:
   - lock on new_child
   - all other nodes unlocked
*/
static inline int
btree_split_child_index(cache              *cc,
                        const btree_config *cfg,
                        mini_allocator     *mini,
                        btree_scratch      *scratch,
                        btree_node         *parent,
                        uint64              index_of_child_in_parent,
                        btree_node         *child,
                        const slice         key_to_be_inserted,
                        btree_node         *new_child, // OUT
                        int64              *next_child_idx)         // IN/OUT
{
   btree_node right_child;

   /* p: lock, c: lock, rc: - */

   uint64 idx = btree_choose_index_split(cfg, child->hdr);

   /* p: lock, c: lock, rc: - */

   btree_alloc(cc,
               mini,
               btree_height(child->hdr),
               NULL_SLICE,
               NULL,
#ifdef SGX_TEST
               PAGE_TYPE_BRANCH,
#else
               PAGE_TYPE_MEMTABLE,
#endif
               &right_child);

   /* p: lock, c: lock, rc: lock */

   {
      /* limit the scope of pivot_key, since subsequent mutations of the nodes
       * may invalidate the memory it points to. */
      slice pivot_key = btree_get_pivot(cfg, child->hdr, idx);
      btree_insert_index_entry(cfg,
                               parent->hdr,
                               index_of_child_in_parent + 1,
                               pivot_key,
                               right_child.ref.addr,
                               BTREE_UNKNOWN_COUNTER,
                               BTREE_UNKNOWN_COUNTER,
                               BTREE_UNKNOWN_COUNTER);
   }
   btree_node_full_unlock_dynamic(cc, cfg, parent);

   /* p: -, c: lock, rc: lock */

   if (*next_child_idx < idx) {
      *new_child = *child;
   } else {
      *new_child = right_child;
      *next_child_idx -= idx;
   }

   btree_split_index_build_right_node(cfg, child->hdr, idx, right_child.hdr);

   /* p: -, c: lock, rc: lock */

   if (new_child->ref.addr != right_child.ref.addr) {
      btree_node_full_unlock_dynamic(cc, cfg, &right_child);
   }

   /* p: -, c: lock, rc: if nc == rc then lock else fully unlocked */

   btree_truncate_index(cfg, scratch, child->hdr, idx);

   /* p: -, c: lock, rc: if nc == rc then lock else fully unlocked */

   if (new_child->ref.addr != child->ref.addr) {
      btree_node_full_unlock_dynamic(cc, cfg, child);
   }

   /* p:  -,
      c:  if nc == c  then locked else fully unlocked
      rc: if nc == rc then locked else fully unlocked */

   return 0;
}

/* Requires:
   - lock on parent
   - lock on child
   Upon completion:
   - lock on new_child
   - all other nodes unlocked
*/
static inline int
btree_defragment_or_split_child_index(cache              *cc,
                                      const btree_config *cfg,
                                      mini_allocator     *mini,
                                      btree_scratch      *scratch,
                                      btree_node         *parent,
                                      uint64      index_of_child_in_parent,
                                      btree_node *child,
                                      const slice key_to_be_inserted,
                                      btree_node *new_child, // OUT
                                      int64      *next_child_idx) // IN/OUT
{
   uint64 nentries   = btree_num_entries(child->hdr);
   uint64 live_bytes = 0;
   for (uint64 i = 0; i < nentries; i++) {
      index_entry *entry = btree_get_index_entry(cfg, child->hdr, i);
      live_bytes += sizeof_index_entry(entry);
   }
   uint64 total_space_required = live_bytes + nentries * sizeof(index_entry);

   if (total_space_required < BTREE_SPLIT_THRESHOLD(btree_page_size(cfg))) {
      btree_node_full_unlock_dynamic(cc, cfg, parent);
      btree_defragment_index(cfg, scratch, child->hdr);
      *new_child = *child;
   } else {
      btree_split_child_index(cc,
                              cfg,
                              mini,
                              scratch,
                              parent,
                              index_of_child_in_parent,
                              child,
                              key_to_be_inserted,
                              new_child,
                              next_child_idx);
   }

   return 0;
}


static inline uint64
add_possibly_unknown(uint32 a, int32 b)
{
   if (a != BTREE_UNKNOWN_COUNTER && b != BTREE_UNKNOWN_COUNTER) {
      return a + b;
   } else {
      return BTREE_UNKNOWN_COUNTER;
   }
}

static inline void
accumulate_node_ranks(const btree_config *cfg,
                      const btree_hdr    *hdr,
                      int                 from,
                      int                 to,
                      uint32             *num_kvs,
                      uint32             *key_bytes,
                      uint32             *message_bytes)
{
   debug_assert(from <= to);
   if (btree_height(hdr) == 0) {
      for (int i = from; i < to; i++) {
         leaf_entry *entry = btree_get_leaf_entry(cfg, hdr, i);
         *key_bytes =
            add_possibly_unknown(*key_bytes, leaf_entry_key_size(entry));
         *message_bytes = add_possibly_unknown(*message_bytes,
                                               leaf_entry_message_size(entry));
      }
      *num_kvs += to - from;
   } else {
      for (int i = from; i < to; i++) {
         index_entry *entry = btree_get_index_entry(cfg, hdr, i);

         *num_kvs   = add_possibly_unknown(*num_kvs,
                                         entry->pivot_data.num_kvs_in_subtree);
         *key_bytes = add_possibly_unknown(
            *key_bytes, entry->pivot_data.key_bytes_in_subtree);
         *message_bytes = add_possibly_unknown(
            *message_bytes, entry->pivot_data.message_bytes_in_subtree);
      }
   }
}

/*
 *-----------------------------------------------------------------------------
 * btree_grow_root --
 *
 *      Adds a new root above the root.
 *
 * Requires: lock on root_node
 *
 * Upon return:
 * - root is locked
 *-----------------------------------------------------------------------------
 */
static inline int
btree_grow_root(cache              *cc,   // IN
                const btree_config *cfg,  // IN
                mini_allocator     *mini, // IN/OUT
                btree_node         *root_node)    // OUT
{
   // allocate a new left node
   btree_node child;
   btree_alloc(cc,
               mini,
               btree_height(root_node->hdr),
               NULL_SLICE,
               NULL,
#ifdef SGX_TEST
               PAGE_TYPE_BRANCH,
#else
               PAGE_TYPE_MEMTABLE,
#endif
               &child);

   // copy root to child
   memmove(child.hdr, root_node->hdr, btree_page_size(cfg));
   btree_node_unlock_dynamic(cc, cfg, &child);
   btree_node_unclaim(cc, cfg, &child);

   btree_reset_node_entries(cfg, root_node->hdr);
   btree_increment_height(root_node->hdr);
   slice new_pivot;
   if (btree_height(child.hdr) == 0) {
      new_pivot = btree_get_tuple_key(cfg, child.hdr, 0);
   } else {
      new_pivot = btree_get_pivot(cfg, child.hdr, 0);
   }
   bool succeeded = btree_set_index_entry(cfg,
                                          root_node->hdr,
                                          0,
                                          new_pivot,
                                          child.ref.addr,
                                          BTREE_UNKNOWN_COUNTER,
                                          BTREE_UNKNOWN_COUNTER,
                                          BTREE_UNKNOWN_COUNTER);
   platform_assert(succeeded);

   btree_node_unget(cc, cfg, &child);
   return 0;
}

/*
 *-----------------------------------------------------------------------------
 * btree_insert --
 *
 *      Inserts the tuple into the dynamic btree.
 *
 *-----------------------------------------------------------------------------
 */
platform_status
btree_insert(cache              *cc,         // IN
             const btree_config *cfg,        // IN
             platform_heap_id    heap_id,    // IN
             btree_scratch      *scratch,    // IN
             uint64              root_addr,  // IN
             mini_allocator     *mini,       // IN
             slice               key,        // IN
             message             msg,        // IN
             uint64             *generation, // OUT
             bool               *was_unique)               // OUT
{
   platform_status       rc;
   leaf_incorporate_spec spec;
   uint64                leaf_wait = 1;

   if (MAX_INLINE_KEY_SIZE < slice_length(key)) {
      return STATUS_BAD_PARAM;
   }

   if (MAX_INLINE_MESSAGE_SIZE < message_length(msg)) {
      return STATUS_BAD_PARAM;
   }

   btree_node root_node;
   root_node.ref.addr = root_addr;

   log_trace_key(key, "btree_insert");

start_over:
#ifdef SGX_TEST
   btree_node_get_no_auth(cc, cfg, &root_node, PAGE_TYPE_BRANCH, NULL);
#else
   btree_node_get(cc, cfg, &root_node, PAGE_TYPE_MEMTABLE, NULL);
#endif
   if (btree_height(root_node.hdr) == 0) {
      rc = btree_create_leaf_incorporate_spec(
         cfg, heap_id, root_node.hdr, key, msg, &spec);
      if (!SUCCESS(rc)) {
         btree_node_unget(cc, cfg, &root_node);
         return rc;
      }
      if (!btree_node_claim(cc, cfg, &root_node)) {
         btree_node_unget(cc, cfg, &root_node);
         destroy_leaf_incorporate_spec(&spec);
         goto start_over;
      }
      btree_node_lock(cc, cfg, &root_node);
      if (btree_try_perform_leaf_incorporate_spec(
             cfg, root_node.hdr, &spec, generation))
      {
         *was_unique = spec.old_entry_state == ENTRY_DID_NOT_EXIST;
         btree_node_full_unlock_dynamic(cc, cfg, &root_node);
         destroy_leaf_incorporate_spec(&spec);
         return STATUS_OK;
      }
      destroy_leaf_incorporate_spec(&spec);
      btree_grow_root(cc, cfg, mini, &root_node);
      btree_node_unlock_dynamic(cc, cfg, &root_node);
      btree_node_unclaim(cc, cfg, &root_node);
   }

   /* read lock on root_node, root_node is an index. */

   bool         found;
   int64        child_idx = btree_find_pivot(cfg, root_node.hdr, key, &found);
   index_entry *parent_entry;

   if (child_idx < 0 || btree_index_is_full(cfg, root_node.hdr)) {
      if (!btree_node_claim(cc, cfg, &root_node)) {
         btree_node_unget(cc, cfg, &root_node);
         goto start_over;
      }
      btree_node_lock(cc, cfg, &root_node);
      bool need_to_set_min_key = FALSE;
      if (child_idx < 0) {
         child_idx           = 0;
         parent_entry        = btree_get_index_entry(cfg, root_node.hdr, 0);
         need_to_set_min_key = !btree_set_index_entry(
            cfg,
            root_node.hdr,
            0,
            key,
            index_entry_child_ref(parent_entry).addr,
            parent_entry->pivot_data.num_kvs_in_subtree,
            parent_entry->pivot_data.key_bytes_in_subtree,
            parent_entry->pivot_data.message_bytes_in_subtree);
      }
      if (btree_index_is_full(cfg, root_node.hdr)) {
         btree_grow_root(cc, cfg, mini, &root_node);
         child_idx = 0;
      }
      if (need_to_set_min_key) {
         parent_entry = btree_get_index_entry(cfg, root_node.hdr, 0);
         bool success = btree_set_index_entry(
            cfg,
            root_node.hdr,
            0,
            key,
            index_entry_child_ref(parent_entry).addr,
            parent_entry->pivot_data.num_kvs_in_subtree,
            parent_entry->pivot_data.key_bytes_in_subtree,
            parent_entry->pivot_data.message_bytes_in_subtree);
         platform_assert(success);
      }
      btree_node_unlock_dynamic(cc, cfg, &root_node);
      btree_node_unclaim(cc, cfg, &root_node);
   }

   parent_entry = btree_get_index_entry(cfg, root_node.hdr, child_idx);

   /* root_node read-locked,
    * root_node is an index,
    * root_node min key is up to date,
    * root_node will not need to split
    */
   btree_node parent_node = root_node;
   btree_node child_node;
   child_node.ref.addr = index_entry_child_ref(parent_entry).addr;
   debug_assert(cache_page_valid(cc, &child_node.ref));
#ifdef SGX_TEST
   btree_node_get_no_auth(cc, cfg, &child_node, PAGE_TYPE_BRANCH, NULL);
#else
   btree_node_get(cc, cfg, &child_node, PAGE_TYPE_MEMTABLE, NULL);
#endif

   uint64 height = btree_height(parent_node.hdr);
   while (height > 1) {
      /* loop invariant:
       * - read lock on parent_node, parent_node is an index, parent_node min
       * key is up to date, and parent_node will not need to split.
       * - read lock on child_node
       * - height >= 1
       */
      int64 next_child_idx = btree_find_pivot(cfg, child_node.hdr, key, &found);
      if (next_child_idx < 0 || btree_index_is_full(cfg, child_node.hdr)) {
         if (!btree_node_claim(cc, cfg, &parent_node)) {
            btree_node_unget(cc, cfg, &parent_node);
            btree_node_unget(cc, cfg, &child_node);
            goto start_over;
         }
         if (!btree_node_claim(cc, cfg, &child_node)) {
            btree_node_unclaim(cc, cfg, &parent_node);
            btree_node_unget(cc, cfg, &parent_node);
            btree_node_unget(cc, cfg, &child_node);
            goto start_over;
         }

         btree_node_lock(cc, cfg, &parent_node);
         btree_node_lock(cc, cfg, &child_node);

         bool need_to_set_min_key = FALSE;
         if (next_child_idx < 0) {
            next_child_idx = 0;
            index_entry *child_entry =
               btree_get_index_entry(cfg, child_node.hdr, next_child_idx);
            need_to_set_min_key = !btree_set_index_entry(
               cfg,
               child_node.hdr,
               0,
               key,
               index_entry_child_ref(child_entry).addr,
               child_entry->pivot_data.num_kvs_in_subtree,
               child_entry->pivot_data.key_bytes_in_subtree,
               child_entry->pivot_data.message_bytes_in_subtree);
         }

         if (btree_index_is_full(cfg, child_node.hdr)) {
            btree_node new_child;
            btree_defragment_or_split_child_index(cc,
                                                  cfg,
                                                  mini,
                                                  scratch,
                                                  &parent_node,
                                                  child_idx,
                                                  &child_node,
                                                  key,
                                                  &new_child,
                                                  &next_child_idx);
            parent_node = new_child;
         } else {
            btree_node_full_unlock_dynamic(cc, cfg, &parent_node);
            parent_node = child_node;
         }

         if (need_to_set_min_key) { // new_child is guaranteed to be child in
                                    // this case
            index_entry *child_entry =
               btree_get_index_entry(cfg, parent_node.hdr, 0);
            bool success = btree_set_index_entry(
               cfg,
               parent_node.hdr,
               0,
               key,
               index_entry_child_ref(child_entry).addr,
               child_entry->pivot_data.num_kvs_in_subtree,
               child_entry->pivot_data.key_bytes_in_subtree,
               child_entry->pivot_data.message_bytes_in_subtree);
            platform_assert(success);
         }
         btree_node_unlock_dynamic(cc, cfg, &parent_node);
         btree_node_unclaim(cc, cfg, &parent_node);
      } else {
         btree_node_unget(cc, cfg, &parent_node);
         parent_node = child_node;
      }

      /* read lock on parent_node, which won't require a split. */

      child_idx    = next_child_idx;
      parent_entry = btree_get_index_entry(cfg, parent_node.hdr, child_idx);
      debug_assert(parent_entry->pivot_data.num_kvs_in_subtree
                   == BTREE_UNKNOWN_COUNTER);
      debug_assert(parent_entry->pivot_data.key_bytes_in_subtree
                   == BTREE_UNKNOWN_COUNTER);
      debug_assert(parent_entry->pivot_data.message_bytes_in_subtree
                   == BTREE_UNKNOWN_COUNTER);
      child_node.ref = index_entry_child_ref(parent_entry);
      debug_assert(cache_page_valid(cc, &child_node.ref));
#ifdef SGX_TEST
      btree_node_get_no_auth(cc, cfg, &child_node, PAGE_TYPE_BRANCH, NULL);
#else
      btree_node_get(cc, cfg, &child_node, PAGE_TYPE_MEMTABLE, NULL);
#endif
      height--;
   }

   /*
    * - read lock on parent_node, parent_node is an index, parent node
    *   min key is up to date, and parent_node will not need to split.
    * - read lock on child_node
    * - height of parent == 1
    */

   rc = btree_create_leaf_incorporate_spec(
      cfg, heap_id, child_node.hdr, key, msg, &spec);
   if (!SUCCESS(rc)) {
      btree_node_unget(cc, cfg, &parent_node);
      btree_node_unget(cc, cfg, &child_node);
      return rc;
   }

   /* If we don't need to split, then let go of the parent and do the
    * insert.  If we can't get a claim on the child, then start
    * over.
    */
   if (btree_can_perform_leaf_incorporate_spec(cfg, child_node.hdr, &spec)) {
      btree_node_unget(cc, cfg, &parent_node);
      if (!btree_node_claim(cc, cfg, &child_node)) {
         btree_node_unget(cc, cfg, &child_node);
         destroy_leaf_incorporate_spec(&spec);
         goto start_over;
      }
      btree_node_lock(cc, cfg, &child_node);
      bool incorporated = btree_try_perform_leaf_incorporate_spec(
         cfg, child_node.hdr, &spec, generation);
      platform_assert(incorporated);
      btree_node_full_unlock_dynamic(cc, cfg, &child_node);
      destroy_leaf_incorporate_spec(&spec);
      *was_unique = spec.old_entry_state == ENTRY_DID_NOT_EXIST;
      return STATUS_OK;
   }

   /* Need to split or defrag the child. */
   if (!btree_node_claim(cc, cfg, &parent_node)) {
      btree_node_unget(cc, cfg, &parent_node);
      btree_node_unget(cc, cfg, &child_node);
      destroy_leaf_incorporate_spec(&spec);
      goto start_over;
   }
   bool need_to_rebuild_spec = FALSE;
   while (!btree_node_claim(cc, cfg, &child_node)) {
      btree_node_unget(cc, cfg, &child_node);
      platform_sleep(leaf_wait);
      leaf_wait = leaf_wait > 2048 ? leaf_wait : 2 * leaf_wait;
#ifdef SGX_TEST
      btree_node_get_no_auth(cc, cfg, &child_node, PAGE_TYPE_BRANCH, NULL);
#else
      btree_node_get(cc, cfg, &child_node, PAGE_TYPE_MEMTABLE, NULL);
#endif
      need_to_rebuild_spec = TRUE;
   }
   if (need_to_rebuild_spec) {
      /* If we had to relenquish our lock, then our spec might be out of date,
       * so rebuild it. */
      destroy_leaf_incorporate_spec(&spec);
      rc = btree_create_leaf_incorporate_spec(
         cfg, heap_id, child_node.hdr, key, msg, &spec);
      if (!SUCCESS(rc)) {
         btree_node_unget(cc, cfg, &parent_node);
         btree_node_unclaim(cc, cfg, &child_node);
         btree_node_unget(cc, cfg, &child_node);
         return rc;
      }
   }
   btree_defragment_or_split_child_leaf(cc,
                                        cfg,
                                        mini,
                                        scratch,
                                        &parent_node,
                                        child_idx,
                                        &child_node,
                                        &spec,
                                        generation);
   destroy_leaf_incorporate_spec(&spec);
   *was_unique = spec.old_entry_state == ENTRY_DID_NOT_EXIST;
   return STATUS_OK;
}


/*
 *-----------------------------------------------------------------------------
 * btree_lookup_path --
 *
 *      lookup_path finds the path to height stop_height with
 *      (node.min_key <= key < node.max_key).  It returns all the
 *      addresses along this path in out_nodes, and all the indexes in out_idxs.
 *      Furthermore, all nodes on this path with height < start_height will be
 *      read-locked on return.
 *
 *      out_rank returns the rank of out_node amount nodes of height
 *      stop_at_height.
 *
 *      If any change is made here, please change
 *      btree_lookup_async_with_ref too.
 *-----------------------------------------------------------------------------
 */
platform_status
btree_lookup_path(
   cache          *cc,           // IN
   btree_config   *cfg,          // IN
   page_reference *root_ref,     // IN
   const slice     key,          // IN
   uint16          start_height, // IN
   uint16          stop_height,  // IN  search down to this height
   page_type       type,         // IN
   btree_node      out_nodes[static BTREE_MAX_HEIGHT], // OUT
   uint64          out_idxs[static BTREE_MAX_HEIGHT],
   uint64          out_invalid_next_extent_addr[static BTREE_MAX_HEIGHT], // out
   uint64         *root_height,  // OUT
   uint32         *kv_rank,      // ranks must be all NULL or all non-NULL
   uint32         *key_byte_rank,
   uint32         *message_byte_rank)
{
   debug_assert(type == PAGE_TYPE_BRANCH || type == PAGE_TYPE_MEMTABLE);

   if (kv_rank) {
      *kv_rank = *key_byte_rank = *message_byte_rank = 0;
   }

   uint32 h;
   {
      // TODO(yizheng.jiao): set up the first out_nodes
      // according to the input argument root_ref
      btree_node node;
      node.ref = *root_ref;
#ifdef SGX_TEST
      btree_node_get_no_auth(cc, cfg, &node, type, NULL);
#else
      btree_node_get(cc, cfg, &node, type, NULL);
#endif
      h            = btree_height(node.hdr);
      out_nodes[h] = node;
      *root_height = h;
      // This means `node` is root of the tree
      if (!node.hdr->next_extent_addr) {
         memcpy(out_invalid_next_extent_addr, node.hdr->invalid_next_extent_addr, sizeof(uint64) * BTREE_MAX_HEIGHT);
      } else {
         // If node is not root, this is out of expectation
         // Need to think off how to handle this.
         // A possible way is to copy the invalid_next_extent_addr from the root
         // When looking up this node. And this doesn't need to be persisted
         // for non-root node
         platform_assert(FALSE);
      }
   }
   while (h > stop_height) {
      bool  found;
      int64 child_idx =
         slices_equal(key, positive_infinity)
            ? btree_num_entries(out_nodes[h].hdr) - 1
            : btree_find_pivot(cfg, out_nodes[h].hdr, key, &found);
      if (child_idx < 0) {
         child_idx = 0;
      }
      out_idxs[h] = child_idx;

      if (kv_rank) {
         accumulate_node_ranks(cfg,
                               out_nodes[h].hdr,
                               0,
                               out_idxs[h],
                               kv_rank,
                               key_byte_rank,
                               message_byte_rank);
      }

      out_nodes[h - 1].ref =
         btree_get_child_ref(cfg, out_nodes[h].hdr, out_idxs[h]);
#ifdef SGX_TEST
      btree_node_get_no_auth(cc, cfg, &out_nodes[h - 1], type, NULL);
#else
      btree_node_get(cc, cfg, &out_nodes[h - 1], type, NULL);
#endif
      debug_assert(out_nodes[h - 1].page->disk_addr == out_nodes[h - 1].ref.addr);
      if (start_height <= h) {
         btree_node_unget(cc, cfg, &out_nodes[h]);
      }

      h--;
   }

   return STATUS_OK;
}

platform_status
btree_lookup_node(cache        *cc,           // IN
                  btree_config *cfg,          // IN
                  page_reference *root_ref,   // IN
                  const slice   key,          // IN
                  uint16      stop_at_height, // IN  search down to this height
                  page_type   type,           // IN
                  btree_node *out_node,       // OUT returns the node of height
                                        // stop_at_height in which key was found
                  uint32 *kv_rank, // ranks must be all NULL or all non-NULL
                  uint32 *key_byte_rank,
                  uint32 *message_byte_rank)
{
   btree_node      out_nodes[BTREE_MAX_HEIGHT];
   uint64          out_idxs[BTREE_MAX_HEIGHT];
   uint64          out_invalid_next_extent_addr[BTREE_MAX_HEIGHT];
   uint64          root_height;
   platform_status rc = btree_lookup_path(cc,
                                          cfg,
                                          root_ref,
                                          key,
                                          stop_at_height + 1,
                                          stop_at_height,
                                          type,
                                          out_nodes,
                                          out_idxs,
                                          out_invalid_next_extent_addr,
                                          &root_height,
                                          kv_rank,
                                          key_byte_rank,
                                          message_byte_rank);
   if (SUCCESS(rc)) {
      *out_node = out_nodes[stop_at_height];
   }
   return rc;
}


static inline void
btree_lookup_with_ref(cache          *cc,        // IN
                      btree_config   *cfg,       // IN
                      page_reference *root_ref,  // IN
                      page_type       type,      // IN
                      const slice     key,       // IN
                      btree_node     *node,      // OUT
                      message        *msg,       // OUT
                      bool           *found)     // OUT
{
   btree_lookup_node(cc, cfg, root_ref, key, 0, type, node, NULL, NULL, NULL);
   int64 idx = btree_find_tuple(cfg, node->hdr, key, found);
   if (*found) {
      leaf_entry *entry = btree_get_leaf_entry(cfg, node->hdr, idx);
      *msg              = leaf_entry_message(entry);
   } else {
      btree_node_unget(cc, cfg, node);
   }
}

platform_status
btree_lookup(cache             *cc,        // IN
             btree_config      *cfg,       // IN
             page_reference    *root_ref, // IN
             page_type          type,      // IN
             const slice        key,       // IN
             merge_accumulator *result)    // OUT
{
   btree_node      node;
   message         data;
   platform_status rc = STATUS_OK;
   bool            local_found;

   btree_lookup_with_ref(
      cc, cfg, root_ref, type, key, &node, &data, &local_found);
   if (local_found) {
      bool success = merge_accumulator_copy_message(result, data);
      rc           = success ? STATUS_OK : STATUS_NO_MEMORY;
      btree_node_unget(cc, cfg, &node);
   }
   return rc;
}

platform_status
btree_lookup_and_merge(cache             *cc,        // IN
                       btree_config      *cfg,       // IN
                       page_reference    *root_ref,  // IN
                       page_type          type,      // IN
                       const slice        key,       // IN
                       merge_accumulator *data,      // OUT
                       bool              *local_found)            // OUT
{
   btree_node      node;
   message         local_data;
   platform_status rc = STATUS_OK;

   log_trace_key(key, "btree_lookup");

   btree_lookup_with_ref(
      cc, cfg, root_ref, type, key, &node, &local_data, local_found);
   if (*local_found) {
      if (merge_accumulator_is_null(data)) {
         bool success = merge_accumulator_copy_message(data, local_data);
         rc           = success ? STATUS_OK : STATUS_NO_MEMORY;
      } else if (btree_merge_tuples(cfg, key, local_data, data)) {
         rc = STATUS_NO_MEMORY;
      }
      btree_node_unget(cc, cfg, &node);
   }
   return rc;
}

/*
 *-----------------------------------------------------------------------------
 * btree_async_set_state --
 *      Set the state of the async btree lookup state machine.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *-----------------------------------------------------------------------------
 */
static inline void
btree_async_set_state(btree_async_ctxt *ctxt, btree_async_state new_state)
{
   ctxt->prev_state = ctxt->state;
   ctxt->state      = new_state;
}


/*
 *-----------------------------------------------------------------------------
 * btree_async_callback --
 *
 *      Callback that's called when the async cache get loads a page into
 *      the cache. This function moves the async btree lookup
 *state machine's state ahead, and calls the upper layer callback that'll
 *re-enqueue the btree lookup for dispatch.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *-----------------------------------------------------------------------------
 */
static void
btree_async_callback(cache_async_ctxt *cache_ctxt)
{
   btree_async_ctxt *ctxt = cache_ctxt->cbdata;

   platform_assert(SUCCESS(cache_ctxt->status));
   platform_assert(cache_ctxt->page);
   //   platform_default_log("%s:%d tid %2lu: ctxt %p is callback with page %p
   //   (%#lx)\n",
   //                __FILE__, __LINE__, platform_get_tid(), ctxt,
   //                cache_ctxt->page, ctxt->child_addr);
   ctxt->was_async = TRUE;
   platform_assert(ctxt->state == btree_async_state_get_node);
   // Move state machine ahead and requeue for dispatch
   btree_async_set_state(ctxt, btree_async_state_get_index_complete);
   ctxt->cb(ctxt);
}


/*
 *-----------------------------------------------------------------------------
 * btree_lookup_async_with_ref --
 *
 *      State machine for the async btree point lookup. This
 *uses hand over hand locking to descend the tree and every time a child node
 *needs to be looked up from the cache, it uses the async get api. A reference
 *to the parent node is held in btree_async_ctxt->node while a
 *reference to the child page is obtained by the cache_get_async() in
 *      btree_async_ctxt->cache_ctxt->page
 *
 * Results:
 *      See btree_lookup_async(). if returning async_success and
 **found = TRUE, this returns with ref on the btree leaf. Caller
 *must do unget() on node_out.
 *
 * Side effects:
 *      None.
 *-----------------------------------------------------------------------------
 */
static cache_async_result
btree_lookup_async_with_ref(cache            *cc,        // IN
                            btree_config     *cfg,       // IN
                            page_reference   *root_ref, // IN
                            slice             key,       // IN
                            btree_node       *node_out,  // OUT
                            message          *data,      // OUT
                            bool             *found,     // OUT
                            btree_async_ctxt *ctxt)      // IN
{
   cache_async_result res  = 0;
   bool               done = FALSE;
   btree_node        *node = &ctxt->node;

   do {
      switch (ctxt->state) {
         case btree_async_state_start:
         {
            ctxt->child_ref = *root_ref;
            node->page       = NULL;
            btree_async_set_state(ctxt, btree_async_state_get_node);
            // fallthrough
         }
         case btree_async_state_get_node:
         {
            cache_async_ctxt *cache_ctxt = ctxt->cache_ctxt;

            cache_ctxt_init(cc, btree_async_callback, ctxt, cache_ctxt);
            res = cache_get_async(
               cc, &ctxt->child_ref, PAGE_TYPE_BRANCH, cache_ctxt);
            switch (res) {
               case async_locked:
               case async_no_reqs:
                  //            platform_default_log("%s:%d tid %2lu: ctxt %p is
                  //            retry\n",
                  //                         __FILE__, __LINE__,
                  //                         platform_get_tid(), ctxt);
                  /*
                   * Ctxt remains at same state. The invocation is done, but
                   * the request isn't; and caller will re-invoke me.
                   */
                  done = TRUE;
                  break;
               case async_io_started:
                  //            platform_default_log("%s:%d tid %2lu: ctxt %p is
                  //            io_started\n",
                  //                         __FILE__, __LINE__,
                  //                         platform_get_tid(), ctxt);
                  // Invocation is done; request isn't. Callback will move
                  // state.
                  done = TRUE;
                  break;
               case async_success:
                  ctxt->was_async = FALSE;
                  btree_async_set_state(ctxt,
                                        btree_async_state_get_index_complete);
                  break;
               default:
                  platform_assert(0);
            }
            break;
         }
         case btree_async_state_get_index_complete:
         {
            cache_async_ctxt *cache_ctxt = ctxt->cache_ctxt;

            if (node->page) {
               // Unlock parent
               btree_node_unget(cc, cfg, node);
            }
            btree_node_get_from_cache_ctxt(cfg, cache_ctxt, node);
            debug_assert(node->ref.addr == ctxt->child_ref.addr);
            if (ctxt->was_async) {
               cache_async_done(cc, PAGE_TYPE_BRANCH, cache_ctxt);
            }
            if (btree_height(node->hdr) == 0) {
               btree_async_set_state(ctxt, btree_async_state_get_leaf_complete);
               break;
            }
            bool  found_pivot;
            int64 child_idx =
               btree_find_pivot(cfg, node->hdr, key, &found_pivot);
            if (child_idx < 0) {
               child_idx = 0;
            }
            ctxt->child_ref = btree_get_child_ref(cfg, node->hdr, child_idx);
            btree_async_set_state(ctxt, btree_async_state_get_node);
            break;
         }
         case btree_async_state_get_leaf_complete:
         {
            int64 idx = btree_find_tuple(cfg, node->hdr, key, found);
            if (*found) {
               *data     = btree_get_tuple_message(cfg, node->hdr, idx);
               *node_out = *node;
            } else {
               btree_node_unget(cc, cfg, node);
            }
            res  = async_success;
            done = TRUE;
            break;
         }
         default:
            platform_assert(0);
      }
   } while (!done);

   return res;
}

/*
 *-----------------------------------------------------------------------------
 * btree_lookup_async --
 *
 *      Async btree point lookup. The ctxt should've been
 *initialized using btree_ctxt_init(). The return value can be
 *either of: async_locked: A page needed by lookup is locked. User should retry
 *      request.
 *      async_no_reqs: A page needed by lookup is not in cache and the IO
 *      subsystem is out of requests. User should throttle.
 *      async_io_started: Async IO was started to read a page needed by the
 *      lookup into the cache. When the read is done, caller will be notified
 *      using ctxt->cb, that won't run on the thread context. It can be used
 *      to requeue the async lookup request for dispatch in thread context.
 *      When it's requeued, it must use the same function params except found.
 *      success: *found is TRUE if found, FALSE otherwise, data is stored in
 *      *data_out
 *
 * Results:
 *      Async result.
 *
 * Side effects:
 *      None.
 *-----------------------------------------------------------------------------
 */
cache_async_result
btree_lookup_async(cache             *cc,        // IN
                   btree_config      *cfg,       // IN
                   page_reference    *root_ref,  // IN
                   slice              key,       // IN
                   merge_accumulator *result,    // OUT
                   btree_async_ctxt  *ctxt)       // IN
{
   cache_async_result res;
   btree_node         node;
   message            data;
   bool               local_found;
   res = btree_lookup_async_with_ref(
      cc, cfg, root_ref, key, &node, &data, &local_found, ctxt);
   if (res == async_success && local_found) {
      bool success = merge_accumulator_copy_message(result, data);
      platform_assert(success); // FIXME
      btree_node_unget(cc, cfg, &node);
   }

   return res;
}

cache_async_result
btree_lookup_and_merge_async(cache             *cc,          // IN
                             btree_config      *cfg,         // IN
                             page_reference    *root_ref,   // IN
                             const slice        key,         // IN
                             merge_accumulator *data,        // OUT
                             bool              *local_found, // OUT
                             btree_async_ctxt  *ctxt)         // IN
{
   cache_async_result res;
   btree_node         node;
   message            local_data;

   res = btree_lookup_async_with_ref(
      cc, cfg, root_ref, key, &node, &local_data, local_found, ctxt);
   if (res == async_success && *local_found) {
      if (merge_accumulator_is_null(data)) {
         bool success = merge_accumulator_copy_message(data, local_data);
         platform_assert(success);
      } else {
         int rc = btree_merge_tuples(cfg, key, local_data, data);
         platform_assert(rc == 0);
      }
      btree_node_unget(cc, cfg, &node);
   }
   return res;
}

/*
 *-----------------------------------------------------------------------------
 * btree_iterator_init --
 * btree_iterator_get_curr --
 * btree_iterator_advance --
 * btree_iterator_at_end
 *
 * This iterator implementation supports an upper bound key ub.  Given
 * an upper bound, the iterator will return only keys strictly less
 * than ub.
 *
 * In order to avoid comparing every key with ub, it precomputes,
 * during initialization, the end leaf and end_idx of ub within that
 * leaf.
 *
 * The iterator interacts with concurrent updates to the tree as
 * follows.  Its guarantees very much depend on the fact that we do
 * not delete entries in the tree.
 *
 * The iterator is guaranteed to see all keys that are between the
 * lower and upper bounds and that were present in the tree when the
 * iterator was initialized.
 *
 * One issue is splits of the end node that we computed during
 * initialization.  If the end node splits after initialization but
 * before the iterator gets to the end node, then some of the keys
 * that we should visit may have been moved to the right sibling of
 * the end node.
 *
 * So, whenever the iterator reaches the end node, it immediately
 * checks whether the end node's generation has changed since the
 * iterator was initialized.  If it has, then the iterator recomputes
 * the end node and end_idx.
 *-----------------------------------------------------------------------------
 */
static bool
btree_iterator_is_at_end(btree_iterator *itor)
{
   int height = itor->height;
   return itor->curr[height].ref.addr == itor->end_addr
          && itor->idx[height] == itor->end_idx;
}

void
btree_iterator_get_curr(iterator *base_itor, slice *key, message *data)
{
   debug_assert(base_itor != NULL);
   btree_iterator *itor =
     (btree_iterator *)base_itor;
   int height = itor->height;
   debug_assert(itor->curr[height].hdr != NULL);
   // if (itor->at_end || itor->idx == itor->curr.hdr->num_entries) {
   //   btree_print_tree(itor->cc, itor->cfg, itor->root_addr);
   //}
   debug_assert(!btree_iterator_is_at_end(itor));
   debug_assert(itor->idx[height]
                < btree_num_entries(itor->curr[height].hdr));
   debug_assert(itor->curr[height].page != NULL);
   debug_assert(itor->curr[height].page->disk_addr == itor->curr[height].ref.addr);
   debug_assert((char *)itor->curr[height].hdr
                == itor->curr[height].page->data);
   cache_validate_page(
      itor->cc, itor->curr[height].page, itor->curr[height].ref.addr);
   if (height == 0) {
      *key  = btree_get_tuple_key(
         itor->cfg, itor->curr[0].hdr, itor->idx[0]);
      *data = btree_get_tuple_message(
         itor->cfg, itor->curr[0].hdr, itor->idx[0]);
   } else {
      index_entry *entry = btree_get_index_entry(
         itor->cfg, itor->curr[height].hdr, itor->idx[height]);
      *key  = index_entry_key_slice(entry);
      *data = message_create(
         MESSAGE_TYPE_INVALID,
         slice_create(sizeof(entry->pivot_data), &entry->pivot_data));
   }
}

static void
btree_iterator_find_end(btree_iterator *itor)
{
   btree_node end;
   btree_lookup_node(itor->cc,
                     itor->cfg,
                     &itor->root_ref,
                     itor->max_key,
                     itor->height,
                     itor->page_type,
                     &end,
                     NULL,
                     NULL,
                     NULL);
   itor->end_addr       = end.ref.addr;
   itor->end_generation = end.hdr->generation;

   if (slices_equal(itor->max_key, positive_infinity)) {
      itor->end_idx = btree_num_entries(end.hdr);
   } else {
      bool  found;
      int64 tmp;
      if (itor->height == 0) {
         tmp = btree_find_tuple(itor->cfg, end.hdr, itor->max_key, &found);
         if (!found) {
            tmp++;
         }
      } else if (itor->height > end.hdr->height) {
         platform_assert(0);
      } else {
         tmp = btree_find_pivot(itor->cfg, end.hdr, itor->max_key, &found);
         if (!found) {
            tmp++;
         }
      }
      itor->end_idx = tmp;
   }

   btree_node_unget(itor->cc, itor->cfg, &end);
}

static bool
btree_next_extent_addr_valid(btree_iterator *itor, uint64 addr)
{
   return FALSE;
   for (int i = 0; i < BTREE_MAX_HEIGHT; i++) {
      if (addr == itor->invalid_next_extent_addr[i]) {
         return FALSE;
      }
   }
   return TRUE;
}

/*
 * There are two versions of the code for moving from one node to the
 * next.  The advance_node() version uses the sibling pointers and is
 * intended for use in the memtable.  The advance_path() version does
 * a tree walk and avoids using the sibling pointers.  This is for the
 * branches.
 */

/*
 * Move to the next node when we've reached the end of one node but
 * haven't reached the end of the iterator.
 */
static void
btree_iterator_advance_node(btree_iterator *itor)
{
   cache        *cc     = itor->cc;
   btree_config *cfg    = itor->cfg;
   uint64        height = itor->height;

   // TODO(yizheng.jiao): this is only for memtable iterator
   uint64 next_addr = itor->curr[height].hdr->next_ref.addr;
   btree_node_unget(cc, cfg, &itor->curr[height]);
   itor->curr[height].ref.addr = next_addr;
#ifdef SGX_TEST
   btree_node_get_no_auth(cc, cfg, &itor->curr[height], itor->page_type, NULL);
#else
   btree_node_get(cc, cfg, &itor->curr[height], itor->page_type, NULL);
#endif
   itor->idx[height] = 0;
   itor->prefetch_distance[height]--;

   while (itor->curr[height].ref.addr == itor->end_addr
          && itor->curr[height].hdr->generation != itor->end_generation)
   {
      /* We need to recompute the end node and end_idx. (see
         comment at beginning of iterator implementation for
         high-level description)
         There's a potential for deadlock with concurrent inserters
         if we hold a read-lock on curr while looking up end, so we
         temporarily release curr.
         It is safe to relase curr because we are at index 0 of
         curr.  To see why, observe that, at this point, curr
         cannot be the first leaf in the tree (since we just
         followed a next pointer a few lines above).  And, for
         every leaf except the left-most leaf of the tree, no key
         can ever be inserted into the leaf that is smaller than
         the leaf's 0th entry, because its 0th entry is also its
         pivot in its parent.  Thus we are guaranteed that the
         first key curr will not change between the unget and the
         get. Hence we will not "go backwards" i.e. return a key
         smaller than the previous key) or skip any keys.
         Furthermore, even if another thread comes along and splits
         curr while we've released it, we will still want to
         continue at curr (since we're at the 0th entry).
      */
      btree_node_unget(itor->cc, itor->cfg, &itor->curr[height]);
      btree_iterator_find_end(itor);
#ifdef SGX_TEST
      btree_node_get_no_auth(itor->cc, itor->cfg, &itor->curr[height], itor->page_type, NULL);
#else
      btree_node_get(itor->cc, itor->cfg, &itor->curr[height], itor->page_type, NULL);
#endif
   }

   // To prefetch:
   // 1. we just moved from one extent to the next
   // 2. this can't be the last extent
   if (itor->prefetch_distance[height] == 0
       && itor->curr[height].hdr->next_extent_addr != 0
       && !btree_addrs_share_extent(
          cfg, itor->curr[height].ref.addr, itor->end_addr)
       && btree_next_extent_addr_valid(itor, itor->curr[height].hdr->next_extent_addr))
   {
      // IO prefetch the next extent
      cache_prefetch(cc, itor->curr[height].hdr->next_extent_addr, TRUE);
      uint64 page_size    = btree_page_size(itor->cfg);
      uint64 extent_pages = btree_extent_size(cfg) / page_size;
      uint64 offset = (itor->curr[height].ref.addr / page_size) % extent_pages;
      itor->prefetch_distance[height] = extent_pages - offset;
   }
}

platform_status
btree_iterator_advance_path(
   btree_iterator *itor)
{
   debug_assert(itor != NULL);

   // We should not be calling advance on an empty iterator
   debug_assert(!btree_iterator_is_at_end(itor));

   // Walk up the tree until we find a node with more entries.
   // Since we are not at the end of the iterator, such a node is
   // guaranteed to exist.
   int height = itor->height;
   while (itor->idx[height]
          == btree_num_entries(itor->curr[height].hdr))
   {
      btree_node_unget(
         itor->cc, itor->cfg, &itor->curr[height]);
      height++;
      itor->idx[height]++;
   }

   uint64 page_size    = btree_page_size(itor->cfg);
   uint64 extent_pages = btree_extent_size(itor->cfg) / page_size;

   // Walk back down the tree to the desired height of the iterator, issuing
   // prefetches as we go.
   while (itor->height < height) {
#ifdef AUTH_DEBUG
      int num_children = btree_num_entries(itor->curr[height].hdr);
      platform_default_log("%s: pid=%ld, index=%ld, parent is itor->curr[%d].page->disk_addr=%lu, root.addr=%lu, height=%d, num_children=%d\n",
                            __func__, platform_get_tid(), itor->idx[height], height,
                            itor->curr[height].page->disk_addr, itor->root_ref.addr,
                            height, num_children);
#endif
      page_reference child_ref = btree_get_child_ref(
         itor->cfg, itor->curr[height].hdr, itor->idx[height]);

      height--;

      itor->curr[height].ref = child_ref;
#ifdef SGX_TEST
      btree_node_get_no_auth(
         itor->cc, itor->cfg, &itor->curr[height], itor->page_type, NULL);
#else
      btree_node_get(
         itor->cc, itor->cfg, &itor->curr[height], itor->page_type, NULL);
#endif
      itor->idx[height] = 0;

      if (itor->prefetch_distance[height] == 0
          && itor->curr[height].hdr->next_extent_addr != 0
          && !btree_addrs_share_extent(
             itor->cfg, itor->curr[height].ref.addr, itor->end_addr)
          && btree_next_extent_addr_valid(itor, itor->curr[height].hdr->next_extent_addr))
      {
         // IO prefetch the next extent
         cache_prefetch(
            itor->cc, itor->curr[height].hdr->next_extent_addr, TRUE);
         uint64 offset = (itor->curr[height].ref.addr / page_size) % extent_pages;
         itor->prefetch_distance[height] = extent_pages - offset;
      }
   }

   debug_assert(btree_iterator_is_at_end(itor)
                || itor->idx[itor->height] < btree_num_entries(
                      itor->curr[itor->height].hdr));

   return STATUS_OK;
}

platform_status
btree_iterator_advance(iterator *base_itor)
{
   debug_assert(base_itor != NULL);
   btree_iterator *itor = (btree_iterator *)base_itor;

   // We should not be calling advance on an empty iterator
   debug_assert(!btree_iterator_is_at_end(itor));
   debug_assert(itor->idx[itor->height] < btree_num_entries(
                   itor->curr[itor->height].hdr));

   itor->idx[itor->height]++;

   if (!btree_iterator_is_at_end(itor)
       && itor->idx[itor->height]
             == btree_num_entries(itor->curr[itor->height].hdr))
   {
      if (itor->page_type == PAGE_TYPE_MEMTABLE) {
         btree_iterator_advance_node(itor);
      } else {
         btree_iterator_advance_path(itor);
      }
   }

   debug_assert(btree_iterator_is_at_end(itor)
                || itor->idx[itor->height] < btree_num_entries(
                      itor->curr[itor->height].hdr));

   return STATUS_OK;
}

platform_status
btree_iterator_at_end(iterator *itor, bool *at_end)
{
   debug_assert(itor != NULL);
   *at_end = btree_iterator_is_at_end((btree_iterator *)itor);

   return STATUS_OK;
}

void
btree_iterator_print(iterator *itor)
{
   debug_assert(itor != NULL);
   btree_iterator *btree_itor = (btree_iterator *)itor;

   platform_default_log("########################################\n");
   platform_default_log("## btree_itor: %p\n", itor);
   platform_default_log("## root: %lu end %lu end_idx %lu end_generation %lu\n",
                btree_itor->root_ref.addr,
                btree_itor->end_addr,
                btree_itor->end_idx,
                btree_itor->end_generation);

   int height = btree_itor->height;
   while (btree_itor->curr[height].hdr) {
      platform_default_log("## height %d curr %lu idx %lu\n",
                   height,
                   btree_itor->curr[height].ref.addr,
                   btree_itor->idx[height]);
      btree_print_node(Platform_default_log_handle,
         btree_itor->cc,
         btree_itor->cfg,
         &btree_itor->curr[height]);
      height++;
   }
}

const static iterator_ops btree_iterator_ops = {
   .get_curr = btree_iterator_get_curr,
   .at_end   = btree_iterator_at_end,
   .advance  = btree_iterator_advance,
   .print    = btree_iterator_print,
};


/*
 *-----------------------------------------------------------------------------
 * Caller must guarantee:
 *    max_key (if not null) needs to be valid until iterator is deinited.
 *-----------------------------------------------------------------------------
 */
void
btree_iterator_init(cache          *cc,
                    btree_config   *cfg,
                    btree_iterator *itor,
                    page_reference *root_ref,
                    page_type       page_type,
                    const slice     min_key,
                    const slice     _max_key,
                    bool            do_prefetch,
                    uint32          height)
{
   platform_assert(root_ref->addr != 0);
   debug_assert(page_type == PAGE_TYPE_MEMTABLE
                || page_type == PAGE_TYPE_BRANCH);

   slice max_key;

   /* Handle _max_key == NULL and when _max_key < min_key. */
   if (slice_is_null(_max_key)) {
      max_key = positive_infinity;
   } else if (!slice_is_null(min_key)
              && btree_key_compare(cfg, min_key, _max_key) > 0)
   {
      max_key = min_key;
   } else {
      max_key = _max_key;
   }

   ZERO_CONTENTS(itor);
   itor->cc          = cc;
   itor->cfg         = cfg;
   itor->root_ref    = *root_ref;
   itor->do_prefetch = do_prefetch;
   itor->height      = height;
   itor->min_key     = min_key;
   itor->max_key     = max_key;
   itor->page_type   = page_type;
   itor->super.ops   = &btree_iterator_ops;

   /* Find the starting node. For branches, this also read-locks the
      entire path to the starting node, and computes the indexes
      within each node on that path (except for the last). */
   uint64 root_height;
   uint64 lock_height = page_type == PAGE_TYPE_MEMTABLE
                           ? itor->height + 1
                           : BTREE_MAX_HEIGHT;
   btree_lookup_path(itor->cc,
                     itor->cfg,
                     &itor->root_ref,
                     min_key,
                     lock_height,
                     itor->height,
                     itor->page_type,
                     itor->curr,
                     itor->idx,
                     itor->invalid_next_extent_addr,
                     &root_height,
                     NULL,
                     NULL,
                     NULL);

   if (root_height < height) {
      /* If the requested height is higher than the tree, then set up the
         iterator so that at_end() will return true. */
      itor->height           = root_height;
      itor->idx[root_height] = 0;
      itor->end_addr         = itor->curr[root_height].ref.addr;
      itor->end_idx          = 0;
      itor->end_generation   = itor->curr[root_height].hdr->generation;
      return;
   }

   /* Find our starting index in curr. */
   bool  found;
   int64 tmp;
   if (slice_is_null(min_key)) {
      tmp = 0;
   } else if (itor->height == 0) {
      tmp = btree_find_tuple(
         itor->cfg, itor->curr[itor->height].hdr, min_key, &found);
      if (!found) {
         tmp++;
      }
   } else if (itor->height > itor->curr[itor->height].hdr->height) {
      tmp = 0;
   } else {
      tmp = btree_find_pivot(
         itor->cfg, itor->curr[itor->height].hdr, min_key, &found);
      if (!found) {
         tmp++;
      }
      platform_assert(0 <= tmp);
   }
   itor->idx[itor->height] = tmp;

   /* Now we find the ending node and index. */

   if (page_type == PAGE_TYPE_MEMTABLE) {
      /* Since we might not be locking the root in this case, there
       * are possible deadlocks with insertion threads while finding
       * the end node.  We avoid these by claiming curr.
       *
       * Note that we can't lookup end first because, if there's a split
       * between looking up end and looking up curr, we could end up in a
       * situation where end comes before curr in the tree!  (We could
       * prevent this by holding a claim on end while looking up curr,
       * but that would essentially be the same as the code below.)
       *
       * Note that the approach in advance (i.e. releasing and reaquiring
       * a lock on curr) is not viable here because we are not
       * necessarily searching for the 0th entry in curr.  Thus a split
       * of curr while we have released it could mean that we really want
       * to start at curr's right sibling (after the split).  So we'd
       * have to redo the search from scratch after releasing curr.
       *
       * So we take a claim on curr instead.
       */
      while (!btree_node_claim(cc, cfg, &itor->curr[height])) {
         btree_node_unget(cc, cfg, &itor->curr[height]);
         btree_lookup_node(itor->cc,
                           itor->cfg,
                           &itor->root_ref,
                           min_key,
                           itor->height,
                           itor->page_type,
                           &itor->curr[height],
                           NULL,
                           NULL,
                           NULL);
      }
   }

   /* Find the end node and index. */
   btree_iterator_find_end(itor);

   if (page_type == PAGE_TYPE_MEMTABLE) {
      /* Once we've found end, we can unclaim curr. */
      btree_node_unclaim(cc, cfg, &itor->curr[height]);
   }

   /* Set up prefetching state. */
   if (itor->do_prefetch) {
      int    h                = itor->height;
      uint64 page_size        = btree_page_size(itor->cfg);
      uint64 pages_per_extent = btree_extent_size(itor->cfg) / page_size;
      while (itor->curr[h].hdr) {
         itor->prefetch_distance[h] =
            BTREE_INITIAL_PREFETCHING_DISTANCE(
               pages_per_extent);
         h++;
      }
   } else {
      memset(itor->prefetch_distance, 0xff, sizeof(itor->prefetch_distance));
   }

   /* If the starting key falls in the range of curr but is larger
      than any key in curr, then we need to advance to the next
      node. We can't do this earlier because we needed to set up the
      prefetching state, and setting up the prefetching state can't be
      done until we've found the end node. */
   if (!btree_iterator_is_at_end(itor)
       && itor->idx[itor->height]
             == btree_num_entries(itor->curr[itor->height].hdr))
   {
      if (itor->page_type == PAGE_TYPE_MEMTABLE) {
         btree_iterator_advance_node(itor);
      } else {
         btree_iterator_advance_path(itor);
      }
   }

   debug_assert(btree_iterator_is_at_end(itor)
                || itor->idx[itor->height]
                      < btree_num_entries(itor->curr[itor->height].hdr));
}

void
btree_iterator_deinit(btree_iterator *itor)
{
   debug_assert(itor != NULL);
   int h = itor->height;
   while (itor->curr[h].hdr) {
      btree_node_unget(itor->cc, itor->cfg, &itor->curr[h]);
      h++;
   }
}

// generation number isn't used in packed btrees
static inline void
btree_pack_node_init_hdr(const btree_config *cfg,
                         btree_hdr          *hdr,
                         uint64              next_extent,
                         uint8               height)
{
   btree_init_hdr(cfg, hdr);
   hdr->next_extent_addr = next_extent;
   hdr->height           = height;
}

static inline void
btree_pack_setup_start(btree_pack_req *req)
{
   req->next_extent = 0;
   req->height      = 0;
   ZERO_ARRAY(req->edge);

   // we create a root here, but we won't build it with the rest
   // of the tree, we'll copy into it at the end
   req->root_ref =
      btree_create(req->cc, req->cfg, &req->mini, PAGE_TYPE_BRANCH);

   req->num_tuples    = 0;
   req->key_bytes     = 0;
   req->message_bytes = 0;
}


static inline void
btree_pack_setup_finish(btree_pack_req *req, slice first_key)
{
   // set up the first leaf
   btree_alloc(req->cc,
               &req->mini,
               0,
               first_key,
               &req->next_extent,
               PAGE_TYPE_BRANCH,
               &req->edge[0]);
   page_reference ref = {.addr = req->next_extent};
   (void)ref;
   debug_assert(cache_page_valid(req->cc, &ref));
   btree_pack_node_init_hdr(req->cfg, req->edge[0].hdr, req->next_extent, 0);
}

static inline void
btree_pack_loop(btree_pack_req *req, // IN/OUT
                slice           key, // IN
                message         msg, // IN
                bool           *at_end)        // IN/OUT
{
   log_trace_key(key, "btree_pack_loop");
   if (!btree_set_leaf_entry(req->cfg,
                             req->edge[0].hdr,
                             btree_num_entries(req->edge[0].hdr),
                             key,
                             msg))
   {
      // the current leaf is full, allocate a new one and add to index
      btree_node old_edge = req->edge[0];
      memset(old_edge.ref.hash, 0, HASH_SIZE);

      btree_alloc(req->cc,
                  &req->mini,
                  0,
                  key,
                  &req->next_extent,
                  PAGE_TYPE_BRANCH,
                  &req->edge[0]);
      //old_edge.hdr->next_ref.addr = req->edge[0].ref.addr;

      // initialize the new leaf edge
      page_reference ref = {.addr = req->next_extent};
      (void)ref;
      debug_assert(cache_page_valid(req->cc, &ref));
      btree_pack_node_init_hdr(req->cfg, req->edge[0].hdr, req->next_extent, 0);
      bool result =
         btree_set_leaf_entry(req->cfg, req->edge[0].hdr, 0, key, msg);
      platform_assert(result);

      // this loop finds the first level with a free slot
      // along the way it allocates new index nodes as necessary
      uint16 i = 1;
      while (i <= req->height
             && !btree_set_index_entry(req->cfg,
                                       req->edge[i].hdr,
                                       btree_num_entries(req->edge[i].hdr),
                                       key,
                                       req->edge[i - 1].ref.addr,
                                       0,
                                       0,
                                       0))
      {
         {
            int height = btree_height(old_edge.hdr);
            int nentries = btree_num_entries(req->edge[height+1].hdr);

            //platform_default_log("%s: pid=%ld, height=%d, parent is=%ld, nentries=%d\n",
            //                      __func__, platform_get_tid(), height, req->edge[height+1].ref.addr,
            //                      nentries);
            btree_node_full_unlock(req->cc, req->cfg, &old_edge, NULL, __LINE__);
            // Even though old_edge is unlocked. I believe nobody is using it.
            // Because btree_pack is done by a single thread.
            btree_set_child_hash(req->cc,
                                 req->cfg,
                                 &req->edge[height+1],
                                 old_edge.ref.addr,
                                 old_edge.ref.hash,
                                 nentries - 1, // old_edge is the last child
                                 __LINE__);
         }

         old_edge = req->edge[i];
         memset(old_edge.ref.hash, 0, HASH_SIZE);

         btree_alloc(req->cc,
                     &req->mini,
                     i,
                     key,
                     &req->next_extent,
                     PAGE_TYPE_BRANCH,
                     &req->edge[i]);
         //old_edge.hdr->next_ref.addr = req->edge[i].ref.addr;

         // initialize the new index edge
         btree_pack_node_init_hdr(
            req->cfg, req->edge[i].hdr, req->next_extent, i);
         btree_set_index_entry(
            req->cfg, req->edge[i].hdr, 0, key, req->edge[i - 1].ref.addr, 0, 0, 0);
         i++;
      }

      if (req->height < i) {
         slice smallest_key =
            btree_height(old_edge.hdr)
               ? btree_get_pivot(req->cfg, old_edge.hdr, 0)
               : btree_get_tuple_key(req->cfg, old_edge.hdr, 0);
         // need to add a new root
         btree_alloc(req->cc,
                     &req->mini,
                     i,
                     smallest_key,
                     &req->next_extent,
                     PAGE_TYPE_BRANCH,
                     &req->edge[i]);
         btree_pack_node_init_hdr(
            req->cfg, req->edge[i].hdr, req->next_extent, i);
         req->height++;
         platform_assert(req->height);

         // add old root and it's younger sibling
         bool succeeded = btree_set_index_entry(req->cfg,
                                                req->edge[i].hdr,
                                                0,
                                                smallest_key,
                                                old_edge.ref.addr,
                                                req->num_tuples,
                                                req->key_bytes,
                                                req->message_bytes);
         platform_assert(succeeded);
         succeeded = btree_set_index_entry(
            req->cfg, req->edge[i].hdr, 1, key, req->edge[i - 1].ref.addr, 0, 0, 0);
         platform_assert(succeeded);
      }
      {
         int height = btree_height(old_edge.hdr);
         int nentries = btree_num_entries(req->edge[height+1].hdr);

         //platform_default_log("%s: pid=%ld, height=%d, parent is=%ld, nentries=%d\n",
         //                      __func__, platform_get_tid(), height, req->edge[height+1].ref.addr,
         //                      btree_num_entries(req->edge[height+1].hdr));
 
         btree_node_full_unlock(req->cc, req->cfg, &old_edge, NULL, __LINE__);
         // Even though old_edge is unlocked. I believe nobody is using it.
         // Because btree_pack is done by a single thread.
         btree_set_child_hash(req->cc,
                              req->cfg,
                              &req->edge[height+1],
                              old_edge.ref.addr,
                              old_edge.ref.hash,
                              nentries - 2, // old_edge is not the last child
                              __LINE__);
      }
   }

#if defined(BTREE_TRACE)
   if (btree_key_compare(req->cfg, key, trace_key) == 0) {
      platform_log("adding tuple to %lu, root addr %lu\n",
                   req->edge[0].addr,
                   *req->root_addr);
   }
#endif

   for (uint16 i = 1; i <= req->height; i++) {
      index_entry *entry = btree_get_index_entry(
         req->cfg, req->edge[i].hdr, btree_num_entries(req->edge[i].hdr) - 1);
      entry->pivot_data.num_kvs_in_subtree++;
      entry->pivot_data.key_bytes_in_subtree += slice_length(key);
      entry->pivot_data.message_bytes_in_subtree += message_length(msg);
   }

   if (req->hash) {
      platform_assert(req->num_tuples < req->max_tuples);
      req->fingerprint_arr[req->num_tuples] =
         req->hash(slice_data(key), slice_length(key), req->seed);
   }

   req->num_tuples++;
   req->key_bytes += slice_length(key);
   req->message_bytes += message_length(msg);

   iterator_advance(req->itor);
   iterator_at_end(req->itor, at_end);
}

static inline void
btree_pack_post_loop(btree_pack_req *req, slice last_key)
{
   cache        *cc  = req->cc;
   btree_config *cfg = req->cfg;
   // we want to use the allocation node, so we copy the root created in the
   // loop into the btree_create root
   btree_node root;
   __attribute__((unused)) bool success;
   uint64 invalid_next_extent_addr[BTREE_MAX_HEIGHT] = { 0 };

   // if output tree is empty, deallocate any preallocated extents
   if (req->num_tuples == 0) {
      mini_destroy_unused(&req->mini);
      req->root_ref.addr = 0;
      return;
   }

   // release all the edge nodes;
   for (uint16 i = 0; i <= req->height; i++) {
      // go back and fix the dangling next extents
      invalid_next_extent_addr[i] = req->edge[i].hdr->next_extent_addr;
      req->edge[i].hdr->next_extent_addr = 0;
      if (i < req->height) {
         btree_node_full_unlock(cc, cfg, &req->edge[i], NULL, __LINE__);
         table_index k = btree_num_entries(req->edge[i+1].hdr) - 1;
         btree_set_child_hash(req->cc,
                              req->cfg,
                              &req->edge[i+1],
                              req->edge[i].ref.addr,
                              req->edge[i].ref.hash,
                              k, __LINE__);
      }
   }

   root.ref = req->root_ref;
   btree_node_get(cc, cfg, &root, PAGE_TYPE_BRANCH, NULL);

   success = btree_node_claim(cc, cfg, &root);
   debug_assert(success);
   btree_node_lock(cc, cfg, &root);
   memmove(root.hdr, req->edge[req->height].hdr, btree_page_size(cfg));
   // fix the root next extent
   root.hdr->next_extent_addr = 0;
   // set the invalid next extent addr to disable prefetch
   memcpy(root.hdr->invalid_next_extent_addr, invalid_next_extent_addr, sizeof(uint64) * BTREE_MAX_HEIGHT);

   btree_node_full_unlock(cc, cfg, &root, NULL, __LINE__);
   platform_assert(root.ref.addr == req->root_ref.addr);
   memcpy(req->root_ref.hash, root.ref.hash, HASH_SIZE);
   debug_assert(memcmp(req->root_ref.hash, root.ref.hash, HASH_SIZE) == 0);
   btree_node_full_unlock(cc, cfg, &req->edge[req->height], NULL, __LINE__);
   mini_release(&req->mini, last_key);
}

static bool
btree_pack_can_fit_tuple(btree_pack_req *req, slice key, message data)
{
   return req->num_tuples < req->max_tuples;
}

/*
 *-----------------------------------------------------------------------------
 * btree_pack --
 *
 *      Packs a btree from an iterator source. Dec_Refs the
 *      output tree if it's empty.
 *-----------------------------------------------------------------------------
 */
platform_status
btree_pack(btree_pack_req *req)
{
   btree_pack_setup_start(req);

   slice   key = NULL_SLICE;
   message data;
   bool    at_end;

   iterator_at_end(req->itor, &at_end);

   if (!at_end) {
      iterator_get_curr(req->itor, &key, &data);
      if (btree_pack_can_fit_tuple(req, key, data)) {
         btree_pack_setup_finish(req, key);
      }
   }

   while (!at_end && req->num_tuples < req->max_tuples
          && btree_pack_can_fit_tuple(req, key, data))
   {
      iterator_get_curr(req->itor, &key, &data);
      btree_pack_loop(req, key, data, &at_end);
   }

   btree_pack_post_loop(req, key);
   platform_assert(IMPLIES(req->num_tuples == 0, req->root_ref.addr == 0));

#ifdef AUTH_DEBUG
   iterator_tests(req->cc, req->cfg, &req->root_ref, PAGE_TYPE_BRANCH);
#endif
   return STATUS_OK;
}

/*
 * Returns the number of kv pairs (k,v ) w/ k < key.  Also returns
 * the total size of all such keys and messages.
 */
static inline void
btree_get_rank(cache        *cc,
               btree_config *cfg,
               page_reference *root_ref,
               const slice   key,
               uint32       *kv_rank,
               uint32       *key_bytes_rank,
               uint32       *message_bytes_rank)
{
   btree_node leaf;
   btree_lookup_node(cc,
                     cfg,
                     root_ref,
                     key,
                     0,
                     PAGE_TYPE_BRANCH,
                     &leaf,
                     kv_rank,
                     key_bytes_rank,
                     message_bytes_rank);
   bool  found;
   int64 tuple_rank_in_leaf = btree_find_tuple(cfg, leaf.hdr, key, &found);
   if (!found) {
      tuple_rank_in_leaf++;
   }
   accumulate_node_ranks(cfg,
                         leaf.hdr,
                         0,
                         tuple_rank_in_leaf,
                         kv_rank,
                         key_bytes_rank,
                         message_bytes_rank);
   btree_node_unget(cc, cfg, &leaf);
}

/*
 * count_in_range returns the exact number of tuples in the given
 * btree between min_key (inc) and max_key (excl).
 */
void
btree_count_in_range(cache          *cc,
                     btree_config   *cfg,
                     page_reference *root_ref,
                     const slice     min_key,
                     const slice     max_key,
                     uint32         *kv_rank,
                     uint32         *key_bytes_rank,
                     uint32         *message_bytes_rank)
{
   uint32 min_kv_rank;
   uint32 min_key_bytes_rank;
   uint32 min_message_bytes_rank;

   btree_get_rank(cc,
                  cfg,
                  root_ref,
                  min_key,
                  &min_kv_rank,
                  &min_key_bytes_rank,
                  &min_message_bytes_rank);
   btree_get_rank(cc,
                  cfg,
                  root_ref,
                  slice_is_null(max_key) ? positive_infinity : max_key,
                  kv_rank,
                  key_bytes_rank,
                  message_bytes_rank);
   if (min_kv_rank < *kv_rank) {
      *kv_rank            = *kv_rank - min_kv_rank;
      *key_bytes_rank     = *key_bytes_rank - min_key_bytes_rank;
      *message_bytes_rank = *message_bytes_rank - min_message_bytes_rank;
   } else {
      *kv_rank            = 0;
      *key_bytes_rank     = 0;
      *message_bytes_rank = 0;
   }
}

/*
 * btree_count_in_range_by_iterator perform
 * btree_count_in_range using an iterator instead of by
 * calculating ranks. Used for debugging purposes.
 */
void
btree_count_in_range_by_iterator(cache        *cc,
                                 btree_config *cfg,
                                 page_reference *root_ref,
                                 const slice   min_key,
                                 const slice   max_key,
                                 uint32       *kv_rank,
                                 uint32       *key_bytes_rank,
                                 uint32       *message_bytes_rank)
{
   btree_iterator btree_itor;
   iterator      *itor = &btree_itor.super;
   btree_iterator_init(cc,
                       cfg,
                       &btree_itor,
                       root_ref,
                       PAGE_TYPE_BRANCH,
                       min_key,
                       max_key,
                       TRUE,
                       0);

   *kv_rank            = 0;
   *key_bytes_rank     = 0;
   *message_bytes_rank = 0;

   bool at_end;
   iterator_at_end(itor, &at_end);
   while (!at_end) {
      slice   key;
      message msg;
      iterator_get_curr(itor, &key, &msg);
      *kv_rank            = *kv_rank + 1;
      *key_bytes_rank     = *key_bytes_rank + slice_length(key);
      *message_bytes_rank = *message_bytes_rank + message_length(msg);
      iterator_advance(itor);
      iterator_at_end(itor, &at_end);
   }
   btree_iterator_deinit(&btree_itor);
}

/*
 *-----------------------------------------------------------------------------
 * btree_print_node --
 * btree_print_tree --
 *
 *      Prints out the contents of the node/tree.
 *-----------------------------------------------------------------------------
 */
void
btree_print_locked_node(platform_log_handle *log_handle,
                        btree_config        *cfg,
                        uint64               addr,
                        btree_hdr           *hdr)
{
   data_config *dcfg = cfg->data_cfg;

   platform_log(log_handle, "*******************\n");
   if (btree_height(hdr) > 0) {
      platform_log(log_handle, "**  INDEX NODE \n");
      platform_log(log_handle, "**  addr: %lu \n", addr);
      platform_log(log_handle, "**  ptr: %p\n", hdr);
      platform_log(log_handle, "**  next_addr: %lu \n", hdr->next_ref.addr);
      platform_log(
         log_handle, "**  next_extent_addr: %lu \n", hdr->next_extent_addr);
      platform_log(log_handle, "**  generation: %lu \n", hdr->generation);
      platform_log(log_handle, "**  height: %u \n", btree_height(hdr));
      platform_log(log_handle, "**  next_entry: %u \n", hdr->next_entry);
      platform_log(
         log_handle, "**  num_entries: %u \n", btree_num_entries(hdr));
      platform_log(log_handle, "-------------------\n");
      platform_log(log_handle, "Table\n");
      for (uint64 i = 0; i < hdr->num_entries; i++) {
         platform_log(
            log_handle, "  %lu:%u\n", i, btree_get_table_entry(hdr, i));
      }
      platform_log(log_handle, "\n");
      platform_log(log_handle, "-------------------\n");
      for (uint64 i = 0; i < btree_num_entries(hdr); i++) {
         index_entry *entry = btree_get_index_entry(cfg, hdr, i);
         platform_log(log_handle,
                      "%2lu:%s -- %lu (%u, %u, %u)\n",
                      i,
                      key_string(dcfg, index_entry_key_slice(entry)),
                      entry->pivot_data.child_ref.addr,
                      entry->pivot_data.num_kvs_in_subtree,
                      entry->pivot_data.key_bytes_in_subtree,
                      entry->pivot_data.message_bytes_in_subtree);
      }
      platform_log(log_handle, "\n");
   } else {
      platform_log(log_handle, "**  LEAF NODE \n");
      platform_log(log_handle, "**  addr: %lu \n", addr);
      platform_log(log_handle, "**  ptr: %p\n", hdr);
      platform_log(log_handle, "**  next_addr: %lu \n", hdr->next_ref.addr);
      platform_log(
         log_handle, "**  next_extent_addr: %lu \n", hdr->next_extent_addr);
      platform_log(log_handle, "**  generation: %lu \n", hdr->generation);
      platform_log(log_handle, "**  height: %u \n", btree_height(hdr));
      platform_log(log_handle, "**  next_entry: %u \n", hdr->next_entry);
      platform_log(
         log_handle, "**  num_entries: %u \n", btree_num_entries(hdr));
      platform_log(log_handle, "-------------------\n");
      for (uint64 i = 0; i < btree_num_entries(hdr); i++) {
         platform_log(log_handle, "%lu:%u ", i, btree_get_table_entry(hdr, i));
      }
      platform_log(log_handle, "\n");
      platform_log(log_handle, "-------------------\n");
      for (uint64 i = 0; i < btree_num_entries(hdr); i++) {
         leaf_entry *entry = btree_get_leaf_entry(cfg, hdr, i);
         platform_log(log_handle,
                      "%2lu:%s -- %s\n",
                      i,
                      key_string(dcfg, leaf_entry_key_slice(entry)),
                      message_string(dcfg, leaf_entry_message(entry)));
      }
      platform_log(log_handle, "-------------------\n");
      platform_log(log_handle, "\n");
   }
}

void
btree_print_node(platform_log_handle *log_handle,
                 cache               *cc,
                 btree_config        *cfg,
                 btree_node          *node)
{
   if (!cache_page_valid(cc, &node->ref)) {
      platform_log(log_handle, "*******************\n");
      platform_log(log_handle, "** INVALID NODE \n");
      platform_log(log_handle, "** addr: %lu \n", node->ref.addr);
      platform_log(log_handle, "-------------------\n");
      return;
   }
   btree_node_get(cc, cfg, node, PAGE_TYPE_BRANCH, NULL);
   btree_print_locked_node(log_handle, cfg, node->ref.addr, node->hdr);
   btree_node_unget(cc, cfg, node);
}

void
btree_print_subtree(platform_log_handle *log_handle,
                    cache               *cc,
                    btree_config        *cfg,
                    page_reference      *ref)
{
   btree_node node;
   node.ref = *ref;
   btree_print_node(log_handle, cc, cfg, &node);
   if (!cache_page_valid(cc, ref)) {
      return;
   }
   btree_node_get(cc, cfg, &node, PAGE_TYPE_BRANCH, NULL);
   table_index idx;

   if (node.hdr->height > 0) {
      for (idx = 0; idx < node.hdr->num_entries; idx++) {
         page_reference child_ref = btree_get_child_ref(cfg, node.hdr, idx);
         btree_print_subtree(
            log_handle, cc, cfg, &child_ref);
      }
   }
   btree_node_unget(cc, cfg, &node);
}

void
btree_print_tree(platform_log_handle *log_handle,
                 cache               *cc,
                 btree_config        *cfg,
                 page_reference      *root_ref,
                 page_type            type)
{
   btree_print_subtree(log_handle, cc, cfg, root_ref);
}

void
btree_print_tree_stats(platform_log_handle *log_handle,
                       cache               *cc,
                       btree_config        *cfg,
                       page_reference      *ref,
                       page_type            type)
{
   btree_node node;
   node.ref = *ref;

   btree_node_get(cc, cfg, &node, type, NULL);

   platform_default_log("Tree stats: height %u\n", node.hdr->height);
   cache_print_stats(log_handle, cc);

   btree_node_unget(cc, cfg, &node);
}

/*
 * returns the space used in bytes by the range [start_key, end_key) in the
 * btree
 */
uint64
btree_space_use_in_range(cache        *cc,
                         btree_config *cfg,
                         uint64        root_addr,
                         page_type     type,
                         const slice   start_key,
                         const slice   end_key)
{
   uint64 meta_head    = btree_root_to_meta_addr(cfg, root_addr, 0);
   uint64 extents_used = mini_keyed_extent_count(
      cc, cfg->data_cfg, type, meta_head, start_key, end_key);
   return extents_used * btree_extent_size(cfg);
}

bool
btree_verify_node(cache          *cc,
                  btree_config   *cfg,
                  page_reference *ref,
                  page_type       type,
                  bool            is_left_edge)
{
   btree_node node;
   node.ref = *ref;
   debug_assert(type == PAGE_TYPE_BRANCH || type == PAGE_TYPE_MEMTABLE);
   btree_node_get(cc, cfg, &node, type, NULL);
   table_index idx;
   bool        result = FALSE;

   for (idx = 0; idx < node.hdr->num_entries; idx++) {
      if (node.hdr->height == 0) {
         // leaf node
         if (node.hdr->num_entries > 0 && idx < node.hdr->num_entries - 1) {
            if (btree_key_compare(cfg,
                                  btree_get_tuple_key(cfg, node.hdr, idx),
                                  btree_get_tuple_key(cfg, node.hdr, idx + 1))
                >= 0)
            {
               platform_error_log("out of order tuples\n");
               platform_error_log("addr: %lu idx %2u\n", node.ref.addr, idx);
               btree_node_unget(cc, cfg, &node);
               goto out;
            }
         }
      } else {
         // index node
         btree_node child;
         child.ref = btree_get_child_ref(cfg, node.hdr, idx);
         btree_node_get(cc, cfg, &child, type, NULL);
         if (child.hdr->height != node.hdr->height - 1) {
            platform_error_log("height mismatch\n");
            platform_error_log("addr: %lu idx: %u\n", node.ref.addr, idx);
            btree_node_unget(cc, cfg, &child);
            btree_node_unget(cc, cfg, &node);
            goto out;
         }
         if (node.hdr->num_entries > 0 && idx < node.hdr->num_entries - 1) {
            if (btree_key_compare(cfg,
                                  btree_get_pivot(cfg, node.hdr, idx),
                                  btree_get_pivot(cfg, node.hdr, idx + 1))
                >= 0)
            {
               btree_node_unget(cc, cfg, &child);
               btree_node_unget(cc, cfg, &node);
               btree_print_tree(Platform_error_log_handle, cc, cfg, &node.ref, type);
               platform_error_log("out of order pivots\n");
               platform_error_log("addr: %lu idx %u\n", node.ref.addr, idx);
               goto out;
            }
         }
         if (child.hdr->height == 0) {
            // child leaf
            if (0 < idx
                && btree_key_compare(cfg,
                                     btree_get_pivot(cfg, node.hdr, idx),
                                     btree_get_tuple_key(cfg, child.hdr, 0))
                      != 0)
            {
               platform_error_log(
                  "pivot key doesn't match in child and parent\n");
               platform_error_log("addr: %lu idx %u\n", node.ref.addr, idx);
               platform_error_log("child addr: %lu\n", child.ref.addr);
               btree_node_unget(cc, cfg, &child);
               btree_node_unget(cc, cfg, &node);
               goto out;
            }
         }
         if (child.hdr->height == 0) {
            // child leaf
            if (idx != btree_num_entries(node.hdr) - 1
                && btree_key_compare(
                      cfg,
                      btree_get_pivot(cfg, node.hdr, idx + 1),
                      btree_get_tuple_key(
                         cfg, child.hdr, btree_num_entries(child.hdr) - 1))
                      < 0)
            {
               platform_error_log("child tuple larger than parent bound\n");
               platform_error_log("addr: %lu idx %u\n", node.ref.addr, idx);
               platform_error_log("child addr: %lu idx %u\n", child.ref.addr, idx);
               btree_print_locked_node(
                  Platform_error_log_handle, cfg, node.ref.addr, node.hdr);
               btree_print_locked_node(
                  Platform_error_log_handle, cfg, child.ref.addr, child.hdr);
               platform_assert(0);
               btree_node_unget(cc, cfg, &child);
               btree_node_unget(cc, cfg, &node);
               goto out;
            }
         } else {
            // child index
            if (idx != btree_num_entries(node.hdr) - 1
                && btree_key_compare(
                      cfg,
                      btree_get_pivot(cfg, node.hdr, idx + 1),
                      btree_get_pivot(
                         cfg, child.hdr, btree_num_entries(child.hdr) - 1))
                      < 0)
            {
               platform_error_log("child pivot larger than parent bound\n");
               platform_error_log("addr: %lu idx %u\n", node.ref.addr, idx);
               platform_error_log("child addr: %lu idx %u\n", child.ref.addr, idx);
               btree_print_locked_node(
                  Platform_error_log_handle, cfg, node.ref.addr, node.hdr);
               btree_print_locked_node(
                  Platform_error_log_handle, cfg, child.ref.addr, child.hdr);
               platform_assert(0);
               btree_node_unget(cc, cfg, &child);
               btree_node_unget(cc, cfg, &node);
               goto out;
            }
         }
         btree_node_unget(cc, cfg, &child);
         bool child_is_left_edge = is_left_edge && idx == 0;
         if (!btree_verify_node(cc, cfg, &child.ref, type, child_is_left_edge))
         {
            btree_node_unget(cc, cfg, &node);
            goto out;
         }
      }
   }
   btree_node_unget(cc, cfg, &node);
   result = TRUE;

out:
   return result;
}

bool
btree_verify_tree(cache *cc, btree_config *cfg, page_reference *ref, page_type type)
{
   return btree_verify_node(cc, cfg, ref, type, TRUE);
}

void
btree_print_lookup(cache        *cc,        // IN
                   btree_config *cfg,       // IN
                   uint64        root_addr, // IN
                   page_type     type,      // IN
                   const slice   key)         // IN
{
   btree_node node, child_node;
   uint32     h;
   int64      child_idx;

   node.ref.addr = root_addr;
   btree_print_node(Platform_default_log_handle, cc, cfg, &node);
   btree_node_get(cc, cfg, &node, type, NULL);

   for (h = node.hdr->height; h > 0; h--) {
      bool found;
      child_idx = btree_find_pivot(cfg, node.hdr, key, &found);
      if (child_idx < 0) {
         child_idx = 0;
      }
      child_node.ref = btree_get_child_ref(cfg, node.hdr, child_idx);
      btree_print_node(Platform_default_log_handle, cc, cfg, &child_node);
      btree_node_get(cc, cfg, &child_node, type, NULL);
      btree_node_unget(cc, cfg, &node);
      node = child_node;
   }

   bool  found;
   int64 idx = btree_find_tuple(cfg, node.hdr, key, &found);
   platform_default_log(
      "Matching index: %lu (%d) of %u\n", idx, found, node.hdr->num_entries);
   btree_node_unget(cc, cfg, &node);
}

/*
 *-----------------------------------------------------------------------------
 * btree_config_init --
 *
 *      Initialize btree config values
 *-----------------------------------------------------------------------------
 */
void
btree_config_init(btree_config *btree_cfg,
                  cache_config *cache_cfg,
                  data_config  *data_cfg,
                  uint64        rough_count_height)
{
   btree_cfg->cache_cfg          = cache_cfg;
   btree_cfg->data_cfg           = data_cfg;
   btree_cfg->rough_count_height = rough_count_height;
}




