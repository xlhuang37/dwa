// Copyright 2018-2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
 * trunk.c --
 *
 *     This file contains the implementation for SplinterDB.
 */

#include "platform.h"

#include "trunk.h"
#include "btree.h"
#include "memtable.h"
#include "routing_filter.h"
#include "shard_log.h"
#include "merge.h"
#include "task.h"
#include "util.h"
#include "srq.h"
#include "sig.h"

#include "poison.h"

#define LATENCYHISTO_SIZE 15

static const int64 latency_histo_buckets[LATENCYHISTO_SIZE] = {
   1,          // 1   ns
   10,         // 10  ns
   100,        // 100 ns
   500,        // 500 ns
   1000,       // 1   us
   5000,       // 5   us
   10000,      // 10  us
   100000,     // 100 us
   500000,     // 500 us
   1000000,    // 1   ms
   5000000,    // 5   ms
   10000000,   // 10  ms
   100000000,  // 100 ms
   1000000000, // 1   s
   10000000000 // 10  s
};

/*
 * At any time, one Memtable is "active" for inserts / updates.
 * At any time, the most # of Memtables that can be active or in one of these
 * states, such as, compaction, incorporation, reclamation, is given by this
 * limit.
 */
#define TRUNK_NUM_MEMTABLES (4)

/*
 * These are hard-coded to values so that statically allocated
 * structures sized by these limits can fit within 4K byte pages.
 *
 * NOTE: The bundle and sub-bundle related limits below are used to size arrays
 * of structures in splinter_trunk_hdr{}; i.e. Splinter pages of type
 * PAGE_TYPE_TRUNK. So these constants do affect disk-resident structures.
 */
#define TRUNK_MAX_PIVOTS            (20)
#define TRUNK_MAX_BUNDLES           (12)
#define TRUNK_MAX_SUBBUNDLES        (24)
#define TRUNK_MAX_SUBBUNDLE_FILTERS (24U)

/*
 * For a "small" range query, you don't want to prefetch pages.
 * This is the minimal # of items requested before we turn ON prefetching.
 * (Empirically established through past experiments, for small key-value
 * pairs. So, _may_ be less efficient in general cases. Needs a revisit.)
 */
#define TRUNK_PREFETCH_MIN (16384)

/*
 * If space reclamation had been configured when Splinter was instantiated.
 * Splinter can perform extra compactions to reclaim space.
 * Compactions are added to the space reclamation queue if the "estimated"
 * amount of space that can be reclaimed is > this limit.
 */
#define TRUNK_MIN_SPACE_RECL (2048)

/* Some randomly chosen Splinter super-block checksum seed. */
#define TRUNK_SUPER_CSUM_SEED (42)

/*
 * When a leaf becomes full, Splinter estimates the amount of data in the leaf.
 * If the 'estimated' amount of data is > this threshold, Splinter will split
 * the leaf. Otherwise, the leaf page will be compacted.
 * (This limit has also been empirically established thru in-house experiments.)
 */
#define TRUNK_SINGLE_LEAF_THRESHOLD_PCT (75)


#define TRUNK_INVALID_PIVOT_NO (UINT16_MAX)

/*
 * Trunk logging functions.
 *
 * If verbose_logging_enabled is enabled in trunk_config, these functions print
 * to cfg->log_handle.
 */

static inline bool
trunk_verbose_logging_enabled(trunk_handle *spl)
{
   return spl->cfg.verbose_logging_enabled;
}

static inline platform_log_handle *
trunk_log_handle(trunk_handle *spl)
{
   platform_assert(trunk_verbose_logging_enabled(spl));
   platform_assert(spl->cfg.log_handle != NULL);
   return spl->cfg.log_handle;
}

static inline platform_status
trunk_open_log_stream_if_enabled(trunk_handle           *spl,
                                 platform_stream_handle *stream)
{
   if (trunk_verbose_logging_enabled(spl)) {
      return platform_open_log_stream(stream);
   }
   return STATUS_OK;
}

static inline void
trunk_close_log_stream_if_enabled(trunk_handle           *spl,
                                  platform_stream_handle *stream)
{
   if (trunk_verbose_logging_enabled(spl)) {
      platform_assert(stream != NULL);
      platform_close_log_stream(stream, trunk_log_handle(spl));
   }
}

static inline void
print_sig_if_enabled(trunk_handle *spl, char *hash, char* msg) {
   if (trunk_verbose_logging_enabled(spl)) {
      print_sig(hash, HASH_SIZE, msg);
   }
}

#define trunk_log_stream_if_enabled(spl, _stream, message, ...)                \
   do {                                                                        \
      if (trunk_verbose_logging_enabled(spl)) {                                \
         platform_log_stream(                                                  \
            (_stream), "[%3lu] " message, platform_get_tid(), ##__VA_ARGS__);  \
      }                                                                        \
   } while (0)

#define trunk_default_log_if_enabled(spl, message, ...)                        \
   do {                                                                        \
      if (trunk_verbose_logging_enabled(spl)) {                                \
         platform_default_log(message, __VA_ARGS__);                           \
      }                                                                        \
   } while (0)

void
trunk_print_locked_node(platform_log_handle *log_handle,
                        trunk_handle        *spl,
                        page_handle         *node);

static inline void
trunk_log_node_if_enabled(platform_stream_handle *stream,
                          trunk_handle           *spl,
                          page_handle            *node)
{
   if (trunk_verbose_logging_enabled(spl)) {
      platform_log_handle *log_handle =
         platform_log_stream_to_log_handle(stream);
      trunk_print_locked_node(log_handle, spl, node);
   }
}

/*
 *-----------------------------------------------------------------------------
 * SplinterDB Structure:
 *
 *       SplinterDB is a size-tiered Be-tree. It has a superstructure called
 *       the trunk tree, which consists of trunk nodes. Each trunk node
 *       contains pointers to a collection of branches. Each branch is a B-tree
 *       which stores key-value pairs (tuples). All the actual data is stored
 *       in the branches, and the trunk indexes and organizes the data.
 *-----------------------------------------------------------------------------
 */

/*
 *-----------------------------------------------------------------------------
 * Substructures:
 *
 *       B-trees:
 *          SplinterDB makes use of B-trees, which come in two flavors, dynamic
 *          and static.
 *
 *          dynamic: Dynamic B-trees are used in the memtable (see
 *             below) and are mutable B-trees, supporting
 *             insertions. The mutable operations on B-trees must use
 *             a btree_dynamic_handle.
 *
 *          static: Static B-trees are used as branches and are
 *             immutable. Static btrees are accessed
 *             using their root_addr, which is thinly wrapped using
 *             their root_addr, which is thinly wrapped using
 *             btree_static_handle.
 *-----------------------------------------------------------------------------
 */


/*
 *-----------------------------------------------------------------------------
 * Insertion Path:
 *
 *       Memtable Insertions are first inserted into a memtable, which
 *          is a dynamic btree. SplinterDB uses
 *          multiple memtables so that when one memtable fills,
 *          insertions can continue into another memtable while the
 *          first is incorporated.
 *
 *          As part of this process, the generation number of the leaf into
 *          which the new tuple is placed is returned and stored in the log (if
 *          used) in order to establish a per-key temporal ordering.  The
 *          memtable also keeps a list of fingerprints, fp_arr, which are used
 *          to build the filter when the memtable becomes a branch.
 *
 *       Incorporation When the memtable fills, it is incorporated
 *          into the root node. The memtable locks itself to inserts
 *          (but not lookups), Splinter switches the active memtable,
 *          then the filter is built from the fp_arr, and the
 *          btree in the memtable is inserted into the
 *          root as a new (distinct) branch.  Then the memtable is
 *          reinitialized with a new (empty) btree and unlocked.
 *
 *       Flushing
 *          A node is considered full when it has max_tuples_per_node tuples
 *          (set to be fanout * memtable_capacity) or when it has
 *          max_branches_per_node branches. The first condition ensures that
 *          data moves down the tree and the second limits the number of
 *          branches on a root-to-leaf path and therefore the worst-case lookup
 *          cost.
 *
 *          When a node fills, a flush is initiated to each pivot (child) of
 *          the node which has at least max_branches_per_node live branches. If
 *          the node is still full, it picks the pivot which has the most
 *          tuples and flushes to that child and repeats this process until the
 *          node is no longer full.
 *
 *          A flush consists of flushing all the branches which are live for
 *          the pivot into a bundle in the child. A bundle is a contiguous
 *          range of branches in a trunk node, see trunk node documentation
 *          below. A flush to a given pivot makes all branches and bundles in
 *          the parent no longer "live" for that pivot.
 *
 *       Compaction (after flush)
 *          After a flush completes, a compact_bundle job is issued for the
 *          bundle which was created. This job first checks if the node is full
 *          and if so flushes until it is no longer full. Then it compacts all
 *          the tuples in the bundle which are live for the node (are within
 *          the node's key range and have not been flushed), and replaces the
 *          bundle with the resulting compacted branch.
 *
 *       Split (internal)
 *          During a flush, if the child has more pivots than the configured
 *          fanout, it is split. Note that pivots are added at other times (to
 *          the parent of an internal or leaf split), so nodes may
 *          temporarily exceed the fanout. Splits are not initiated then,
 *          because the hand-over-hand locking protocol means that the lock of
 *          the grandparent is not held and it is awkward for try to acquire
 *          locks going up the tree.
 *
 *          An internal node split is a logical split: the trunk node is
 *          copied, except the first (fanout/2) pivots become the pivots of
 *          the left node and the remaining pivots become the right node. No
 *          compaction is initiated, and the branches and bundles of the node
 *          pre-split are shared between the new left and right nodes.
 *
 *       Split (leaf)
 *          When a leaf has more than cfg->max_tuples_per_node (fanout *
 *          memtable_capacity), it is considered full.
 *
 *          When a leaf is full, it is split logically: new pivots are
 *          calculated, new leaves are created with those pivots as min/max
 *          keys, and all the branches in the leaf at the time of the split are
 *          shared between them temporarily as a single bundle in each.  This
 *          split happens synchronously with the flush.
 *
 *          A compact_bundle job is issued for each new leaf, which
 *          asynchronously compacts the shared branches into a single unshared
 *          branch with the tuples from each new leaf's range.
 *-----------------------------------------------------------------------------
 */

/*
 *-----------------------------------------------------------------------------
 * Interactions between Concurrent Processes
 *
 *       The design of SplinterDB allows flushes, compactions, internal node
 *       split and leaf splits to happen concurrently, even within the same
 *       node. The ways in which these processes can interact are detailed
 *       here.
 *
 *  o Flushes and compactions:
 *
 *       1. While a compaction has been scheduled or is in process, a flush may
 *          occur. This will flush the bundle being compacted to the child and
 *          the in-progress compaction will continue as usual. Note that the
 *          tuples which are flushed will still be compacted if the compaction
 *          is in progress, which results in some wasted work.
 *       2. As a result of 1., while a compaction has been scheduled, its
 *          bundle may be flushed to all children, so that it is no longer
 *          live. In this case, when the compact_bundle job initiates, it
 *          detects that the bundle is not live and aborts before compaction.
 *       3. Similarly, if the bundle for an in-progress compaction is flushed
 *          to all children, when it completes, it will detect that the bundle
 *          is no longer live and it will discard the output.
 *
 *  o Flushes and internal/leaf splits:
 *
 *          Flushes and internal/leaf splits are synchronous and do not
 *          interact.
 *
 *  o Internal splits and compaction:
 *
 *       4. If an internal split occurs in a node which has a scheduled
 *          compaction, when the compact_bundle job initiates it will detect
 *          the node split using the node's generation number
 *          (hdr->generation). It then creates a separate compact_bundle job on
 *          the new sibling.
 *       5. If an internal split occurs in a node with an in-progress
 *          compaction, the bundle being compacted is copied to the new
 *          sibling.  When the compact_bundle job finishes compaction and
 *          fetches the node to replace the bundle, the node split is detected
 *          using the generation number, and the bundle is replaced in the new
 *          sibling as well. Note that the output of the compaction will
 *          contain tuples for both the node and its new sibling.
 *
 *  o Leaf splits and compaction:
 *
 *       6. If a compaction is scheduled or in progress when a leaf split
 *          triggers, the leaf split will start its own compaction job on the
 *          bundle being compacted. When the compaction job initiates or
 *          finishes, it will detect the leaf split using the generation number
 *          of the leaf, and abort.
 *-----------------------------------------------------------------------------
 */

/*
 *-----------------------------------------------------------------------------
 * Trunk Nodes: splinter_trunk_hdr{}: Disk-resident structure
 *
 *   A trunk node, on pages of PAGE_TYPE_TRUNK type, consists of the following:
 *
 *       header
 *          meta data
 *       ---------
 *       array of bundles
 *          When a collection of branches are flushed into a node, they are
 *          organized into a bundle. This bundle will be compacted into a
 *          single branch by a call to trunk_compact_bundle. Bundles are
 *          implemented as a collection of subbundles, each of which covers a
 *          range of branches.
 *       ----------
 *       array of subbundles
 *          A subbundle consists of the branches from a single ancestor (really
 *          that ancestor's pivot). During a flush, all the whole branches in
 *          the parent are collected into a subbundle in the child and any
 *          subbundles in the parent are copied to the child.
 *
 *          Subbundles function properly in the current design, but are not
 *          used for anything. They are going to be used for routing filters.
 *       ----------
 *       array of pivots: Each node has a pivot corresponding to each
 *          child as well as an additional last pivot which contains
 *          an exclusive upper bound key for the node. Each pivot has
 *          a key which is an inclusive lower bound for the keys in
 *          its child node (as well as the btree
 *          rooted there). This means that the key for the 0th pivot
 *          is an inclusive lower bound for all keys in the node.
 *          Each pivot also has its own start_branch, which is used to
 *          determine which branches have tuples for that pivot (the
 *          range start_branch to end_branch).
 *
 *          Each pivot's key is accessible via a call to trunk_get_pivot and
 *          the remaining data is accessible via a call to
 *          trunk_get_pivot_data.
 *
 *          The number of pivots has two different limits: a soft limit
 *          (fanout) and a hard limit (max_pivot_keys). When the soft limit is
 *          reached, it will cause the node to split the next time it is
 *          flushed into (see internal node splits above). Note that multiple
 *          pivots can be added to the parent of a leaf during a split and
 *          multiple splits could theoretically occur before the node is
 *          flushed into again, so the fanout limit may temporarily be exceeded
 *          by multiple pivots. The hard limit is the amount of physical space
 *          in the node which can be used for pivots and cannot be exceeded. By
 *          default the fanout is 8 and the hard limit is 3x the fanout. Note
 *          that the additional last pivot (containing the exclusive upper
 *          bound to the node) counts towards the hard limit (because it uses
 *          physical space), but not the soft limit.
 *       ----------
 *       array of branches
 *          whole branches: the branches from hdr->start_branch to
 *             hdr->start_frac_branch are "whole" branches, each of which is
 *             the output of a compaction or incorporation.
 *          fractional branches: from hdr->start_frac_branch to hdr->end_branch
 *             are "fractional" branches that are part of bundles and are in
 *             the process of being compacted into whole branches.
 *          Logically, each whole branch and each bundle counts toward the
 *          number of branches in the node (or pivot), since each bundle
 *          represents a single branch after compaction.
 *
 *          There are two limits on the number of branches in a node. The soft
 *          limit (max_branches_per_node) refers to logical branches (each
 *          whole branch and each bundle counts as a logical branch), and when
 *          there are more logical branches than the soft limit, the node is
 *          considered full and flushed until there are fewer branches than the
 *          soft limit. The hard limit (hard_max_branches_per_node) is the
 *          number of branches (whole and fractional) for which there is
 *          physical room in the node, and as a result cannot be exceeded. An
 *          attempt to flush into a node which is at the hard limit will fail.
 *-----------------------------------------------------------------------------
 */


/*
 *-----------------------------------------------------------------------------
 * structs
 *-----------------------------------------------------------------------------
 */

/*
 *-----------------------------------------------------------------------------
 * Splinter Super Block: Disk-resident structure.
 * Super block lives on page of page type == PAGE_TYPE_SUPERBLOCK.
 *-----------------------------------------------------------------------------
 */
typedef struct ONDISK trunk_super_block {
   page_reference root_ref; // Address of the root of the trunk for the instance
                            // referenced by this superblock.
   uint64      meta_tail;
   uint64      log_addr;
   uint64      log_meta_addr;
   uint64      timestamp;
   uint64      latest_filter_id;
   uint64      latest_log_gen_id;
   bool        checkpointed;
   bool        dismounted;
   //checksum128 checksum;
   char        hash[HASH_SIZE];
} trunk_super_block;

/*
 * A subbundle is a collection of branches which originated in the same node.
 * It is used to organize branches with their routing filters when they are
 * flushed or otherwise moved or reorganized. A query to the node uses the
 * routing filter to filter the branches in the subbundle.
 * Disk-resident artifact.
 */
typedef uint16 trunk_subbundle_state_t;
typedef enum trunk_subbundle_state {
   SB_STATE_UNCOMPACTED_INDEX = 0,
   SB_STATE_UNCOMPACTED_LEAF,
   SB_STATE_COMPACTED, // compacted subbundles are always index
} trunk_subbundle_state;

/*
 *-----------------------------------------------------------------------------
 * Splinter Sub-bundle: Disk-resident structure on PAGE_TYPE_TRUNK pages.
 *-----------------------------------------------------------------------------
 */
typedef struct ONDISK trunk_subbundle {
   trunk_subbundle_state_t state;
   uint16                  start_branch;
   uint16                  end_branch;
   uint16                  start_filter;
   uint16                  end_filter;
} trunk_subbundle;

/*
 *-----------------------------------------------------------------------------
 * Splinter Bundle: Disk-resident structure on PAGE_TYPE_TRUNK pages.
 *
 * A flush moves branches from the parent to a bundle in the child. The bundle
 * is then compacted with a compact_bundle job.
 *
 * Branches are organized into subbundles.
 *
 * When a compact_bundle job completes, the branches in the bundle are replaced
 * with the outputted branch of the compaction and the bundle is marked
 * compacted. If there is not an earlier uncompacted bundle, the bundle can be
 * released and the compacted branch can become a whole branch. This is to
 * maintain the invariant that the outstanding bundles form a contiguous range.
 *-----------------------------------------------------------------------------
 */
typedef struct ONDISK trunk_bundle {
   uint16 start_subbundle;
   uint16 end_subbundle;
   uint64 num_tuples;
   uint64 num_kv_bytes;
} trunk_bundle;

/*
 *-----------------------------------------------------------------------------
 * Trunk headers: Disk-resident structure
 *
 * Contains metadata for trunk nodes. See below for comments on fields.
 * Found on pages of page type == PAGE_TYPE_TRUNK
 *
 * Generation numbers are used by asynchronous processes to detect node splits.
 *    internal nodes: Splits increment the generation number of the left node.
 *       If a process visits a node with generation number g, then returns at a
 *       later point, it can find all the nodes which it splits into by search
 *       right until it reaches a node with generation number g (inclusive).
 *    leaves: Splits increment the generation numbers of all the resulting
 *       leaves. This is because there are no processes which need to revisit
 *       all the created leaves.
 *-----------------------------------------------------------------------------
 */
typedef struct ONDISK trunk_hdr {
   uint16 num_pivot_keys;   // number of used pivot keys (== num_children + 1)
   uint16 height;           // height of the node
   uint64 generation;       // counter incremented on a node split
   uint64 pivot_generation; // counter incremented when new pivots are added

   uint16 start_branch;      // first live branch
   uint16 start_frac_branch; // first fractional branch (branch in a bundle)
   uint16 end_branch;        // successor to the last live branch
   uint16 start_bundle;      // first live bundle
   uint16 end_bundle;        // successor to the last live bundle
   uint16 start_subbundle;   // first live subbundle
   uint16 end_subbundle;     // successor to the last live subbundle
   uint16 start_sb_filter;   // first subbundle filter
   uint16 end_sb_filter;     // successor to the last sb filter

   trunk_bundle    bundle[TRUNK_MAX_BUNDLES];
   trunk_subbundle subbundle[TRUNK_MAX_SUBBUNDLES];
   routing_filter  sb_filter[TRUNK_MAX_SUBBUNDLE_FILTERS];
} trunk_hdr;

/*
 *-----------------------------------------------------------------------------
 * Splinter Pivot Data: Disk-resident structure on Trunk pages
 *
 * A pivot consists of the pivot key (of size cfg.key_size) followed by a
 * trunk_pivot_data
 *
 * The generation is used by asynchronous processes to determine when a pivot
 * has split
 *-----------------------------------------------------------------------------
 */
typedef struct ONDISK trunk_pivot_data {
   page_reference ref;                // it has PBN of the child
   uint64 num_kv_bytes_whole;  // # kv bytes for this pivot in whole branches
   uint64 num_kv_bytes_bundle; // # kv bytes for this pivot in bundles
   uint64 num_tuples_whole;    // # tuples for this pivot in whole branches
   uint64 num_tuples_bundle;   // # tuples for this pivot in bundles
   uint64 generation;          // receives new higher number when pivot splits
   uint16 start_branch;        // first branch live (not used in leaves)
   uint16 start_bundle;        // first bundle live (not used in leaves)
   routing_filter filter;      // routing filter for keys in this pivot
   int64          srq_idx;     // index in the space rec queue
} trunk_pivot_data;

/*
 * Used to specify compaction bundle "task" request. These enums specify
 * the compaction bundle request type. (Not disk-resident.)
 */
typedef enum trunk_compaction_type {
   TRUNK_COMPACTION_TYPE_INVALID = 0,
   TRUNK_COMPACTION_TYPE_MEMTABLE,
   TRUNK_COMPACTION_TYPE_FLUSH,
   TRUNK_COMPACTION_TYPE_LEAF_SPLIT,
   TRUNK_COMPACTION_TYPE_SINGLE_LEAF_SPLIT,
   TRUNK_COMPACTION_TYPE_SPACE_REC,
   NUM_TRUNK_COMPACTION_TYPES,
} trunk_compaction_type;

// arguments to a compact_bundle job
struct trunk_compact_bundle_req {
   trunk_handle         *spl;
   char                  start_key[MAX_KEY_SIZE];
   char                  end_key[MAX_KEY_SIZE];
   uint16                height;
   uint16                bundle_no;
   trunk_compaction_type type;
   uint64                pivot_generation[TRUNK_MAX_PIVOTS];
   uint64                max_pivot_generation;
   uint64                input_pivot_tuple_count[TRUNK_MAX_PIVOTS];
   uint64                output_pivot_tuple_count[TRUNK_MAX_PIVOTS];
   uint64                input_pivot_kv_byte_count[TRUNK_MAX_PIVOTS];
   uint64                output_pivot_kv_byte_count[TRUNK_MAX_PIVOTS];
   uint64                tuples_reclaimed;
   uint64                kv_bytes_reclaimed;
   uint32               *fp_arr;
};

// an iterator which skips masked pivots
typedef struct trunk_btree_skiperator {
   iterator       super;
   uint64         curr;
   uint64         end;
   trunk_branch   branch;
   btree_iterator itor[TRUNK_MAX_PIVOTS];
} trunk_btree_skiperator;

// for find_pivot
typedef enum lookup_type {
   less_than,
   less_than_or_equal,
   greater_than,
   greater_than_or_equal,
} lookup_type;

// for for_each_node
typedef bool (*node_fn)(trunk_handle *spl, page_reference *ref, void *arg);

// Used by trunk_compact_bundle()
typedef struct {
   trunk_btree_skiperator skip_itor[TRUNK_RANGE_ITOR_MAX_BRANCHES];
   iterator              *itor_arr[TRUNK_RANGE_ITOR_MAX_BRANCHES];
   key_buffer             saved_pivot_keys[TRUNK_MAX_PIVOTS];
} compact_bundle_scratch;

// Used by trunk_split_leaf()
typedef struct {
   char           pivot[TRUNK_MAX_PIVOTS][MAX_KEY_SIZE];
   btree_iterator btree_itor[TRUNK_RANGE_ITOR_MAX_BRANCHES];
   iterator      *rough_itor[TRUNK_RANGE_ITOR_MAX_BRANCHES];
} split_leaf_scratch;

/*
 * Union of various data structures that can live on the per-thread
 * scratch memory provided by the task subsystem and are needed by
 * splinter's task dispatcher routines.
 */
typedef union {
   compact_bundle_scratch compact_bundle;
   split_leaf_scratch     split_leaf;
} trunk_task_scratch;


/*
 *-----------------------------------------------------------------------------
 * Function declarations
 *-----------------------------------------------------------------------------
 */

// clang-format off
static inline bool                 trunk_is_leaf                   (trunk_handle *spl, page_handle *node);
static inline bool                 trunk_is_leaf                   (trunk_handle *spl, page_handle *node);
static inline int                  trunk_key_compare               (trunk_handle *spl, const char *key1, const char *key2);
static inline page_handle *        trunk_node_get                  (trunk_handle *spl, page_reference *ref);
static inline void                 trunk_node_unget                (trunk_handle *spl, page_handle **node);
static inline void                 trunk_node_claim                (trunk_handle *spl, page_handle **node);
static inline void                 trunk_node_unclaim              (trunk_handle *spl, page_handle *node);
static inline void                 trunk_node_lock                 (trunk_handle *spl, page_handle *node);
static inline void                 trunk_node_unlock               (trunk_handle *spl, page_handle *node, page_reference *ref, int line);
page_handle *                      trunk_alloc                     (trunk_handle *spl, uint64 height);
static inline char *               trunk_get_pivot                 (trunk_handle *spl, page_handle *node, uint16 pivot_no);
static inline trunk_pivot_data    *trunk_get_pivot_data            (trunk_handle *spl, page_handle *node, uint16 pivot_no);
static inline void                 trunk_set_pivot_data_ref        (trunk_handle *spl, page_handle *node, uint16 pivot_no, page_handle *child);
static inline uint16               trunk_find_pivot                (trunk_handle *spl, page_handle *node, const char *key, lookup_type comp);
platform_status                    trunk_add_pivot                 (trunk_handle *spl, page_handle *parent, page_handle *child, uint16 pivot_no);
static inline uint16               trunk_num_children              (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_num_pivot_keys            (trunk_handle *spl, page_handle *node);
static inline void                 trunk_inc_num_pivot_keys        (trunk_handle *spl, page_handle *node);
static inline char *               trunk_max_key                   (trunk_handle *spl, page_handle *node);
static inline char *               trunk_min_key                   (trunk_handle *spl, page_handle *node);
static inline uint64               trunk_pivot_num_tuples          (trunk_handle *spl, page_handle *node, uint16 pivot_no);
static inline uint64               trunk_pivot_kv_bytes            (trunk_handle *spl, page_handle *node, uint16 pivot_no);
static inline void                 trunk_pivot_branch_tuple_counts (trunk_handle *spl, page_handle  *node, uint16 pivot_no, uint16 branch_no, uint64 *num_tuples, uint64 *num_kv_bytes);
void                               trunk_pivot_recount_num_tuples_and_kv_bytes  (trunk_handle *spl, page_handle *node, uint64 pivot_no);
static inline bool                 trunk_has_vacancy               (trunk_handle *spl, page_handle *node, uint16 num_new_branches);
static inline uint16               trunk_add_bundle_number         (trunk_handle *spl, uint16 start, uint16 end);
static inline uint16               trunk_subtract_bundle_number    (trunk_handle *spl, uint16 start, uint16 end);
static inline trunk_bundle        *trunk_get_bundle                (trunk_handle *spl, page_handle *node, uint16 bundle_no);
static inline uint16               trunk_get_new_bundle            (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_bundle_start_branch       (trunk_handle *spl, page_handle *node, trunk_bundle *bundle);
static inline uint16               trunk_start_bundle              (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_inc_start_bundle          (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_end_bundle                (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_bundle_clear_subbundles   (trunk_handle *spl, page_handle *node, trunk_bundle *bundle);
static inline uint16               trunk_add_subbundle_number      (trunk_handle *spl, uint16 start, uint16 end);
static inline uint16               trunk_subtract_subbundle_number (trunk_handle *spl, uint16 start, uint16 end);
static inline uint16               trunk_end_subbundle             (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_end_sb_filter             (trunk_handle *spl, page_handle *node);
static inline trunk_branch        *trunk_get_branch                (trunk_handle *spl, page_handle *node, uint32 k);
static inline trunk_branch        *trunk_get_new_branch            (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_start_branch              (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_end_branch                (trunk_handle *spl, page_handle *node);
static inline uint16               trunk_start_frac_branch         (trunk_handle *spl, page_handle *node);
static inline void                 trunk_set_start_frac_branch     (trunk_handle *spl, page_handle *node, uint16 branch_no);
static inline uint16               trunk_branch_count              (trunk_handle *spl, page_handle *node);
static inline bool                 trunk_branch_valid              (trunk_handle *spl, page_handle *node, uint64 branch_no);
static inline bool                 trunk_branch_live               (trunk_handle *spl, page_handle *node, uint64 branch_no);
static inline bool                 trunk_branch_live_for_pivot     (trunk_handle *spl, page_handle *node, uint64 branch_no, uint16 pivot_no);
static inline bool                 trunk_branch_is_whole           (trunk_handle *spl, page_handle *node, uint64 branch_no);
trunk_bundle *                     trunk_flush_into_bundle         (trunk_handle *spl, page_handle *parent, page_handle *child, trunk_pivot_data *pdata, trunk_compact_bundle_req *req);
void                               trunk_replace_bundle_branches   (trunk_handle *spl, page_handle *node, trunk_branch *new_branch, trunk_compact_bundle_req *req);
static inline uint16               trunk_add_branch_number         (trunk_handle *spl, uint16 branch_no, uint16 offset);
static inline uint16               trunk_subtract_branch_number    (trunk_handle *spl, uint16 branch_no, uint16 offset);
static inline void                 trunk_dec_ref                   (trunk_handle *spl, trunk_branch *branch, bool is_memtable);
static inline void                 trunk_zap_branch_range          (trunk_handle *spl, trunk_branch *branch, const char *start_key, const char *end_key, page_type type);
static inline void                 trunk_inc_intersection          (trunk_handle *spl, trunk_branch *branch, const char *key, bool is_memtable);
void                               trunk_memtable_flush_virtual    (void *arg, uint64 generation);
platform_status                    trunk_memtable_insert           (trunk_handle *spl, char *key, message data);
void                               trunk_bundle_build_filters      (void *arg, void *scratch);
static inline void                 trunk_inc_filter                (trunk_handle *spl, routing_filter *filter);
static inline void                 trunk_dec_filter                (trunk_handle *spl, routing_filter *filter);
void                               trunk_compact_bundle            (void *arg, void *scratch);
platform_status                    trunk_flush                     (trunk_handle *spl, page_handle *parent, trunk_pivot_data *pdata, bool is_space_rec);
platform_status                    trunk_flush_fullest             (trunk_handle *spl, page_handle *node);
static inline bool                 trunk_needs_split               (trunk_handle *spl, page_handle *node);
int                                trunk_split_index               (trunk_handle *spl, page_handle *parent, page_handle *child, uint64 pivot_no);
void                               trunk_split_leaf                (trunk_handle *spl, page_handle *parent, page_handle *leaf, page_reference *ref_p, page_reference *ref_ch, uint16 child_idx);
int                                trunk_split_root                (trunk_handle *spl, page_handle     *root);
void                               trunk_print                     (platform_log_handle *log_handle, trunk_handle *spl);
void                               trunk_print_node                (platform_log_handle *log_handle, trunk_handle *spl, page_reference *ref);
static void                        trunk_btree_skiperator_init     (trunk_handle *spl, trunk_btree_skiperator *skip_itor, page_handle *node, uint16 branch_idx, key_buffer pivots[static TRUNK_MAX_PIVOTS]);
void                               trunk_btree_skiperator_get_curr (iterator *itor, slice *key, message *data);
platform_status                    trunk_btree_skiperator_advance  (iterator *itor);
platform_status                    trunk_btree_skiperator_at_end   (iterator *itor, bool *at_end);
void                               trunk_btree_skiperator_print    (iterator *itor);
void                               trunk_btree_skiperator_deinit   (trunk_handle *spl, trunk_btree_skiperator *skip_itor);
bool                               trunk_verify_node               (trunk_handle *spl, page_handle *node);
void                               trunk_maybe_reclaim_space       (trunk_handle *spl);
const static iterator_ops trunk_btree_skiperator_ops = {
   .get_curr = trunk_btree_skiperator_get_curr,
   .at_end   = trunk_btree_skiperator_at_end,
   .advance  = trunk_btree_skiperator_advance,
   .print    = trunk_btree_skiperator_print,
};

// clang-format on

static inline uint64
trunk_page_size(const trunk_config *cfg)
{
   return cache_config_page_size(cfg->cache_cfg);
}

static inline uint64
trunk_extent_size(const trunk_config *cfg)
{
   return cache_config_extent_size(cfg->cache_cfg);
}

static inline uint64
trunk_pages_per_extent(const trunk_config *cfg)
{
   return cache_config_pages_per_extent(cfg->cache_cfg);
}

/*
 *-----------------------------------------------------------------------------
 * Super block functions
 *-----------------------------------------------------------------------------
 */
void
trunk_set_super_block(trunk_handle *spl,
                      bool          is_checkpoint,
                      bool          is_dismount,
                      bool          is_create)
{
   page_reference     super_ref;
   page_handle       *super_page;
   trunk_super_block *super;
   uint64             wait = 1;
   platform_status    rc;

   if (is_create) {
      rc = allocator_alloc_super_addr(spl->al, spl->id, &super_ref);
   } else {
      // TODO(yizheng.jiao): read something from disk, do we need
      // to verify the content.
      rc = allocator_get_super_addr(spl->al, spl->id, &super_ref);
   }
   platform_assert_status_ok(rc);
   super_page = cache_get(spl->cc, &super_ref, TRUE, PAGE_TYPE_SUPERBLOCK, NULL);
   while (!cache_claim(spl->cc, super_page)) {
      platform_sleep(wait);
      wait *= 2;
   }
   wait = 1;
   cache_lock(spl->cc, super_page);

   super            = (trunk_super_block *)super_page->data;
   super->root_ref = spl->root_ref;
   super->latest_filter_id = spl->filter_id;
   super->latest_log_gen_id = spl->log_gen_id;
   //print_sig(spl->root_ref.hash, HASH_SIZE, "root_spl hash");
   //cache_print_page_hash(spl->cc, super_page);
   //cache_print_page_hash(spl->cc, super_page);
   //cache_hash(spl->cc, super_page);

   super->meta_tail = mini_meta_tail(&spl->mini);
   if (spl->cfg.use_log) {
      super->log_addr      = log_addr(spl->log);
      super->log_meta_addr = log_meta_addr(spl->log);
   }
   super->timestamp    = platform_get_real_time();
   super->checkpointed = is_checkpoint;
   super->dismounted   = is_dismount;
   //super->checksum =
   //   platform_checksum128(super,
   //                        sizeof(trunk_super_block) - sizeof(checksum128),
   //                        TRUNK_SUPER_CSUM_SEED);
   trunk_hmac((char*)super, sizeof(trunk_super_block) - sizeof(super->hash),
               super->hash, sizeof(super->hash), PAGE_TYPE_SUPERBLOCK);

   cache_mark_dirty(spl->cc, super_page);
   cache_unlock(spl->cc, super_page);
   cache_unclaim(spl->cc, super_page);
   cache_unget(spl->cc, super_page);
   cache_page_sync(spl->cc, super_page, TRUE, PAGE_TYPE_SUPERBLOCK);
}

trunk_super_block *
trunk_get_super_block_if_valid(trunk_handle *spl, page_handle **super_page)
{
   page_reference     super_ref;
   trunk_super_block *super;

   platform_status rc = allocator_get_super_addr(spl->al, spl->id, &super_ref);
   platform_assert_status_ok(rc);
   *super_page = cache_get(spl->cc, &super_ref, TRUE, PAGE_TYPE_SUPERBLOCK, NULL);
   super       = (trunk_super_block *)(*super_page)->data;

   char hash[HASH_SIZE];
   trunk_hmac((char*)super, sizeof(trunk_super_block) - sizeof(super->hash),
               hash, sizeof(hash), PAGE_TYPE_SUPERBLOCK);
   if (0 != memcmp(super->hash, hash, sizeof(hash))) {
      cache_unget(spl->cc, *super_page);
      *super_page = NULL;
      return NULL;
   }
#if 0
   if (!platform_checksum_is_equal(
          super->checksum,
          platform_checksum128(super,
                               sizeof(trunk_super_block) - sizeof(checksum128),
                               TRUNK_SUPER_CSUM_SEED)))
   {
      cache_unget(spl->cc, *super_page);
      *super_page = NULL;
      return NULL;
   }
#endif
   return super;
}

void
trunk_release_super_block(trunk_handle *spl, page_handle *super_page)
{
   cache_unget(spl->cc, super_page);
}

/*
 *-----------------------------------------------------------------------------
 * Helper/wrapper functions
 *-----------------------------------------------------------------------------
 */

static inline uint16
trunk_height(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->height;
}

static inline uint16
trunk_tree_height(trunk_handle *spl)
{
   page_handle *root        = trunk_node_get(spl, &spl->root_ref);
   uint16       tree_height = trunk_height(spl, root);
   trunk_node_unget(spl, &root);
   return tree_height;
}

static inline bool
trunk_is_leaf(trunk_handle *spl, page_handle *node)
{
   return trunk_height(spl, node) == 0;
}

uint64
trunk_hdr_size()
{
   return sizeof(trunk_hdr);
}

/*
 * The logical branch count is the number of branches the node would have if
 * all compactions completed. This is the number of whole branches plus the
 * number of bundles.
 */
static inline uint16
trunk_logical_branch_count(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   // whole branches
   uint16 num_branches = trunk_subtract_branch_number(
      spl, hdr->start_frac_branch, hdr->start_branch);
   // bundles
   uint16 num_bundles =
      trunk_subtract_bundle_number(spl, hdr->end_bundle, hdr->start_bundle);
   return num_branches + num_bundles;
}

/*
 * A node is full if either it has too many tuples or if it has too many
 * logical branches.
 */
static inline bool
trunk_node_is_full(trunk_handle *spl, page_handle *node)
{
   uint64 num_kv_bytes = 0;
   if (trunk_logical_branch_count(spl, node) > spl->cfg.max_branches_per_node) {
      return TRUE;
   }
   for (uint16 i = 0; i < trunk_num_children(spl, node); i++) {
      num_kv_bytes += trunk_pivot_kv_bytes(spl, node, i);
   }
   return num_kv_bytes > spl->cfg.max_kv_bytes_per_node;
}

bool
trunk_for_each_subtree(trunk_handle *spl, page_reference *ref, node_fn func, void *arg)
{
   // func may be deallocation, so first apply to subtree
   page_handle *node = trunk_node_get(spl, ref);
   if (!trunk_is_leaf(spl, node)) {
      uint16 num_children = trunk_num_children(spl, node);
      for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
         trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
         page_reference ch_ref   = pdata->ref;
         bool              succeeded_on_subtree =
            trunk_for_each_subtree(spl, &ch_ref, func, arg);
         if (!succeeded_on_subtree) {
            goto failed_on_subtree;
         }
      }
   }
   trunk_node_unget(spl, &node);
   return func(spl, ref, arg);

failed_on_subtree:
   trunk_node_unget(spl, &node);
   return FALSE;
}

/*
 * trunk_for_each_node() is an iterator driver function to walk through all
 * nodes in a Splinter tree, and to execute the work-horse 'func' function on
 * each node.
 *
 * Returns: TRUE, if 'func' was successful on all nodes. FALSE, otherwise.
 */
bool
trunk_for_each_node(trunk_handle *spl, node_fn func, void *arg)
{
   return trunk_for_each_subtree(spl, &spl->root_ref, func, arg);
}

static inline btree_config *
trunk_btree_config(trunk_handle *spl)
{
   return &spl->cfg.btree_cfg;
}


/*
 *-----------------------------------------------------------------------------
 * Cache Wrappers
 *-----------------------------------------------------------------------------
 */
static inline page_handle *
trunk_node_get(trunk_handle *spl, page_reference *ref)
{
   return cache_get(spl->cc, ref, TRUE, PAGE_TYPE_TRUNK, NULL);
}

static inline cache_async_result
trunk_node_get_async(trunk_handle *spl, page_reference *ref, trunk_async_ctxt *ctxt)
{
   return cache_get_async(spl->cc, ref, PAGE_TYPE_TRUNK, &ctxt->cache_ctxt);
}

static inline void
trunk_node_async_done(trunk_handle *spl, trunk_async_ctxt *ctxt)
{
   cache_async_done(spl->cc, PAGE_TYPE_TRUNK, &ctxt->cache_ctxt);
}

static inline void
trunk_node_unget(trunk_handle *spl, page_handle **node)
{
   cache_unget(spl->cc, *node);
   *node = NULL;
}

static inline void
trunk_node_claim(trunk_handle *spl, page_handle **node)
{
   page_reference ref;
   uint64 wait = 1;
   while (!cache_claim(spl->cc, *node)) {
      cache_fill_page_reference(spl->cc, (char*)&ref, *node);
      trunk_node_unget(spl, node);
      platform_sleep(wait);
      wait  = wait > 2048 ? wait : 2 * wait;
      *node = trunk_node_get(spl, &ref);
   }
}

static inline void
trunk_node_unclaim(trunk_handle *spl, page_handle *node)
{
   cache_unclaim(spl->cc, node);
}

static inline void
trunk_node_lock(trunk_handle *spl, page_handle *node)
{
   cache_lock(spl->cc, node);
   cache_mark_dirty(spl->cc, node);
}

static inline void
trunk_node_unlock(trunk_handle *spl, page_handle *node, page_reference *ref, int line)
{
   if (ref != NULL) {
      cache_hash(spl->cc, node, node->disk_addr);
      memcpy(ref->hash, cache_get_page_hash(spl->cc, node), HASH_SIZE);
      trunk_default_log_if_enabled(spl, "%s pid=%lu: unlock node addr=%ld\n", __func__, platform_get_tid(), ref->addr);
      print_sig_if_enabled(spl, ref->hash, "unlock node sig");
   }
   cache_unlock(spl->cc, node);
}

page_handle *
trunk_alloc(trunk_handle *spl, uint64 height)
{
   uint64 addr = mini_alloc(&spl->mini, height, NULL_SLICE, NULL);
   return cache_alloc(spl->cc, addr, PAGE_TYPE_TRUNK);
}

/*
 *-----------------------------------------------------------------------------
 * Fetch Trunk Nodes By Key and Height
 *
 * Returns the node whose key range contains key at height height. Returns an
 * error if no such node exists, which should only happen when height >
 * height(root);
 *-----------------------------------------------------------------------------
 */

platform_status
trunk_node_get_by_key_and_height(trunk_handle *spl,      // IN
                                 const char   *key,      // IN
                                 uint16        height,   // IN
                                 page_handle **out_node) // OUT
{
   page_handle *node        = trunk_node_get(spl, &spl->root_ref);
   uint16       root_height = trunk_height(spl, node);
   if (height > root_height) {
      goto error;
   }

   for (uint16 h = root_height; h > height; h--) {
      debug_assert(trunk_height(spl, node) == h);
      uint16 pivot_no = trunk_find_pivot(spl, node, key, less_than_or_equal);
      debug_assert(pivot_no < trunk_num_children(spl, node));
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      page_reference    ch_ref   = pdata->ref;
      page_handle      *child = trunk_node_get(spl, &ch_ref);
      trunk_node_unget(spl, &node);
      node = child;
   }

   debug_assert(trunk_height(spl, node) == height);
   debug_assert(trunk_key_compare(spl, trunk_min_key(spl, node), key) <= 0);
   debug_assert(trunk_key_compare(spl, key, trunk_max_key(spl, node)) < 0);

   *out_node = node;
   return STATUS_OK;

error:
   trunk_node_unget(spl, &node);
   return STATUS_BAD_PARAM;
}


/*
 *-----------------------------------------------------------------------------
 * Circular Buffer Arithmetic
 *
 *       X_add and X_sub add or subtract the offset in the arithmetic of the
 *       circular buffer for X.
 *
 *       X_in_range returns TRUE if the given index is in the range [start,
 *       end] in the circular buffer for X.
 *-----------------------------------------------------------------------------
 */

static inline uint16
trunk_add_branch_number(trunk_handle *spl, uint16 branch_no, uint16 offset)
{
   return (branch_no + offset) % spl->cfg.hard_max_branches_per_node;
}

static inline uint16
trunk_subtract_branch_number(trunk_handle *spl, uint16 branch_no, uint16 offset)
{
   return (branch_no + spl->cfg.hard_max_branches_per_node - offset)
          % spl->cfg.hard_max_branches_per_node;
}

static inline bool
trunk_branch_in_range(trunk_handle *spl,
                      uint16        branch_no,
                      uint16        start,
                      uint16        end)
{
   return trunk_subtract_branch_number(spl, branch_no, start)
          < trunk_subtract_branch_number(spl, end, start);
}

static inline uint16
trunk_add_bundle_number(trunk_handle *spl, uint16 start, uint16 end)
{
   return (start + end) % TRUNK_MAX_BUNDLES;
}

static inline uint16
trunk_subtract_bundle_number(trunk_handle *spl, uint16 start, uint16 end)
{
   return (start + TRUNK_MAX_BUNDLES - end) % TRUNK_MAX_BUNDLES;
}

static inline bool
trunk_bundle_in_range(trunk_handle *spl,
                      uint16        bundle_no,
                      uint16        start,
                      uint16        end)
{
   return trunk_subtract_bundle_number(spl, bundle_no, start)
          < trunk_subtract_bundle_number(spl, end, start);
}

static inline uint16
trunk_add_subbundle_number(trunk_handle *spl, uint16 start, uint16 end)
{
   return (start + end) % TRUNK_MAX_SUBBUNDLES;
}

static inline uint16
trunk_subtract_subbundle_number(trunk_handle *spl, uint16 start, uint16 end)
{
   return (start + TRUNK_MAX_SUBBUNDLES - end) % TRUNK_MAX_SUBBUNDLES;
}

static inline uint16
trunk_add_subbundle_filter_number(trunk_handle *spl, uint16 start, uint16 end)
{
   return (start + end) % TRUNK_MAX_SUBBUNDLE_FILTERS;
}

static inline uint16
trunk_subtract_subbundle_filter_number(trunk_handle *spl,
                                       uint16        start,
                                       uint16        end)
{
   return (start + TRUNK_MAX_SUBBUNDLE_FILTERS - end)
          % TRUNK_MAX_SUBBUNDLE_FILTERS;
}

/*
 *-----------------------------------------------------------------------------
 * Pivot functions
 *-----------------------------------------------------------------------------
 */

static inline char *
trunk_get_pivot(trunk_handle *spl, page_handle *node, uint16 pivot_no)
{
   platform_assert((pivot_no < spl->cfg.max_pivot_keys),
                   "pivot_no = %d, cfg.max_pivot_keys = %lu",
                   pivot_no,
                   spl->cfg.max_pivot_keys);
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return ((char *)hdr) + sizeof(*hdr) + pivot_no * trunk_pivot_size(spl);
}

static inline void
trunk_set_pivot(trunk_handle *spl,
                page_handle  *node,
                uint16        pivot_no,
                const char   *pivot_key)
{
   debug_assert(pivot_no < trunk_num_pivot_keys(spl, node));

   char *dst_pivot_key = trunk_get_pivot(spl, node, pivot_no);
   memmove(dst_pivot_key, pivot_key, trunk_key_size(spl));

   // debug asserts (should be optimized away)
   if (pivot_no != 0) {
      __attribute__((unused)) const char *pred_pivot =
         trunk_get_pivot(spl, node, pivot_no - 1);
      debug_assert(trunk_key_compare(spl, pred_pivot, pivot_key) < 0);
   }
   if (pivot_no < trunk_num_children(spl, node)) {
      __attribute__((unused)) const char *succ_pivot =
         trunk_get_pivot(spl, node, pivot_no + 1);
      debug_assert(trunk_key_compare(spl, pivot_key, succ_pivot) < 0);
   }
}

static inline void
trunk_set_initial_pivots(trunk_handle *spl,
                         page_handle  *node,
                         const char   *min_key,
                         const char   *max_key)
{
   debug_assert(trunk_key_compare(spl, min_key, max_key) < 0);

   trunk_hdr *hdr      = (trunk_hdr *)node->data;
   hdr->num_pivot_keys = 2;

   char *dst_pivot_key = trunk_get_pivot(spl, node, 0);
   memmove(dst_pivot_key, min_key, trunk_key_size(spl));
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, 0);
   ZERO_CONTENTS(pdata);
   pdata->srq_idx = -1;
   dst_pivot_key  = trunk_get_pivot(spl, node, 1);
   memmove(dst_pivot_key, max_key, trunk_key_size(spl));
}

static inline char *
trunk_min_key(trunk_handle *spl, page_handle *node)
{
   return trunk_get_pivot(spl, node, 0);
}

static inline char *
trunk_max_key(trunk_handle *spl, page_handle *node)
{
   return trunk_get_pivot(spl, node, trunk_num_children(spl, node));
}

static inline uint64
trunk_pivot_generation(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->pivot_generation;
}

static inline uint64
trunk_inc_pivot_generation(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->pivot_generation++;
}

uint64
trunk_pivot_size(trunk_handle *spl)
{
   return trunk_key_size(spl) + sizeof(trunk_pivot_data);
}

uint64
trunk_pivot_message_size()
{
   return sizeof(trunk_pivot_data);
}

static inline trunk_pivot_data *
trunk_get_pivot_data(trunk_handle *spl, page_handle *node, uint16 pivot_no)
{
   return (trunk_pivot_data *)(trunk_get_pivot(spl, node, pivot_no)
                               + trunk_key_size(spl));
}

static inline void
trunk_set_pivot_data_ref(trunk_handle *spl, page_handle *node, uint16 pivot_no, page_handle *child)
{
   trunk_pivot_data *pdata = (trunk_pivot_data *)(trunk_get_pivot(spl, node, pivot_no)
                               + trunk_key_size(spl));
   cache_hash(spl->cc, child, child->disk_addr);
   cache_fill_page_reference(spl->cc, (char*)&pdata->ref, child);
}

static inline void
trunk_set_ref_new_root(trunk_handle *spl,
                       page_handle  *node,
                       page_handle  *child)
{
   debug_assert(trunk_height(spl, node) != 0);
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, 0);
   trunk_default_log_if_enabled(spl, "%s pid=%lu: pdata->ref.addr=%lu, child.addr=%lu\n",
                                __func__, platform_get_tid(), pdata->ref.addr, child->disk_addr);
   platform_assert(child->disk_addr == pdata->ref.addr);
   cache_hash(spl->cc, child, child->disk_addr);
   cache_fill_page_reference(spl->cc, (char*)&pdata->ref, child);
}

static inline void
trunk_set_pivot_data_new_root(trunk_handle *spl,
                              page_handle  *node,
                              page_handle  *child)
{
   debug_assert(trunk_height(spl, node) != 0);
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, 0);

   pdata->ref.addr = child->disk_addr;

   pdata->num_tuples_whole    = 0;
   pdata->num_kv_bytes_whole  = 0;
   pdata->num_tuples_bundle   = 0;
   pdata->num_kv_bytes_bundle = 0;
   pdata->start_branch        = trunk_start_branch(spl, node);
   pdata->start_bundle        = trunk_end_bundle(spl, node);
   ZERO_STRUCT(pdata->filter);
}

static inline void
trunk_copy_pivot_data_from_pred(trunk_handle *spl,
                                page_handle  *node,
                                uint16        pivot_no,
                                page_handle  *child)
{
   debug_assert(trunk_height(spl, node) != 0);
   debug_assert(pivot_no != 0);
   trunk_pivot_data *pdata      = trunk_get_pivot_data(spl, node, pivot_no);
   trunk_pivot_data *pred_pdata = trunk_get_pivot_data(spl, node, pivot_no - 1);

   memmove(pdata, pred_pdata, sizeof(*pdata));

   trunk_default_log_if_enabled(spl, "%s pid=%lu: before pdata->ref.addr=%lu\n", __func__, platform_get_tid(), pdata->ref.addr);
   print_sig_if_enabled(spl, pdata->ref.hash, "before pdata->ref.hash");

   cache_hash(spl->cc, child, child->disk_addr);
   cache_fill_page_reference(spl->cc, (char*)&pdata->ref, child);

   trunk_default_log_if_enabled(spl, "%s pid=%lu: after pdata->ref.addr=%lu\n", __func__, platform_get_tid(), pdata->ref.addr);
   print_sig_if_enabled(spl, pdata->ref.hash, "after pdata->ref.hash");

   pdata->num_tuples_whole    = 0;
   pdata->num_kv_bytes_whole  = 0;
   pdata->num_tuples_bundle   = 0;
   pdata->num_kv_bytes_bundle = 0;
   pred_pdata->generation     = trunk_inc_pivot_generation(spl, node);
   platform_assert(pdata->srq_idx == -1);
}

static inline uint16
trunk_pivot_start_branch(trunk_handle *spl, page_handle *node, uint16 pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->start_branch;
}

static inline uint16
trunk_pivot_start_bundle(trunk_handle *spl, page_handle *node, uint16 pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->start_bundle;
}

static inline void
trunk_inc_generation(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   hdr->generation++;
}

/*
 * Used by find_pivot
 */
static inline uint32
lowerbound(uint32 size)
{
   if (size <= 1)
      return 0;
   return (8 * sizeof(uint32)) - __builtin_clz(size - 1);
}

/*
 * Used by find_pivot
 */
static inline void
trunk_update_lowerbound(uint16 *lo, uint16 *mid, int cmp, lookup_type comp)
{
   switch (comp) {
      case less_than:
      case greater_than_or_equal:
         if (cmp < 0)
            *lo = *mid;
         break;
      case less_than_or_equal:
      case greater_than:
         if (cmp <= 0)
            *lo = *mid;
         break;
      default:
         platform_assert(0);
   }
}

/*
 * find_pivot performs a binary search for the extremal pivot that satisfies
 * comp, e.g. if comp == greater_than, find_pivot finds the smallest pivot
 * which is greater than key. It returns the found pivot's index.
 */
static inline uint16
trunk_find_pivot(trunk_handle *spl,
                 page_handle  *node,
                 const char   *key,
                 lookup_type   comp)
{
   debug_assert(node != NULL);
   uint16 lo_idx = 0, mid_idx;
   uint32 i;
   int    cmp;
   uint32 size = trunk_num_children(spl, node);

   if (size == 0) {
      return 0;
   }

   if (size == 1) {
      cmp = trunk_key_compare(spl, trunk_get_pivot(spl, node, 0), key);
      switch (comp) {
         case less_than:
            debug_assert(cmp < 0);
            return 0;
         case less_than_or_equal:
            debug_assert(cmp <= 0);
            return 0;
         case greater_than:
            return cmp > 0 ? 0 : 1;
         case greater_than_or_equal:
            return cmp >= 0 ? 0 : 1;
      }
   }

   // binary search for the pivot
   mid_idx = size - (1u << (lowerbound(size) - 1));
   size    = 1u << (lowerbound(size) - 1);
   cmp     = trunk_key_compare(spl, trunk_get_pivot(spl, node, mid_idx), key);
   trunk_update_lowerbound(&lo_idx, &mid_idx, cmp, comp);

   for (i = lowerbound(size); i != 0; i--) {
      size /= 2;
      mid_idx = lo_idx + size;
      cmp = trunk_key_compare(spl, trunk_get_pivot(spl, node, mid_idx), key);
      trunk_update_lowerbound(&lo_idx, &mid_idx, cmp, comp);
   }

   switch (comp) {
      case less_than:
      case less_than_or_equal:
         return lo_idx;
      case greater_than:
      case greater_than_or_equal:
         return lo_idx + 1;
      default:
         platform_assert(0);
         return (0);
   }
}

/*
 * branch_live_for_pivot returns TRUE if the branch is live for the pivot and
 * FALSE otherwise.
 */
static inline bool
trunk_branch_live_for_pivot(trunk_handle *spl,
                            page_handle  *node,
                            uint64        branch_no,
                            uint16        pivot_no)
{
   trunk_hdr        *hdr   = (trunk_hdr *)node->data;
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return trunk_subtract_branch_number(spl, branch_no, pdata->start_branch)
          < trunk_subtract_branch_number(
             spl, hdr->end_branch, pdata->start_branch);
}

/*
 * branch_is_whole returns TRUE if the branch is whole and FALSE if it is
 * fractional (part of a bundle) or dead.
 */
static inline bool
trunk_branch_is_whole(trunk_handle *spl, page_handle *node, uint64 branch_no)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_branch_number(spl, branch_no, hdr->start_branch)
          < trunk_subtract_branch_number(
             spl, hdr->start_frac_branch, hdr->start_branch);
}

static inline void
trunk_shift_pivots(trunk_handle *spl,
                   page_handle  *node,
                   uint16        pivot_no,
                   uint16        shift)
{
   debug_assert(trunk_height(spl, node) != 0);
   debug_assert(trunk_num_pivot_keys(spl, node) + shift
                < spl->cfg.max_pivot_keys);
   debug_assert(pivot_no < trunk_num_pivot_keys(spl, node));

   char  *dst_pivot       = trunk_get_pivot(spl, node, pivot_no + shift);
   char  *src_pivot       = trunk_get_pivot(spl, node, pivot_no);
   uint16 pivots_to_shift = trunk_num_pivot_keys(spl, node) - pivot_no;
   size_t bytes_to_shift  = pivots_to_shift * trunk_pivot_size(spl);
   memmove(dst_pivot, src_pivot, bytes_to_shift);
}

/*
 * add_pivot adds a pivot in parent at position pivot_no that points to child.
 */
platform_status
trunk_add_pivot(trunk_handle *spl,
                page_handle  *parent,
                page_handle  *child,
                uint16        pivot_no) // position of new pivot
{
   trunk_default_log_if_enabled(spl, "%s: pid=%lu, child->disk_addr=%lu, parent->disk_addr=%lu, pivot_no=%d\n", 
                                __func__, platform_get_tid(), child->disk_addr, parent->disk_addr, pivot_no);
   // equality is allowed, because we can be adding a pivot at the end
   platform_assert(pivot_no <= trunk_num_children(spl, parent));
   platform_assert(pivot_no != 0);

   if (trunk_num_pivot_keys(spl, parent) >= spl->cfg.max_pivot_keys) {
      // No room to add a pivot
      debug_assert(trunk_num_pivot_keys(spl, parent)
                   == spl->cfg.max_pivot_keys);
      return STATUS_LIMIT_EXCEEDED;
   }

   // move pivots in parent and add new pivot for child
   trunk_shift_pivots(spl, parent, pivot_no, 1);
   trunk_inc_num_pivot_keys(spl, parent);
   const char *pivot_key = trunk_get_pivot(spl, child, 0);
   trunk_set_pivot(spl, parent, pivot_no, pivot_key);

   trunk_copy_pivot_data_from_pred(spl, parent, pivot_no, child);

   return STATUS_OK;
}

void
trunk_add_pivot_new_root(trunk_handle *spl,
                         page_handle  *parent,
                         page_handle  *child)
{
   const char *pivot_key                       = trunk_get_pivot(spl, child, 0);
   __attribute__((unused)) const char *min_key = spl->cfg.data_cfg->min_key;
   debug_assert(trunk_key_compare(spl, pivot_key, min_key) == 0);

   const char *max_key = spl->cfg.data_cfg->max_key;
   trunk_set_initial_pivots(spl, parent, pivot_key, max_key);
   trunk_set_pivot_data_new_root(spl, parent, child);
}

/*
 * pivot_recount_num_tuples recounts num_tuples for the pivot at position
 * pivot_no using a rough count.
 *
 * Used after index splits.
 */
void
trunk_pivot_recount_num_tuples_and_kv_bytes(trunk_handle *spl,
                                            page_handle  *node,
                                            uint64        pivot_no)
{
   trunk_hdr        *hdr      = (trunk_hdr *)node->data;
   trunk_pivot_data *pdata    = trunk_get_pivot_data(spl, node, pivot_no);
   pdata->num_tuples_whole    = 0;
   pdata->num_tuples_bundle   = 0;
   pdata->num_kv_bytes_whole  = 0;
   pdata->num_kv_bytes_bundle = 0;
   for (uint64 branch_no = pdata->start_branch; branch_no != hdr->end_branch;
        branch_no        = trunk_add_branch_number(spl, branch_no, 1))
   {
      uint64 num_tuples;
      uint64 num_kv_bytes;
      trunk_pivot_branch_tuple_counts(
         spl, node, pivot_no, branch_no, &num_tuples, &num_kv_bytes);
      if (trunk_branch_is_whole(spl, node, branch_no)) {
         pdata->num_tuples_whole += num_tuples;
         pdata->num_kv_bytes_whole += num_kv_bytes;
      } else {
         pdata->num_tuples_bundle += num_tuples;
         pdata->num_kv_bytes_bundle += num_kv_bytes;
      }
   }
}

static inline uint64
trunk_pivot_num_tuples(trunk_handle *spl, page_handle *node, uint16 pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->num_tuples_whole + pdata->num_tuples_bundle;
}

static inline uint64
trunk_pivot_num_tuples_whole(trunk_handle *spl,
                             page_handle  *node,
                             uint16        pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->num_tuples_whole;
}

static inline uint64
trunk_pivot_num_tuples_bundle(trunk_handle *spl,
                              page_handle  *node,
                              uint16        pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->num_tuples_bundle;
}

static inline uint64
trunk_pivot_kv_bytes(trunk_handle *spl, page_handle *node, uint16 pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->num_kv_bytes_whole + pdata->num_kv_bytes_bundle;
}

static inline int64
trunk_pivot_kv_bytes_whole(trunk_handle *spl,
                           page_handle  *node,
                           uint16        pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->num_kv_bytes_whole;
}

static inline int64
trunk_pivot_kv_bytes_bundle(trunk_handle *spl,
                            page_handle  *node,
                            uint16        pivot_no)
{
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
   return pdata->num_kv_bytes_bundle;
}

void
trunk_pivot_set_bundle_counts(trunk_handle *spl,
                              page_handle  *node,
                              uint16        pivot_no,
                              uint64        num_tuples,
                              uint64        num_kv_bytes)
{
   trunk_pivot_data *pdata    = trunk_get_pivot_data(spl, node, pivot_no);
   pdata->num_tuples_bundle   = num_tuples;
   pdata->num_kv_bytes_bundle = num_kv_bytes;
}

void
trunk_pivot_clear_counts(trunk_handle *spl, page_handle *node, uint16 pivot_no)
{
   trunk_pivot_data *pdata    = trunk_get_pivot_data(spl, node, pivot_no);
   pdata->num_tuples_whole    = 0;
   pdata->num_tuples_bundle   = 0;
   pdata->num_kv_bytes_whole  = 0;
   pdata->num_kv_bytes_bundle = 0;
}

static inline uint64
trunk_pivot_tuples_to_reclaim(trunk_handle *spl, trunk_pivot_data *pdata)
{
   uint64 tuples_in_pivot = pdata->filter.num_fingerprints;
   uint64 est_unique_tuples =
      routing_filter_estimate_unique_keys(&pdata->filter, &spl->cfg.filter_cfg);
   return tuples_in_pivot > est_unique_tuples
             ? tuples_in_pivot - est_unique_tuples
             : 0;
}

/*
 * Returns the number of whole branches which are live for the pivot
 */
static inline uint64
trunk_pivot_whole_branch_count(trunk_handle     *spl,
                               page_handle      *node,
                               trunk_pivot_data *pdata)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   if (!trunk_branch_is_whole(spl, node, pdata->start_branch))
      return 0;
   return trunk_subtract_branch_number(
      spl, hdr->start_frac_branch, pdata->start_branch);
}

/*
 * Returns the number of bundles which are live for the pivot.
 */
static inline uint16
trunk_pivot_bundle_count(trunk_handle     *spl,
                         page_handle      *node,
                         trunk_pivot_data *pdata)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_bundle_number(
      spl, hdr->end_bundle, pdata->start_bundle);
}

/*
 * Returns the number of subbundles which are live for the pivot.
 */
static inline uint16
trunk_pivot_subbundle_count(trunk_handle     *spl,
                            page_handle      *node,
                            trunk_pivot_data *pdata)
{
   trunk_hdr    *hdr = (trunk_hdr *)node->data;
   uint16        pivot_start_subbundle;
   trunk_bundle *bundle;
   if (trunk_pivot_bundle_count(spl, node, pdata) == 0) {
      return 0;
   }

   bundle                = trunk_get_bundle(spl, node, pdata->start_bundle);
   pivot_start_subbundle = bundle->start_subbundle;
   return trunk_subtract_subbundle_number(
      spl, hdr->end_subbundle, pivot_start_subbundle);
}

static inline uint16
trunk_pivot_start_subbundle(trunk_handle     *spl,
                            page_handle      *node,
                            trunk_pivot_data *pdata)
{
   if (pdata->start_bundle == trunk_end_bundle(spl, node)) {
      return trunk_end_subbundle(spl, node);
   }
   trunk_bundle *bundle = trunk_get_bundle(spl, node, pdata->start_bundle);
   return bundle->start_subbundle;
}

static inline uint16
trunk_pivot_end_subbundle_for_lookup(trunk_handle     *spl,
                                     page_handle      *node,
                                     trunk_pivot_data *pdata)
{
   return trunk_subtract_subbundle_number(
      spl, trunk_pivot_start_subbundle(spl, node, pdata), 1);
}

/*
 * Returns the logical number of branches which are live for the pivot. A
 * logical branch is either a whole branch or a bundle.
 */
static inline uint16
trunk_pivot_logical_branch_count(trunk_handle     *spl,
                                 page_handle      *node,
                                 trunk_pivot_data *pdata)
{
   return trunk_pivot_whole_branch_count(spl, node, pdata)
          + trunk_pivot_bundle_count(spl, node, pdata);
}

/*
 * pivot_needs_flush returns TRUE if the pivot has too many logical branches
 * and FALSE otherwise.
 *
 * When a node is full because it has too many logical branches, all pivots
 * with too many live logical branches must be flushed in order to reduce the
 * branch count.
 */
static inline bool
trunk_pivot_needs_flush(trunk_handle     *spl,
                        page_handle      *node,
                        trunk_pivot_data *pdata)
{
   return trunk_pivot_logical_branch_count(spl, node, pdata)
          > spl->cfg.max_branches_per_node;
}

/*
 * Returns the number of branches which are live for the pivot.
 *
 * This counts each fractional branch independently as opposed to
 * pivot_whole_branch_count.
 */
static inline uint16
trunk_pivot_branch_count(trunk_handle     *spl,
                         page_handle      *node,
                         trunk_pivot_data *pdata)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_branch_number(
      spl, hdr->end_branch, pdata->start_branch);
}

static inline void
trunk_pivot_btree_tuple_counts(trunk_handle   *spl,
                               page_handle    *node,
                               uint16          pivot_no,
                               page_reference *root_ref,
                               uint64         *num_tuples,
                               uint64         *num_kv_bytes)
{
   char  *min_key = trunk_get_pivot(spl, node, pivot_no);
   char  *max_key = trunk_get_pivot(spl, node, pivot_no + 1);
   uint32 local_num_tuples;
   uint32 key_bytes;
   uint32 message_bytes;
   btree_count_in_range(spl->cc,
                        trunk_btree_config(spl),
                        root_ref,
                        trunk_key_slice(spl, min_key),
                        trunk_key_slice(spl, max_key),
                        &local_num_tuples,
                        &key_bytes,
                        &message_bytes);
   *num_tuples   = local_num_tuples;
   *num_kv_bytes = key_bytes + message_bytes;
}

static inline void
trunk_pivot_branch_tuple_counts(trunk_handle *spl,
                                page_handle  *node,
                                uint16        pivot_no,
                                uint16        branch_no,
                                uint64       *num_tuples,
                                uint64       *num_kv_bytes)
{
   trunk_branch *branch = trunk_get_branch(spl, node, branch_no);
   page_reference *branch_ref = (page_reference *)branch;

   return trunk_pivot_btree_tuple_counts(
      spl, node, pivot_no, branch_ref, num_tuples, num_kv_bytes);
}

__attribute__((unused)) static inline uint64
trunk_pivot_tuples_in_branch_slow(trunk_handle *spl,
                                  page_handle  *node,
                                  uint16        pivot_no,
                                  uint16        branch_no)
{
   trunk_branch *branch  = trunk_get_branch(spl, node, branch_no);
   char         *min_key = trunk_get_pivot(spl, node, pivot_no);
   char         *max_key = trunk_get_pivot(spl, node, pivot_no + 1);
   uint32        num_tuples;
   uint32        key_bytes;
   uint32        message_bytes;
   page_reference *root_ref = (page_reference *)branch;
   btree_count_in_range_by_iterator(spl->cc,
                                    trunk_btree_config(spl),
                                    root_ref,
                                    trunk_key_slice(spl, min_key),
                                    trunk_key_slice(spl, max_key),
                                    &num_tuples,
                                    &key_bytes,
                                    &message_bytes);
   return num_tuples;
}


/*
 * reset_start_branch sets the trunk start branch to the smallest start branch
 * of any pivot, and resets the trunk start bundle accordingly.
 *
 * After a node flush, there may be branches and bundles in the node which are
 * no longer live for any pivot. reset_start_branch identifies these, makes
 * sure they are dereferenced and updates the values in the header.
 */
static inline void
trunk_reset_start_branch(trunk_handle *spl, page_handle *node)
{
   trunk_hdr    *hdr          = (trunk_hdr *)node->data;
   uint16        start_branch = hdr->end_branch;
   uint16        pivot_no, branch_no, bundle_no;
   trunk_bundle *bundle;

   // find the pivot with the smallest branch and bundle
   for (pivot_no = 0; pivot_no < trunk_num_children(spl, node); pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (trunk_subtract_branch_number(
             spl, hdr->end_branch, pdata->start_branch)
          > trunk_subtract_branch_number(spl, hdr->end_branch, start_branch))
         start_branch = pdata->start_branch;
   }

   // reset the start branch (and maybe the fractional branch)
   hdr->start_branch = start_branch;
   if (!trunk_branch_valid(spl, node, hdr->start_frac_branch)) {
      hdr->start_frac_branch = hdr->start_branch;
   }

   // kill any bundles that have no live branches
   for (bundle_no = hdr->start_bundle; bundle_no != hdr->end_bundle;
        bundle_no = trunk_add_bundle_number(spl, bundle_no, 1))
   {
      bundle    = trunk_get_bundle(spl, node, bundle_no);
      branch_no = trunk_bundle_start_branch(spl, node, bundle);
      if (!trunk_branch_live(spl, node, branch_no)) {
         /*
          * either all branches in the bundle are live or none are, so in this
          * case none are
          */
         trunk_bundle_clear_subbundles(spl, node, bundle);
         trunk_inc_start_bundle(spl, node);
         trunk_default_log_if_enabled(
            spl, "node %lu evicting bundle %hu\n", node->disk_addr, bundle_no);
      }
   }
}

/*
 * pivot_clear clears all branches and bundles from the pivot
 *
 * Used when flushing the pivot.
 */
static inline void
trunk_pivot_clear(trunk_handle *spl, page_handle *node, trunk_pivot_data *pdata)
{
   trunk_hdr *hdr             = (trunk_hdr *)node->data;
   uint16     start_branch    = pdata->start_branch;
   pdata->start_branch        = hdr->end_branch;
   pdata->start_bundle        = hdr->end_bundle;
   pdata->num_tuples_whole    = 0;
   pdata->num_tuples_bundle   = 0;
   pdata->num_kv_bytes_whole  = 0;
   pdata->num_kv_bytes_bundle = 0;
   pdata->srq_idx             = -1;
   if (start_branch == hdr->start_branch) {
      trunk_reset_start_branch(spl, node);
   }
   pdata->filter.addr             = 0;
   pdata->filter.meta_head        = 0;
   pdata->filter.num_fingerprints = 0;
}

/*
 * Returns the index of the pivot with pivot data pdata.
 */
static inline uint16
trunk_pdata_to_pivot_index(trunk_handle     *spl,
                           page_handle      *node,
                           trunk_pivot_data *pdata)
{
   uint64 byte_difference =
      (char *)pdata - (char *)trunk_get_pivot_data(spl, node, 0);
   debug_assert(byte_difference % trunk_pivot_size(spl) == 0);
   return byte_difference / trunk_pivot_size(spl);
}

/*
 * Returns the number of children of the node
 */
static inline uint16
trunk_num_children(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   debug_assert(hdr->num_pivot_keys >= 2);
   return hdr->num_pivot_keys - 1;
}

/*
 * Returns the number of pivot keys in the node. This is equal to the number of
 * children + 1 for the upper bound pivot key.
 */
static inline uint16
trunk_num_pivot_keys(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   debug_assert(hdr->num_pivot_keys >= 2);
   return hdr->num_pivot_keys;
}

static inline void
trunk_inc_num_pivot_keys(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   debug_assert(hdr->num_pivot_keys >= 2);
   hdr->num_pivot_keys++;
   debug_assert(hdr->num_pivot_keys <= spl->cfg.max_pivot_keys);
}


/*
 * Returns the PBN of the node at height height whose key range contains key.
 *
 * Used to locate the parent of a leaf which has finished splitting in the case
 * where the parent might have changed as a result of a internal node split or
 * root split.
 */
page_reference
trunk_find_node(trunk_handle *spl, char *key, uint64 height)
{
   page_handle *node        = trunk_node_get(spl, &spl->root_ref);
   uint16       tree_height = trunk_height(spl, node);
   for (uint16 h = tree_height; h > height + 1; h--) {
      uint32 pivot_no = trunk_find_pivot(spl, node, key, less_than_or_equal);
      debug_assert(pivot_no < trunk_num_children(spl, node));
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      page_reference    ch_ref = pdata->ref;
      page_handle      *child = trunk_node_get(spl, &ch_ref);
      trunk_node_unget(spl, &node);
      node = child;
   }
   uint32 pivot_no = trunk_find_pivot(spl, node, key, less_than_or_equal);
   debug_assert(pivot_no < trunk_num_children(spl, node));
   trunk_pivot_data *pdata    = trunk_get_pivot_data(spl, node, pivot_no);
   page_reference    ref      = pdata->ref;
   trunk_node_unget(spl, &node);
   return ref;
}

/*
 *-----------------------------------------------------------------------------
 * Bundle functions
 *-----------------------------------------------------------------------------
 */

/*
 * Returns TRUE if the bundle is live in the node and FALSE otherwise.
 */
static inline bool
trunk_bundle_live(trunk_handle *spl, page_handle *node, uint16 bundle_no)
{
   return trunk_bundle_in_range(spl,
                                bundle_no,
                                trunk_start_bundle(spl, node),
                                trunk_end_bundle(spl, node));
}

static inline trunk_bundle *
trunk_get_bundle(trunk_handle *spl, page_handle *node, uint16 bundle_no)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   debug_assert(trunk_bundle_live(spl, node, bundle_no),
                "Attempt to get a dead bundle.\n"
                "addr: %lu, bundle_no: %u, start_bundle: %u, end_bundle: %u\n",
                node->disk_addr,
                bundle_no,
                trunk_start_bundle(spl, node),
                trunk_end_bundle(spl, node));
   return &hdr->bundle[bundle_no];
}

static inline uint16
trunk_get_new_bundle(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr           = (trunk_hdr *)node->data;
   uint16     new_bundle_no = hdr->end_bundle;
   hdr->end_bundle          = trunk_add_bundle_number(spl, hdr->end_bundle, 1);
   platform_assert((hdr->end_bundle != hdr->start_bundle),
                   "No available bundles in trunk node. "
                   "page disk_addr=%lu, end_bundle=%d, start_bundle=%d",
                   node->disk_addr,
                   hdr->end_bundle,
                   hdr->start_bundle);
   return new_bundle_no;
}

static inline uint16
trunk_start_bundle(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->start_bundle;
}

static inline uint16
trunk_end_bundle(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->end_bundle;
}

static inline uint16
trunk_inc_start_bundle(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr    = (trunk_hdr *)node->data;
   hdr->start_bundle = trunk_add_bundle_number(spl, hdr->start_bundle, 1);
   return hdr->start_bundle;
}

static inline trunk_subbundle *
trunk_get_subbundle(trunk_handle *spl, page_handle *node, uint16 subbundle_no)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return &hdr->subbundle[subbundle_no];
}

static inline uint16
trunk_subbundle_no(trunk_handle *spl, page_handle *node, trunk_subbundle *sb)
{
   return sb - trunk_get_subbundle(spl, node, 0);
}

/*
 * get_new_subbundle allocates a new subbundle in the node and returns its
 * index.
 */
static inline trunk_subbundle *
trunk_get_new_subbundle(trunk_handle *spl,
                        page_handle  *node,
                        uint16        num_filters)
{
   trunk_hdr *hdr              = (trunk_hdr *)node->data;
   uint16     new_subbundle_no = hdr->end_subbundle;
   hdr->end_subbundle = trunk_add_subbundle_number(spl, hdr->end_subbundle, 1);
   // ALEX: Need a way to handle this better
   platform_assert(hdr->end_subbundle != hdr->start_subbundle);

   // get filters
   trunk_subbundle *sb = trunk_get_subbundle(spl, node, new_subbundle_no);
   sb->start_filter    = trunk_end_sb_filter(spl, node);
   hdr->end_sb_filter =
      trunk_add_subbundle_filter_number(spl, hdr->end_sb_filter, num_filters);
   sb->end_filter = trunk_end_sb_filter(spl, node);
   sb->state      = SB_STATE_COMPACTED;
   return sb;
}

static inline trunk_subbundle *
trunk_leaf_get_new_subbundle_at_head(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   uint16     new_subbundle_no =
      trunk_subtract_subbundle_number(spl, hdr->start_subbundle, 1);
   platform_assert(new_subbundle_no != hdr->end_subbundle);
   hdr->start_subbundle = new_subbundle_no;

   // get filters
   trunk_subbundle *sb = trunk_get_subbundle(spl, node, new_subbundle_no);
   sb->end_filter      = hdr->start_sb_filter;
   sb->start_filter =
      trunk_subtract_subbundle_number(spl, hdr->start_sb_filter, 1);
   platform_assert(sb->start_filter != hdr->end_sb_filter);
   hdr->start_sb_filter = sb->start_filter;
   sb->state            = SB_STATE_UNCOMPACTED_LEAF;
   return sb;
}

static inline routing_filter *
trunk_get_sb_filter(trunk_handle *spl, page_handle *node, uint16 filter_no)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   debug_assert(filter_no < TRUNK_MAX_SUBBUNDLE_FILTERS,
                "filter_no=%u should be < TRUNK_MAX_SUBBUNDLE_FILTERS (%u)",
                filter_no,
                TRUNK_MAX_SUBBUNDLE_FILTERS);
   return &hdr->sb_filter[filter_no];
}

static inline uint16
trunk_start_sb_filter(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->start_sb_filter;
}

static inline uint16
trunk_end_sb_filter(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->end_sb_filter;
}

static inline bool
trunk_sb_filter_valid(trunk_handle *spl, page_handle *node, uint16 filter_no)
{
   uint16 start_filter = trunk_start_sb_filter(spl, node);
   uint16 end_filter   = trunk_end_sb_filter(spl, node);
   return trunk_subtract_subbundle_filter_number(spl, filter_no, start_filter)
          <= trunk_subtract_subbundle_filter_number(
             spl, end_filter, start_filter);
}

static inline uint16
trunk_subbundle_filter_count(trunk_handle    *spl,
                             page_handle     *node,
                             trunk_subbundle *sb)
{
   return trunk_subtract_subbundle_number(
      spl, sb->end_filter, sb->start_filter);
}

static inline uint16
trunk_bundle_filter_count(trunk_handle *spl,
                          page_handle  *node,
                          trunk_bundle *bundle)
{
   uint16 filter_count = 0;
   for (uint16 sb_no = bundle->start_subbundle; sb_no != bundle->end_subbundle;
        sb_no        = trunk_add_subbundle_number(spl, sb_no, 1))
   {
      trunk_subbundle *sb = trunk_get_subbundle(spl, node, sb_no);
      filter_count += trunk_subbundle_filter_count(spl, node, sb);
   }
   return filter_count;
}

static inline uint16
trunk_bundle_start_filter(trunk_handle *spl,
                          page_handle  *node,
                          trunk_bundle *bundle)
{
   uint16           sb_no = bundle->start_subbundle;
   trunk_subbundle *sb    = trunk_get_subbundle(spl, node, sb_no);
   return sb->start_filter;
}

static inline uint16
trunk_bundle_end_filter(trunk_handle *spl,
                        page_handle  *node,
                        trunk_bundle *bundle)
{
   uint16 last_sb_no =
      trunk_subtract_subbundle_number(spl, bundle->end_subbundle, 1);
   trunk_subbundle *sb = trunk_get_subbundle(spl, node, last_sb_no);
   return sb->end_filter;
}

static inline routing_filter *
trunk_subbundle_filter(trunk_handle    *spl,
                       page_handle     *node,
                       trunk_subbundle *sb,
                       uint16           filter_off)
{
   uint16 start_filter = sb->start_filter;
   uint16 filter_no =
      trunk_add_subbundle_filter_number(spl, start_filter, filter_off);
   debug_assert(filter_off < trunk_subbundle_filter_count(spl, node, sb));
   return trunk_get_sb_filter(spl, node, filter_no);
}

__attribute__((unused)) static inline uint16
trunk_subbundle_branch_count(trunk_handle    *spl,
                             page_handle     *node,
                             trunk_subbundle *sb)
{
   return trunk_subtract_branch_number(spl, sb->end_branch, sb->start_branch);
}

static inline uint16
trunk_start_subbundle(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->start_subbundle;
}

static inline uint16
trunk_end_subbundle(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->end_subbundle;
}

static inline uint16
trunk_start_subbundle_for_lookup(trunk_handle *spl, page_handle *node)
{
   return trunk_subtract_subbundle_number(
      spl, trunk_end_subbundle(spl, node), 1);
}

static inline uint16
trunk_bundle_clear_subbundles(trunk_handle *spl,
                              page_handle  *node,
                              trunk_bundle *bundle)
{
   trunk_hdr *hdr          = (trunk_hdr *)node->data;
   uint16     start_filter = trunk_bundle_start_filter(spl, node, bundle);
   uint16     end_filter   = trunk_bundle_end_filter(spl, node, bundle);
   for (uint16 filter_no = start_filter; filter_no != end_filter;
        filter_no        = trunk_add_subbundle_filter_number(spl, filter_no, 1))
   {
      routing_filter *filter = trunk_get_sb_filter(spl, node, filter_no);
      trunk_dec_filter(spl, filter);
   }
   hdr->start_sb_filter = end_filter;
   hdr->start_subbundle = bundle->end_subbundle;
   return hdr->start_subbundle;
}

/*
 * Removes all bundles except the given bundle.
 *
 * This function does not just clear compacted bundles into whole branches, but
 * removes bundles wholesale.
 *
 * Used in leaf splits to abort compactions in progress.
 */
static inline void
trunk_leaf_remove_bundles_except(trunk_handle *spl,
                                 page_handle  *node,
                                 uint16        bundle_no)
{
   debug_assert(trunk_height(spl, node) == 0);
   trunk_hdr *hdr            = (trunk_hdr *)node->data;
   uint16     last_bundle_no = trunk_end_bundle(spl, node);
   last_bundle_no = trunk_subtract_bundle_number(spl, last_bundle_no, 1);
   debug_assert(bundle_no == last_bundle_no);
   hdr->start_bundle       = bundle_no;
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, 0);
   pdata->start_bundle     = hdr->start_bundle;
}

/*
 * Rebundles all branches and subbundles in a leaf into a single bundle.
 *
 * Used in leaf splits to abort compactions in progress.
 */
static inline uint16
trunk_leaf_rebundle_all_branches(trunk_handle *spl,
                                 page_handle  *node,
                                 uint64        target_num_tuples,
                                 uint64        target_kv_bytes,
                                 bool          is_space_rec)
{
   debug_assert(trunk_height(spl, node) == 0);
   uint16 bundle_no = trunk_get_new_bundle(spl, node);
   if (trunk_branch_is_whole(spl, node, trunk_start_branch(spl, node))) {
      trunk_subbundle *sb = trunk_leaf_get_new_subbundle_at_head(spl, node);
      sb->start_branch    = trunk_start_branch(spl, node);
      sb->end_branch      = trunk_start_frac_branch(spl, node);
      routing_filter   *filter = trunk_subbundle_filter(spl, node, sb, 0);
      trunk_pivot_data *pdata  = trunk_get_pivot_data(spl, node, 0);
      *filter                  = pdata->filter;
      debug_assert(filter->addr != 0);
      ZERO_STRUCT(pdata->filter);
      debug_assert(trunk_subbundle_branch_count(spl, node, sb) != 0);
   }
   trunk_bundle *bundle    = trunk_get_bundle(spl, node, bundle_no);
   bundle->num_tuples      = target_num_tuples;
   bundle->num_kv_bytes    = target_kv_bytes;
   bundle->start_subbundle = trunk_start_subbundle(spl, node);
   bundle->end_subbundle   = trunk_end_subbundle(spl, node);
   trunk_leaf_remove_bundles_except(spl, node, bundle_no);
   trunk_set_start_frac_branch(spl, node, trunk_start_branch(spl, node));
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, 0);
   if (!is_space_rec && pdata->srq_idx != -1
       && spl->cfg.reclaim_threshold != UINT64_MAX)
   {
      // platform_default_log("Deleting %12lu-%lu (index %lu) from SRQ\n",
      //       node->disk_addr, pdata->generation, pdata->srq_idx);
      srq_delete(&spl->srq, pdata->srq_idx);
      srq_print(&spl->srq);
      pdata->srq_idx = -1;
   }
   pdata->generation        = trunk_inc_pivot_generation(spl, node);
   pdata->num_tuples_bundle = bundle->num_tuples;
   pdata->num_tuples_whole  = 0;
   return bundle_no;
}

/*
 * Returns the index of the first branch in the bundle.
 */
static inline uint16
trunk_bundle_start_branch(trunk_handle *spl,
                          page_handle  *node,
                          trunk_bundle *bundle)
{
   trunk_subbundle *subbundle =
      trunk_get_subbundle(spl, node, bundle->start_subbundle);
   return subbundle->start_branch;
}

/*
 * Returns the index of the successor to the last branch in the bundle.
 */
static inline uint16
trunk_bundle_end_branch(trunk_handle *spl,
                        page_handle  *node,
                        trunk_bundle *bundle)
{
   uint16 last_subbundle_no =
      trunk_subtract_subbundle_number(spl, bundle->end_subbundle, 1);
   trunk_subbundle *subbundle =
      trunk_get_subbundle(spl, node, last_subbundle_no);
   return subbundle->end_branch;
}

/*
 * Returns the number of (by definition fractional) branches in the bundle.
 */
static inline uint16
trunk_bundle_branch_count(trunk_handle *spl,
                          page_handle  *node,
                          trunk_bundle *bundle)
{
   return trunk_subtract_branch_number(
      spl,
      trunk_bundle_end_branch(spl, node, bundle),
      trunk_bundle_start_branch(spl, node, bundle));
}

static inline uint16
trunk_bundle_subbundle_count(trunk_handle *spl,
                             page_handle  *node,
                             trunk_bundle *bundle)
{
   return trunk_subtract_subbundle_number(
      spl, bundle->end_subbundle, bundle->start_subbundle);
}

/*
 * Returns the number of live bundles in the node.
 */
static inline uint16
trunk_bundle_count(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_bundle_number(spl, hdr->end_bundle, hdr->start_bundle);
}

/*
 * Returns the number of live subbundles in the node.
 */
static inline uint16
trunk_subbundle_count(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_subbundle_number(
      spl, hdr->end_subbundle, hdr->start_subbundle);
}

/*
 * Returns TRUE if the bundle is valid in the node (live or == end_bundle) and
 * FALSE otherwise.
 */
static inline bool
trunk_bundle_valid(trunk_handle *spl, page_handle *node, uint16 bundle_no)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_bundle_number(spl, bundle_no, hdr->start_bundle)
          <= trunk_subtract_bundle_number(
             spl, hdr->end_bundle, hdr->start_bundle);
}

/*
 * Returns TRUE if the bundle is live for the pivot and FALSE otherwise
 */
static inline bool
trunk_bundle_live_for_pivot(trunk_handle *spl,
                            page_handle  *node,
                            uint16        bundle_no,
                            uint16        pivot_no)
{
   debug_assert(pivot_no < trunk_num_children(spl, node));
   return trunk_bundle_in_range(spl,
                                bundle_no,
                                trunk_pivot_start_bundle(spl, node, pivot_no),
                                trunk_end_bundle(spl, node));
}

static inline uint16
trunk_start_frac_branch(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->start_frac_branch;
}

static inline void
trunk_set_start_frac_branch(trunk_handle *spl,
                            page_handle  *node,
                            uint16        branch_no)
{
   trunk_hdr *hdr         = (trunk_hdr *)node->data;
   hdr->start_frac_branch = branch_no;
}

static inline void
trunk_reset_start_frac_branch(trunk_handle *spl, page_handle *node)
{
   if (trunk_bundle_count(spl, node) == 0) {
      trunk_set_start_frac_branch(spl, node, trunk_end_branch(spl, node));
   } else {
      uint16        start_bundle = trunk_start_bundle(spl, node);
      trunk_bundle *bundle       = trunk_get_bundle(spl, node, start_bundle);
      uint16 start_frac_branch   = trunk_bundle_start_branch(spl, node, bundle);
      trunk_set_start_frac_branch(spl, node, start_frac_branch);
   }
}

static inline void
trunk_clear_bundle(trunk_handle *spl, page_handle *node, uint16 bundle_no)
{
   platform_assert(bundle_no == trunk_start_bundle(spl, node));

   trunk_bundle *bundle = trunk_get_bundle(spl, node, bundle_no);

   trunk_bundle_clear_subbundles(spl, node, bundle);
   trunk_inc_start_bundle(spl, node);

   // update the pivot start bundles
   for (uint16 pivot_no = 0; pivot_no < trunk_num_children(spl, node);
        pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (!trunk_bundle_valid(spl, node, pdata->start_bundle)) {
         pdata->start_bundle = trunk_start_bundle(spl, node);
      }
   }

   // update the fractional start branch
   trunk_reset_start_frac_branch(spl, node);
}

static inline void
trunk_tuples_in_bundle(trunk_handle *spl,
                       page_handle  *node,
                       trunk_bundle *bundle,
                       uint64        pivot_tuple_count[static TRUNK_MAX_PIVOTS],
                       uint64 pivot_kv_byte_count[static TRUNK_MAX_PIVOTS])
{
   // Can't ZERO_ARRAY because degerates to a uint64 *
   ZERO_CONTENTS_N(pivot_tuple_count, TRUNK_MAX_PIVOTS);
   ZERO_CONTENTS_N(pivot_kv_byte_count, TRUNK_MAX_PIVOTS);

   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 branch_no = trunk_bundle_start_branch(spl, node, bundle);
        branch_no != trunk_bundle_end_branch(spl, node, bundle);
        branch_no = trunk_add_branch_number(spl, branch_no, 1))
   {
      for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
         uint64 local_tuple_count;
         uint64 local_kv_byte_count;
         trunk_pivot_branch_tuple_counts(spl,
                                         node,
                                         pivot_no,
                                         branch_no,
                                         &local_tuple_count,
                                         &local_kv_byte_count);
         pivot_tuple_count[pivot_no] += local_tuple_count;
         pivot_kv_byte_count[pivot_no] += local_kv_byte_count;
      }
   }
}

static inline void
trunk_pivot_add_bundle_tuple_counts(
   trunk_handle *spl,
   page_handle  *node,
   trunk_bundle *bundle,
   uint64        pivot_tuple_count[TRUNK_MAX_PIVOTS],
   uint64        pivot_kv_byte_count[TRUNK_MAX_PIVOTS])

{
   bundle->num_tuples  = 0;
   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      pdata->num_tuples_bundle += pivot_tuple_count[pivot_no];
      bundle->num_tuples += pivot_tuple_count[pivot_no];
      pdata->num_kv_bytes_bundle += pivot_kv_byte_count[pivot_no];
      bundle->num_kv_bytes += pivot_kv_byte_count[pivot_no];
   }
}

static inline void
trunk_bundle_inc_pivot_rc(trunk_handle *spl,
                          page_handle  *node,
                          trunk_bundle *bundle)
{
   uint16        num_children = trunk_num_children(spl, node);
   cache        *cc           = spl->cc;
   btree_config *btree_cfg    = &spl->cfg.btree_cfg;
   // Skip the first pivot, because that has been inc'd in the parent
   for (uint16 branch_no = trunk_bundle_start_branch(spl, node, bundle);
        branch_no != trunk_bundle_end_branch(spl, node, bundle);
        branch_no = trunk_add_branch_number(spl, branch_no, 1))
   {
      trunk_branch *branch = trunk_get_branch(spl, node, branch_no);
      for (uint64 pivot_no = 1; pivot_no < num_children; pivot_no++) {
         const char *key = trunk_get_pivot(spl, node, pivot_no);
         btree_inc_ref_range(cc,
                             btree_cfg,
                             branch->root_addr,
                             trunk_key_slice(spl, key),
                             NULL_SLICE);
      }
   }
}

/*
 *-----------------------------------------------------------------------------
 * Branch functions
 *-----------------------------------------------------------------------------
 */

/*
 * has_vacancy returns TRUE unless there is not enough physical space in the
 * node to add another branch
 */

/*
 * Returns the number of live branches (including fractional branches).
 */
static inline uint16
trunk_branch_count(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_branch_number(spl, hdr->end_branch, hdr->start_branch);
}

static inline bool
trunk_has_vacancy(trunk_handle *spl, page_handle *node, uint16 num_new_branches)
{
   uint16 branch_count = trunk_branch_count(spl, node);
   uint16 max_branches = spl->cfg.hard_max_branches_per_node;
   return branch_count + num_new_branches + 1 < max_branches;
}

static inline trunk_branch *
trunk_get_branch(trunk_handle *spl, page_handle *node, uint32 k)
{
   debug_assert(sizeof(trunk_hdr)
                   + spl->cfg.max_pivot_keys * trunk_pivot_size(spl)
                   + (k + 1) * sizeof(trunk_branch)
                < trunk_page_size(&spl->cfg));

   char *cursor = node->data;
   cursor += sizeof(trunk_hdr) + spl->cfg.max_pivot_keys * trunk_pivot_size(spl)
             + k * sizeof(trunk_branch);
   return (trunk_branch *)cursor;
}

/*
 * get_new_branch allocates a new branch in the node and returns a pointer to
 * it.
 */
static inline trunk_branch *
trunk_get_new_branch(trunk_handle *spl, page_handle *node)
{
   trunk_hdr    *hdr        = (trunk_hdr *)node->data;
   trunk_branch *new_branch = trunk_get_branch(spl, node, hdr->end_branch);
   hdr->end_branch          = trunk_add_branch_number(spl, hdr->end_branch, 1);
   debug_assert(hdr->end_branch != hdr->start_branch);
   return new_branch;
}

static inline uint16
trunk_branch_no(trunk_handle *spl, page_handle *node, trunk_branch *branch)
{
   return branch - trunk_get_branch(spl, node, 0);
}

static inline uint16
trunk_start_branch(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->start_branch;
}

static inline uint16
trunk_end_branch(trunk_handle *spl, page_handle *node)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return hdr->end_branch;
}

/*
 * branch_live checks if branch_no is live for any pivot in the node.
 */
static inline bool
trunk_branch_live(trunk_handle *spl, page_handle *node, uint64 branch_no)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_branch_in_range(
      spl, branch_no, hdr->start_branch, hdr->end_branch);
}

/*
 * branch_valid checks if branch_no is being used by any pivot or is
 * end_branch. Used to verify if a given entry is valid.
 */
static inline bool
trunk_branch_valid(trunk_handle *spl, page_handle *node, uint64 branch_no)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   return trunk_subtract_branch_number(spl, branch_no, hdr->start_branch)
          <= trunk_subtract_branch_number(
             spl, hdr->end_branch, hdr->start_branch);
}

static inline uint64
trunk_process_generation_to_pos(trunk_handle             *spl,
                                trunk_compact_bundle_req *req,
                                uint64                    generation)
{
   uint64 pos = 0;
   while ((pos != TRUNK_MAX_PIVOTS)
          && (req->pivot_generation[pos] != generation)) {
      pos++;
   }
   return pos;
}

/*
 * replace_bundle_branches replaces the branches of an uncompacted bundle with
 * a newly compacted branch.
 *
 * This process is:
 * 1. de-ref the old branches of the bundle
 * 2. add the new branch (unless replacement_branch == NULL)
 * 3. move any remaining branches to maintain a contiguous array
 * 4. adjust pivot start branches if necessary
 * 5. mark bundle as compacted and remove all by its first subbundle
 * 6. move any remaining subbundles to maintain a contiguous array (and adjust
 *    any remaining bundles to account)
 */
void
trunk_replace_bundle_branches(trunk_handle             *spl,
                              page_handle              *node,
                              trunk_branch             *repl_branch,
                              trunk_compact_bundle_req *req)
{
   trunk_hdr *hdr = (trunk_hdr *)node->data;
   debug_assert(req->height == trunk_height(spl, node));

   uint16        bundle_no    = req->bundle_no;
   trunk_bundle *bundle       = trunk_get_bundle(spl, node, bundle_no);
   uint16 bundle_start_branch = trunk_bundle_start_branch(spl, node, bundle);
   uint16 bundle_end_branch   = trunk_bundle_end_branch(spl, node, bundle);
   uint16 branch_diff         = trunk_bundle_branch_count(spl, node, bundle);

   // de-ref the dead branches
   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 branch_no = bundle_start_branch; branch_no != bundle_end_branch;
        branch_no        = trunk_add_branch_number(spl, branch_no, 1))
   {
      trunk_branch *branch = trunk_get_branch(spl, node, branch_no);
      for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
         if (trunk_bundle_live_for_pivot(spl, node, bundle_no, pivot_no)) {
            const char *start_key = trunk_get_pivot(spl, node, pivot_no);
            const char *end_key   = trunk_get_pivot(spl, node, pivot_no + 1);
            trunk_zap_branch_range(
               spl, branch, start_key, end_key, PAGE_TYPE_BRANCH);
         }
      }
   }

   // add new branch
   uint16 new_branch_no = UINT16_MAX;
   if (repl_branch != NULL) {
      trunk_branch *new_branch =
         trunk_get_branch(spl, node, bundle_start_branch);
      *new_branch = *repl_branch;
      branch_diff--;
      new_branch_no = trunk_branch_no(spl, node, new_branch);

      // increment the fringes of the new branch along the pivots
      uint16 num_pivot_keys = trunk_num_pivot_keys(spl, node);
      for (uint16 pivot_no = 1; pivot_no < num_pivot_keys; pivot_no++) {
         const char *start_key = trunk_get_pivot(spl, node, pivot_no);
         trunk_inc_intersection(spl, new_branch, start_key, FALSE);
      }

      // slice out the pivots ranges for which this branch is already dead
      for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
         if (!trunk_bundle_live_for_pivot(spl, node, bundle_no, pivot_no)) {
            const char *start_key = trunk_get_pivot(spl, node, pivot_no);
            const char *end_key   = trunk_get_pivot(spl, node, pivot_no + 1);
            trunk_zap_branch_range(
               spl, new_branch, start_key, end_key, PAGE_TYPE_BRANCH);
         }
      }
   }

   // move any remaining branches to maintain a contiguous array
   for (uint16 branch_no = bundle_end_branch; branch_no != hdr->end_branch;
        branch_no        = trunk_add_branch_number(spl, branch_no, 1))
   {
      uint16 dst_branch_no =
         trunk_subtract_branch_number(spl, branch_no, branch_diff);
      *trunk_get_branch(spl, node, dst_branch_no) =
         *trunk_get_branch(spl, node, branch_no);
   }

   /*
    * if the bundle has no keys, move the filters to form a contiguous array
    */
   if (repl_branch == NULL) {
      // decrement the ref counts of the old filters
      for (uint16 filter_no = trunk_bundle_start_filter(spl, node, bundle);
           filter_no != trunk_bundle_end_filter(spl, node, bundle);
           filter_no = trunk_add_subbundle_filter_number(spl, filter_no, 1))
      {
         routing_filter *old_filter = trunk_get_sb_filter(spl, node, filter_no);
         trunk_dec_filter(spl, old_filter);
      }

      // move any later filters
      uint16 filter_diff = trunk_bundle_filter_count(spl, node, bundle);
      for (uint16 filter_no = trunk_bundle_end_filter(spl, node, bundle);
           filter_no != trunk_end_sb_filter(spl, node);
           filter_no = trunk_add_subbundle_filter_number(spl, filter_no, 1))
      {
         uint16 dst_filter_no =
            trunk_subtract_subbundle_number(spl, filter_no, filter_diff);
         *trunk_get_sb_filter(spl, node, dst_filter_no) =
            *trunk_get_sb_filter(spl, node, filter_no);
      }

      // adjust the end filter
      hdr->end_sb_filter = trunk_subtract_subbundle_filter_number(
         spl, hdr->end_sb_filter, filter_diff);
   }

   /*
    * the compacted bundle will have a single branch in a single subbundle
    * containing all the filters.
    */
   uint16 sb_diff        = trunk_bundle_subbundle_count(spl, node, bundle);
   uint16 first_later_sb = bundle->end_subbundle;
   if (repl_branch != NULL) {
      uint16           sb_no = bundle->start_subbundle;
      trunk_subbundle *sb    = trunk_get_subbundle(spl, node, sb_no);
      sb->end_branch = trunk_add_branch_number(spl, bundle_start_branch, 1);
      sb->end_filter = trunk_bundle_end_filter(spl, node, bundle);
      sb->state      = SB_STATE_COMPACTED;
      sb_diff--;
      bundle->end_subbundle = trunk_add_subbundle_number(spl, sb_no, 1);
   }

   for (uint16 sb_no = first_later_sb; sb_no != hdr->end_subbundle;
        sb_no        = trunk_add_subbundle_number(spl, sb_no, 1))
   {
      trunk_subbundle *sb = trunk_get_subbundle(spl, node, sb_no);
      sb->start_branch =
         trunk_subtract_branch_number(spl, sb->start_branch, branch_diff);
      sb->end_branch =
         trunk_subtract_branch_number(spl, sb->end_branch, branch_diff);
      uint16 dst_sb_no = trunk_subtract_subbundle_number(spl, sb_no, sb_diff);
      *trunk_get_subbundle(spl, node, dst_sb_no) = *sb;
   }
   hdr->end_subbundle =
      trunk_subtract_subbundle_number(spl, hdr->end_subbundle, sb_diff);
   for (uint16 later_bundle_no = trunk_add_bundle_number(spl, bundle_no, 1);
        later_bundle_no != hdr->end_bundle;
        later_bundle_no = trunk_add_bundle_number(spl, later_bundle_no, 1))
   {
      trunk_bundle *bundle = trunk_get_bundle(spl, node, later_bundle_no);
      bundle->start_subbundle =
         trunk_subtract_subbundle_number(spl, bundle->start_subbundle, sb_diff);
      bundle->end_subbundle =
         trunk_subtract_subbundle_number(spl, bundle->end_subbundle, sb_diff);
   }
   debug_assert(trunk_bundle_start_branch(spl, node, bundle)
                == bundle_start_branch);

   // record the pivot tuples
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      if (trunk_bundle_live_for_pivot(spl, node, bundle_no, pivot_no)) {
         trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
         uint64            pos =
            trunk_process_generation_to_pos(spl, req, pdata->generation);
         platform_assert((pos != TRUNK_MAX_PIVOTS),
                         "Pivot live for bundle not found in req, "
                         "pos=%lu != TRUNK_MAX_PIVOTS=%d",
                         pos,
                         TRUNK_MAX_PIVOTS);
         if (repl_branch != NULL) {
            trunk_pivot_branch_tuple_counts(
               spl,
               node,
               pivot_no,
               new_branch_no,
               &req->output_pivot_tuple_count[pos],
               &req->output_pivot_kv_byte_count[pos]);
         }

         uint64 tuples_reclaimed = req->input_pivot_tuple_count[pos]
                                   - req->output_pivot_tuple_count[pos];
         req->tuples_reclaimed += tuples_reclaimed;
         pdata->num_tuples_bundle -= tuples_reclaimed;

         uint64 kv_bytes_reclaimed = req->input_pivot_kv_byte_count[pos]
                                     - req->output_pivot_kv_byte_count[pos];
         req->kv_bytes_reclaimed += kv_bytes_reclaimed;
         pdata->num_kv_bytes_bundle -= req->kv_bytes_reclaimed;
      }
   }

   // if there is no replacement branch, vanish the bundle
   if (repl_branch == NULL) {
      for (uint16 later_bundle_no = bundle_no;
           later_bundle_no
           != trunk_subtract_bundle_number(spl, hdr->end_bundle, 1);
           later_bundle_no = trunk_add_bundle_number(spl, later_bundle_no, 1))
      {
         uint16 src_later_bundle_no =
            trunk_add_bundle_number(spl, later_bundle_no, 1);
         *trunk_get_bundle(spl, node, later_bundle_no) =
            *trunk_get_bundle(spl, node, src_later_bundle_no);
      }
      uint16 later_bundle_start = trunk_add_bundle_number(spl, bundle_no, 1);
      uint16 later_bundle_end =
         trunk_add_bundle_number(spl, trunk_end_bundle(spl, node), 1);
      for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
         trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
         if (trunk_bundle_in_range(
                spl, pdata->start_bundle, later_bundle_start, later_bundle_end))
         {
            pdata->start_bundle =
               trunk_subtract_bundle_number(spl, pdata->start_bundle, 1);
         }
      }
      hdr->end_bundle = trunk_subtract_bundle_number(spl, hdr->end_bundle, 1);
   }

   // fix the pivot start branches
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (!trunk_branch_live_for_pivot(
             spl, node, bundle_start_branch, pivot_no)) {
         pdata->start_branch =
            trunk_subtract_branch_number(spl, pdata->start_branch, branch_diff);
         debug_assert(trunk_branch_valid(spl, node, pdata->start_branch));
      }
   }

   // update the end_branch
   hdr->end_branch =
      trunk_subtract_branch_number(spl, hdr->end_branch, branch_diff);
}

static inline void
trunk_inc_branch_range(trunk_handle *spl,
                       trunk_branch *branch,
                       const char   *start_key,
                       const char   *end_key)
{
   if (branch->root_addr) {
      btree_inc_ref_range(spl->cc,
                          &spl->cfg.btree_cfg,
                          branch->root_addr,
                          trunk_key_slice(spl, start_key),
                          trunk_key_slice(spl, end_key));
   }
}

static inline void
trunk_zap_branch_range(trunk_handle *spl,
                       trunk_branch *branch,
                       const char   *start_key,
                       const char   *end_key,
                       page_type     type)
{
   trunk_default_log_if_enabled(spl, "%s: pid=%lu, root_addr=%lu\n", __func__, platform_get_tid(), branch->root_addr);
   platform_assert(type == PAGE_TYPE_BRANCH);
   platform_assert((start_key == NULL && end_key == NULL)
                   || (type != PAGE_TYPE_MEMTABLE && start_key != NULL));
   platform_assert(branch->root_addr != 0, "root_addr=%lu", branch->root_addr);
   btree_dec_ref_range(spl->cc,
                       &spl->cfg.btree_cfg,
                       branch->root_addr,
                       trunk_key_slice(spl, start_key),
                       trunk_key_slice(spl, end_key),
                       PAGE_TYPE_BRANCH);
}

/*
 * Decrement the ref count for branch and destroy it and its filter if it
 * reaches 0.
 */
static inline void
trunk_dec_ref(trunk_handle *spl, trunk_branch *branch, bool is_memtable)
{
   page_type type = is_memtable ? PAGE_TYPE_MEMTABLE : PAGE_TYPE_BRANCH;
   trunk_zap_branch_range(spl, branch, NULL, NULL, type);
}

/*
 * Increment the ref count for all extents whose key range intersects with key
 */
static inline void
trunk_inc_intersection(trunk_handle *spl,
                       trunk_branch *branch,
                       const char   *key,
                       bool          is_memtable)
{
   platform_assert(IMPLIES(is_memtable, key == NULL));
   trunk_inc_branch_range(spl, branch, key, NULL);
}

/*
 * trunk_btree_lookup performs a lookup for key in branch.
 *
 * Pre-conditions:
 *    If *data is not the null write_buffer, then
 *       `data` has the most recent answer.
 *       the current memtable is older than the most recent answer
 *
 * Post-conditions:
 *    if *local_found, then data can be found in `data`.
 */
static inline platform_status
trunk_btree_lookup_and_merge(trunk_handle      *spl,
                             trunk_branch      *branch,
                             const char        *key,
                             merge_accumulator *data,
                             bool              *local_found)
{
   cache          *cc  = spl->cc;
   btree_config   *cfg = &spl->cfg.btree_cfg;
   platform_status rc;
   // TODO(yizheng.jiao): need to put page_reference inside branch
   page_reference root_ref;
   memcpy(&root_ref, branch, sizeof(root_ref));

   rc = btree_lookup_and_merge(cc,
                               cfg,
                               &root_ref,
                               PAGE_TYPE_BRANCH,
                               trunk_key_slice(spl, key),
                               data,
                               local_found);
   return rc;
}


/*
 *-----------------------------------------------------------------------------
 * trunk_btree_lookup_async
 *
 * Pre-conditions:
 *    The ctxt should've been initialized using
 *    btree_ctxt_init(). If *found `data` has the most
 *    recent answer. the current memtable is older than the most
 *    recent answer
 *
 *    The return value can be either of:
 *      async_locked: A page needed by lookup is locked. User should retry
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
 *-----------------------------------------------------------------------------
 */
static cache_async_result
trunk_btree_lookup_and_merge_async(trunk_handle      *spl,    // IN
                                   trunk_branch      *branch, // IN
                                   char              *key,    // IN
                                   merge_accumulator *data,   // OUT
                                   btree_async_ctxt  *ctxt)    // IN
{
   cache             *cc  = spl->cc;
   btree_config      *cfg = &spl->cfg.btree_cfg;
   cache_async_result res;
   bool               local_found;

   res = btree_lookup_and_merge_async(cc,
                                      cfg,
                                      (page_reference *)branch,
                                      trunk_key_slice(spl, key),
                                      data,
                                      &local_found,
                                      ctxt);
   return res;
}


/*
 *-----------------------------------------------------------------------------
 * Memtable Functions
 *-----------------------------------------------------------------------------
 */

memtable *
trunk_try_get_memtable(trunk_handle *spl, uint64 generation)
{
   uint64    memtable_idx = generation % TRUNK_NUM_MEMTABLES;
   memtable *mt           = &spl->mt_ctxt->mt[memtable_idx];
   if (mt->generation != generation) {
      mt = NULL;
   }
   return mt;
}

/*
 * returns the memtable with generation number generation. Caller must ensure
 * that there exists a memtable with the appropriate generation.
 */
memtable *
trunk_get_memtable(trunk_handle *spl, uint64 generation)
{
   uint64    memtable_idx = generation % TRUNK_NUM_MEMTABLES;
   memtable *mt           = &spl->mt_ctxt->mt[memtable_idx];
   platform_assert(mt->generation == generation);
   return mt;
}

trunk_compacted_memtable *
trunk_get_compacted_memtable(trunk_handle *spl, uint64 generation)
{
   uint64 memtable_idx = generation % TRUNK_NUM_MEMTABLES;

   // this call asserts the generation is correct
   memtable *mt = trunk_get_memtable(spl, generation);
   platform_assert(mt->state != MEMTABLE_STATE_READY);

   return &spl->compacted_memtable[memtable_idx];
}

static inline void
trunk_memtable_inc_ref(trunk_handle *spl, uint64 mt_gen)
{
   memtable *mt = trunk_get_memtable(spl, mt_gen);
   allocator_inc_ref(spl->al, mt->root_addr);
}


void
trunk_memtable_dec_ref(trunk_handle *spl, uint64 generation)
{
   memtable *mt = trunk_get_memtable(spl, generation);
   memtable_dec_ref_maybe_recycle(spl->mt_ctxt, mt);

   // the branch in the compacted memtable is now in the tree, so don't zap it,
   // we don't try to zero out the cmt because that would introduce a race.
}


/*
 * Wrappers for creating/destroying memtable iterators. Increments/decrements
 * the memtable ref count and cleans up if ref count == 0
 */
static void
trunk_memtable_iterator_init(trunk_handle   *spl,
                             btree_iterator *itor,
                             uint64          root_addr,
                             const char     *min_key,
                             const char     *max_key,
                             bool            is_live,
                             bool            inc_ref)
{
   if (inc_ref) {
      allocator_inc_ref(spl->al, root_addr);
   }
   page_reference root_ref = {.addr = root_addr};
   btree_iterator_init(spl->cc,
                       &spl->cfg.btree_cfg,
                       itor,
                       &root_ref,
                       PAGE_TYPE_MEMTABLE,
                       trunk_key_slice(spl, min_key),
                       trunk_key_slice(spl, max_key),
                       FALSE,
                       0);
}

static void
trunk_memtable_iterator_deinit(trunk_handle   *spl,
                               btree_iterator *itor,
                               uint64          mt_gen,
                               bool            dec_ref)
{
   btree_iterator_deinit(itor);
   if (dec_ref) {
      trunk_memtable_dec_ref(spl, mt_gen);
   }
}

/*
 * Attempts to insert (key, data) into the current memtable.
 *
 * Returns:
 *    success if succeeded
 *    locked if the current memtable is full
 *    lock_acquired if the current memtable is full and this thread is
 *       responsible for flushing it.
 */
platform_status
trunk_memtable_insert(trunk_handle *spl, char *key, message msg)
{
   page_handle    *lock_page;
   uint64          generation;
   platform_status rc = memtable_maybe_rotate_and_get_insert_lock(
      spl->mt_ctxt, &generation, &lock_page);
   if (!SUCCESS(rc)) {
      goto out;
   }

   // this call is safe because we hold the insert lock
   memtable *mt = trunk_get_memtable(spl, generation);
   uint64    leaf_generation; // used for ordering the log
   rc = memtable_insert(
      spl->mt_ctxt, mt, spl->heap_id, key, msg, &leaf_generation);
   if (!SUCCESS(rc)) {
      goto unlock_insert_lock;
   }

   if (spl->cfg.use_log) {
      slice key_slice = slice_create(trunk_key_size(spl), key);
      int   crappy_rc = log_write(spl->log, key_slice, msg, leaf_generation);
      if (crappy_rc != 0) {
         goto unlock_insert_lock;
      }
   }

unlock_insert_lock:
   memtable_unget_insert_lock(spl->mt_ctxt, lock_page);
out:
   return rc;
}

/* Assume trunk update lock is held */
static inline void
trunk_get_cow_path(trunk_handle *spl, page_reference *root_ref,
                   char *key, page_handle **node_path,
                   page_reference *ref_array, int *idx,
                   int *root_height, uint16 dest_height)
{
   trunk_default_log_if_enabled(spl, "%s: pid=%lu ==== trunk_get_cow_path  start ====\n", __func__, platform_get_tid());
   // FIXME: spl->root_addr may not be the same with root_addr argument here
   page_handle *node = trunk_node_get(spl, root_ref);

   uint16 height = trunk_height(spl, node);
   *root_height = height;
   int num_cowed = 0;

   trunk_default_log_if_enabled(spl, "%s: pid=%lu, key=%s, dest_height=%d\n", __func__, platform_get_tid(), key, dest_height);
   int h = height;
   do {
      page_handle *cow_node = trunk_alloc(spl, h);
      memcpy(cow_node->data, node->data, trunk_page_size(&spl->cfg));
      node_path[h] = cow_node;
      ref_array[h].addr = cow_node->disk_addr;
      num_cowed += 1;
      // only root is cow here
      // only called during memtable incorporation
      // also break if the node is a leaf
      if (dest_height == TRUNK_MAX_HEIGHT || h == 0) {
         trunk_node_unget(spl, &node);
         break;
      }

      uint16 pivot_no = trunk_find_pivot(spl, node, key, less_than_or_equal);
      debug_assert(pivot_no < trunk_num_children(spl, node));
      char *pivot = trunk_get_pivot(spl, node, pivot_no);
      int cmp = trunk_key_compare(spl, key, pivot);
      if (0 == cmp && h == dest_height) {
         // We choose the first pivot to search this node
         // for splinter_compact_bundle
         debug_assert(pivot_no == 0);
         trunk_node_unget(spl, &node);
         break;
      }
      idx[h] = pivot_no;
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      page_reference ref = pdata->ref;
      page_handle *child = trunk_node_get(spl, &ref);
      trunk_node_unget(spl, &node);
      node = child;
      h = trunk_height(spl, node);
   } while (h >= 0);


   if (num_cowed == 1) {
      goto unlock_root;
   }

   // The for loop below only works when the cow-ed path
   // has at least two node.
   // set the link from parent to child
   for (h = 0; h <= *root_height-1; h++) {
      if (node_path[h] == NULL) {
         continue;
      }
      page_handle *parent = node_path[h+1];
      uint16 child_no = idx[h+1];
      uint16 num_children = trunk_num_children(spl, parent);
      platform_assert(child_no < num_children);
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, parent, child_no);

      trunk_node_unlock(spl, node_path[h], &ref_array[h], __LINE__);

      cache_fill_page_reference(spl->cc, (char*)&pdata->ref, node_path[h]);

      trunk_node_unclaim(spl, node_path[h]);
      trunk_node_unget(spl, &node_path[h]);
   }

unlock_root:
   platform_assert(h == *root_height);
   trunk_node_unlock(spl, node_path[h], &ref_array[h], __LINE__);
   trunk_node_unclaim(spl, node_path[h]);
   trunk_node_unget(spl, &node_path[h]);
   trunk_default_log_if_enabled(spl, "%s: pid=%lu------ trunk_get_cow_path end ---\n", __func__, platform_get_tid());
}

/* Assume trunk update lock is held */
static inline void
trunk_update_ancestor_hash(trunk_handle   *spl,       // int
                           page_handle    *child,     // int
                           page_reference *ref_array, // int
                           page_reference *root_ref,  // out
                           int            *idx,          // in
                           uint16          start_height, // in
                           uint16          root_height)  // in
{
   page_handle *node_path[TRUNK_MAX_HEIGHT] = { 0 };
   node_path[start_height] = child;

   int h = start_height + 1;
   while (h <= root_height) {
      page_handle *parent = trunk_node_get(spl, &ref_array[h]);
      trunk_node_claim(spl, &parent);
      trunk_node_lock(spl, parent);
      node_path[h] = parent;
      uint16 child_no = idx[h];
      uint16 num_children = trunk_num_children(spl, parent);
      platform_assert(child_no < num_children);
      platform_assert(node_path[h-1] != NULL);
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, parent, child_no);

      cache_hash(spl->cc, child, child->disk_addr);
      cache_fill_page_reference(spl->cc, (char*)&ref_array[h-1], child);
      cache_fill_page_reference(spl->cc, (char*)&pdata->ref, child);

      print_sig_if_enabled(spl, ref_array[h-1].hash, "update ancestor child hash");

      child = parent;
      h += 1;
   }

   // Child is the root node
   platform_assert(root_height == h-1);
   cache_hash(spl->cc, child,child->disk_addr);
   cache_fill_page_reference(spl->cc, (char*)root_ref, child);
   cache_fill_page_reference(spl->cc, (char*)&ref_array[h-1], child);
   print_sig_if_enabled(spl, ref_array[h-1].hash, "update ancestor root hash");

   for (h = start_height + 1; h <= root_height; h++) {
      trunk_node_unlock(spl, node_path[h], NULL, __LINE__);
      trunk_node_unclaim(spl, node_path[h]);
      trunk_node_unget(spl, &node_path[h]);
   }
}

static inline void
trunk_node_pre_unlock(trunk_handle *spl, page_handle *node,
                      page_reference *new_root_ref,
                      page_reference *node_ref,
                      int node_height, int root_height,
                      page_reference *ref_array, int *idx,
                      int line)
{
   trunk_default_log_if_enabled(spl, "%s pid=%lu, called by %d\n", __func__,  platform_get_tid(), line);
   trunk_default_log_if_enabled(spl, "%s pid=%lu, root_height=%d, node_height=%d\n", __func__, platform_get_tid(), root_height, node_height);
   trunk_default_log_if_enabled(spl, "%s pid=%lu, node->disk_addr=%ld, new_root_ref->addr=%ld\n", __func__, platform_get_tid(),  node->disk_addr, new_root_ref->addr);

   // TODO(yizheng.jiao): node is changed, need to update the ancestors
   cache_hash(spl->cc, node, node->disk_addr);
   print_sig_if_enabled(spl, cache_get_page_hash(spl->cc, node), "trunk_node_pre_unlock hash:");

   // TODO(yizheng.jiao): we may need to unify these two cases
   if (node->disk_addr == new_root_ref->addr) {
      cache_fill_page_reference(spl->cc, (char*)new_root_ref, node);
   } else {
      trunk_update_ancestor_hash(spl, node, ref_array, new_root_ref, idx, node_height, root_height);
   }
   memcpy(node_ref->hash, cache_get_page_hash(spl->cc, node), HASH_SIZE);
}

/*
 * Compacts the memtable with generation generation and builds its filter.
 * Returns a pointer to the memtable.
 */
static memtable *
trunk_memtable_compact_and_build_filter(trunk_handle  *spl,
                                        uint64         generation,
                                        const threadid tid)
{
   timestamp comp_start = platform_get_timestamp();

   memtable *mt = trunk_get_memtable(spl, generation);

   memtable_transition(mt, MEMTABLE_STATE_FINALIZED, MEMTABLE_STATE_COMPACTING);
   mini_release(&mt->mini, NULL_SLICE);

   trunk_compacted_memtable *cmt =
      trunk_get_compacted_memtable(spl, generation);
   trunk_branch *new_branch = &cmt->branch;
   ZERO_CONTENTS(new_branch);

   uint64         memtable_root_addr = mt->root_addr;
   btree_iterator btree_itor;
   iterator      *itor    = &btree_itor.super;
   const char    *min_key = spl->cfg.data_cfg->min_key;

   trunk_memtable_iterator_init(
      spl, &btree_itor, memtable_root_addr, min_key, NULL, FALSE, FALSE);
   btree_pack_req req;
   btree_pack_req_init(&req,
                       spl->cc,
                       &spl->cfg.btree_cfg,
                       itor,
                       spl->cfg.max_tuples_per_node,
                       UINT64_MAX,
                       spl->cfg.filter_cfg.hash,
                       spl->cfg.filter_cfg.seed,
                       spl->heap_id);
   uint64 pack_start;
   if (spl->cfg.use_stats) {
      spl->stats[tid].root_compactions++;
      pack_start = platform_get_timestamp();
   }
   btree_pack(&req);
   platform_assert(req.num_tuples <= spl->cfg.max_tuples_per_node);
   if (spl->cfg.use_stats) {
      spl->stats[tid].root_compaction_pack_time_ns +=
         platform_timestamp_elapsed(pack_start);
      spl->stats[tid].root_compaction_tuples += req.num_tuples;
      if (req.num_tuples > spl->stats[tid].root_compaction_max_tuples) {
         spl->stats[tid].root_compaction_max_tuples = req.num_tuples;
      }
   }
   trunk_memtable_iterator_deinit(spl, &btree_itor, FALSE, FALSE);

   // TODO(yizheng.jiao): maybe use a function to do this
   new_branch->root_addr = req.root_ref.addr;
   memcpy(&new_branch->sig, req.root_ref.hash, HASH_SIZE);
   trunk_default_log_if_enabled(spl, "%s pid=%lu: generation=%ld\n", __func__, platform_get_tid(), generation);
   print_sig_if_enabled(spl, req.root_ref.hash, "compacted memtable hash:");

   platform_assert(req.num_tuples > 0);
   uint64 filter_build_start;
   if (spl->cfg.use_stats) {
      filter_build_start = platform_get_timestamp();
   }

   cmt->req         = TYPED_ZALLOC(spl->heap_id, cmt->req);
   cmt->req->spl    = spl;
   cmt->req->fp_arr = req.fingerprint_arr;
   cmt->req->type   = TRUNK_COMPACTION_TYPE_MEMTABLE;
   uint32 *dup_fp_arr =
      TYPED_ARRAY_MALLOC(spl->heap_id, dup_fp_arr, req.num_tuples);
   memmove(dup_fp_arr, cmt->req->fp_arr, req.num_tuples * sizeof(uint32));
   routing_filter empty_filter = {0};

   uint64 new_filter_id = trunk_get_filter_id(spl);
   platform_status rc = routing_filter_add(spl->cc,
                                           &spl->cfg.filter_cfg,
                                           spl->heap_id,
                                           &empty_filter,
                                           &cmt->filter,
                                           new_filter_id,
                                           cmt->req->fp_arr,
                                           req.num_tuples,
                                           0);

   platform_assert(SUCCESS(rc));
   if (spl->cfg.use_stats) {
      spl->stats[tid].root_filter_time_ns +=
         platform_timestamp_elapsed(filter_build_start);
      spl->stats[tid].root_filters_built++;
      spl->stats[tid].root_filter_tuples += req.num_tuples;
   }

   btree_pack_req_deinit(&req, spl->heap_id);
   cmt->req->fp_arr = dup_fp_arr;
   if (spl->cfg.use_stats) {
      uint64 comp_time = platform_timestamp_elapsed(comp_start);
      spl->stats[tid].root_compaction_time_ns += comp_time;
      if (comp_start > spl->stats[tid].root_compaction_time_max_ns) {
         spl->stats[tid].root_compaction_time_max_ns = comp_time;
      }
      cmt->wait_start = platform_get_timestamp();
   }

   memtable_transition(mt, MEMTABLE_STATE_COMPACTING, MEMTABLE_STATE_COMPACTED);
   return mt;
}

/*
 * Cases:
 * 1. memtable set to COMP before try_continue tries to set it to incorp
 *       try_continue will successfully assign itself to incorp the memtable
 * 2. memtable set to COMP after try_continue tries to set it to incorp
 *       should_wait will be set to generation, so try_start will incorp
 */
static inline bool
trunk_try_start_incorporate(trunk_handle *spl, uint64 generation)
{
   bool should_start = FALSE;

   memtable_lock_incorporation_lock(spl->mt_ctxt);
   memtable *mt = trunk_try_get_memtable(spl, generation);
   if ((mt == NULL)
       || (generation != memtable_generation_to_incorporate(spl->mt_ctxt)))
   {
      should_start = FALSE;
      goto unlock_incorp_lock;
   }
   should_start = memtable_try_transition(
      mt, MEMTABLE_STATE_COMPACTED, MEMTABLE_STATE_INCORPORATION_ASSIGNED);

unlock_incorp_lock:
   memtable_unlock_incorporation_lock(spl->mt_ctxt);
   return should_start;
}

static inline bool
trunk_try_continue_incorporate(trunk_handle *spl, uint64 next_generation)
{
   bool should_continue = FALSE;

   memtable_lock_incorporation_lock(spl->mt_ctxt);
   memtable *mt = trunk_try_get_memtable(spl, next_generation);
   if (mt == NULL) {
      should_continue = FALSE;
      goto unlock_incorp_lock;
   }
   should_continue = memtable_try_transition(
      mt, MEMTABLE_STATE_COMPACTED, MEMTABLE_STATE_INCORPORATION_ASSIGNED);
   memtable_increment_to_generation_to_incorporate(spl->mt_ctxt,
                                                   next_generation);

unlock_incorp_lock:
   memtable_unlock_incorporation_lock(spl->mt_ctxt);
   return should_continue;
}

/*
 * Function to incorporate the memtable to the root.
 * Carries out the following steps :
 *  4. Lock root (block lookups -- lookups obtain a read lock on the root
 *     before performing lookup on memtable)
 *  5. Add the memtable to the root as a new compacted bundle
 *  6. If root is full, flush until it is no longer full
 *  7. If necessary, split the root
 *  8. Create a new empty memtable in the memtable array at position
 *     curr_memtable.
 *  9. Unlock the root
 *
 * This functions has some preconditions prior to being called.
 *  --> Trunk root node should be write locked.
 *  --> The memtable should have inserts blocked (can_insert == FALSE)
 */
static void
trunk_memtable_incorporate(trunk_handle  *spl,
                           uint64         generation,
                           const threadid tid)
{
   trunk_update_lock(spl);

   // X. Get, claim and lock the lookup lock
   page_handle *mt_lookup_lock_page =
      memtable_uncontended_get_claim_lock_lookup_lock(spl->mt_ctxt);

   memtable_increment_to_generation_retired(spl->mt_ctxt, generation);

   page_handle *node_path[TRUNK_MAX_HEIGHT] = { NULL };
   int idx[TRUNK_MAX_HEIGHT] = { TRUNK_MAX_PIVOTS };
   page_reference ref_array[TRUNK_MAX_HEIGHT] = {0};
   int root_height;
   trunk_default_log_if_enabled(spl, "%s pid=%lu: trunk_get_cow_path is called at %d\n", __func__, platform_get_tid(), __LINE__);
   trunk_get_cow_path(spl, &spl->root_ref, "", node_path, ref_array, idx, &root_height, TRUNK_MAX_HEIGHT);

   // X. Release lookup lock
   memtable_unlock_unclaim_unget_lookup_lock(spl->mt_ctxt, mt_lookup_lock_page);

   page_reference new_root_ref = ref_array[root_height];
   // X. Get, claim and lock the root
   page_handle *root = trunk_node_get(spl, &new_root_ref);
   trunk_node_claim(spl, &root);
   platform_assert(trunk_has_vacancy(spl, root, 1));
   trunk_node_lock(spl, root);

   platform_stream_handle stream;
   platform_status        rc = trunk_open_log_stream_if_enabled(spl, &stream);
   platform_assert_status_ok(rc);
   trunk_log_stream_if_enabled(spl,
                               &stream,
                               "incorporate memtable gen %lu into root %lu\n",
                               generation,
                               root->disk_addr);
   trunk_log_node_if_enabled(&stream, spl, root);
   trunk_log_stream_if_enabled(
      spl, &stream, "----------------------------------------\n");

   /*
    * X. Get a new branch in a bundle for the memtable
    */
   trunk_compacted_memtable *cmt =
      trunk_get_compacted_memtable(spl, generation);
   trunk_compact_bundle_req *req = cmt->req;
   req->bundle_no                = trunk_get_new_bundle(spl, root);
   trunk_bundle    *bundle       = trunk_get_bundle(spl, root, req->bundle_no);
   trunk_subbundle *sb           = trunk_get_new_subbundle(spl, root, 1);
   trunk_branch    *branch       = trunk_get_new_branch(spl, root);
   *branch                       = cmt->branch;

   trunk_default_log_if_enabled(spl, "%s pid=%lu: branch root_addr=%lu, pid=%lu\n", __func__, platform_get_tid(), branch->root_addr, platform_get_tid());
   print_sig_if_enabled(spl, branch->sig, "incorporate branch");

   bundle->start_subbundle       = trunk_subbundle_no(spl, root, sb);
   bundle->end_subbundle         = trunk_end_subbundle(spl, root);
   sb->start_branch              = trunk_branch_no(spl, root, branch);
   sb->end_branch                = trunk_end_branch(spl, root);
   sb->state                     = SB_STATE_COMPACTED;
   routing_filter *filter        = trunk_subbundle_filter(spl, root, sb, 0);
   *filter                       = cmt->filter;
   // When the background job is executed, spl->root_addr has been change
   req->spl                      = spl;
   req->height                   = trunk_height(spl, root);
   req->max_pivot_generation     = trunk_pivot_generation(spl, root);
   trunk_key_copy(spl, req->start_key, trunk_min_key(spl, root));
   trunk_key_copy(spl, req->end_key, trunk_max_key(spl, root));
   trunk_tuples_in_bundle(spl,
                          root,
                          bundle,
                          req->output_pivot_tuple_count,
                          req->output_pivot_kv_byte_count);
   memmove(req->input_pivot_tuple_count,
           req->output_pivot_tuple_count,
           sizeof(req->input_pivot_tuple_count));
   memmove(req->input_pivot_kv_byte_count,
           req->output_pivot_kv_byte_count,
           sizeof(req->input_pivot_kv_byte_count));
   trunk_pivot_add_bundle_tuple_counts(spl,
                                       root,
                                       bundle,
                                       req->output_pivot_tuple_count,
                                       req->output_pivot_kv_byte_count);
   uint16 num_children = trunk_num_children(spl, root);

   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      if (pivot_no != 0) {
         const char *key = trunk_get_pivot(spl, root, pivot_no);
         // NOTE: reference counting handling
         trunk_inc_intersection(spl, branch, key, FALSE);
      }
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, root, pivot_no);
      req->pivot_generation[pivot_no] = pdata->generation;
   }

   debug_assert(trunk_subbundle_branch_count(spl, root, sb) != 0);
   trunk_log_stream_if_enabled(
      spl,
      &stream,
      "enqueuing build filter: range %s-%s, height %u, bundle %u\n",
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->start_key)),
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->end_key)),
      req->height,
      req->bundle_no);
   task_enqueue(
      spl->ts, TASK_TYPE_NORMAL, trunk_bundle_build_filters, req, TRUE);

   // X. Incorporate new memtable into the bundle
   memtable *mt = trunk_get_memtable(spl, generation);
   // Normally need to hold incorp_mutex, but debug code and also guaranteed no
   // one is changing gen_to_incorp (we are the only thread that would try)
   debug_assert(generation == memtable_generation_to_incorporate(spl->mt_ctxt));
   memtable_transition(
      mt, MEMTABLE_STATE_INCORPORATION_ASSIGNED, MEMTABLE_STATE_INCORPORATING);
   *branch = cmt->branch;
   *filter = cmt->filter;
   if (spl->cfg.use_stats) {
      spl->stats[tid].memtable_flush_wait_time_ns +=
         platform_timestamp_elapsed(cmt->wait_start);
   }

   memtable_transition(
      mt, MEMTABLE_STATE_INCORPORATING, MEMTABLE_STATE_INCORPORATED);
   trunk_log_node_if_enabled(&stream, spl, root);
   trunk_log_stream_if_enabled(
      spl, &stream, "----------------------------------------\n");
   trunk_log_stream_if_enabled(spl, &stream, "\n");
   trunk_close_log_stream_if_enabled(spl, &stream);

   // X. If root is full, flush until it is no longer full
   uint64 flush_start;
   if (spl->cfg.use_stats) {
      flush_start = platform_get_timestamp();
   }

   uint64 wait = 1;
   while (trunk_node_is_full(spl, root)) {
      platform_status rc = trunk_flush_fullest(spl, root);
      if (!SUCCESS(rc)) {
         // TODO(yizheng.jiao): need to figure the argument for unlock
         platform_assert(0);
         trunk_node_unlock(spl, root, &new_root_ref, __LINE__);
         platform_sleep(wait);
         wait = wait > 2048 ? 2048 : 2 * wait;
         trunk_node_lock(spl, root);
      }
   }

   // X. If necessary, split the root
   if (trunk_needs_split(spl, root)) {
      trunk_split_root(spl, root);
   }

   // X. Unlock the root
   trunk_node_unlock(spl, root, &new_root_ref, __LINE__);
   trunk_node_unclaim(spl, root);
   trunk_node_unget(spl, &root);

   // X. Dec-ref the now-incorporated memtable
   memtable_dec_ref_maybe_recycle(spl->mt_ctxt, mt);

   if (spl->cfg.use_stats) {
      const threadid tid = platform_get_tid();
      flush_start        = platform_timestamp_elapsed(flush_start);
      spl->stats[tid].memtable_flush_time_ns += flush_start;
      spl->stats[tid].memtable_flushes++;
      if (flush_start > spl->stats[tid].memtable_flush_time_max_ns) {
         spl->stats[tid].memtable_flush_time_max_ns = flush_start;
      }
   }

   spl->root_ref = new_root_ref;
   trunk_update_unlock(spl);
}

/*
 * Main wrapper function to carry out incorporation of a memtable.
 *
 * If background threads are disabled this function is called inline in the
 * context of the foreground thread.  If background threads are enabled, this
 * function is called in the context of the memtable worker thread.
 */
static void
trunk_memtable_flush_internal(trunk_handle *spl, uint64 generation)
{
   const threadid tid = platform_get_tid();
   // pack and build filter.
   trunk_memtable_compact_and_build_filter(spl, generation, tid);

   // If we are assigned to do so, incorporate the memtable onto the root node.
   if (!trunk_try_start_incorporate(spl, generation)) {
      goto out;
   }
   do {
      trunk_memtable_incorporate(spl, generation, tid);
      generation++;
   } while (trunk_try_continue_incorporate(spl, generation));
out:
   return;
}

static void
trunk_memtable_flush_internal_virtual(void *arg, void *scratch)
{
   trunk_memtable_args *mt_args = arg;
   trunk_memtable_flush_internal(mt_args->spl, mt_args->generation);
}

/*
 * Function to trigger a memtable incorporation. Called in the context of
 * the foreground doing insertions.
 * If background threads are not enabled, this function does the entire memtable
 * incorporation inline.
 * If background threads are enabled, this function just queues up the task to
 * carry out the incorporation, swaps the curr_memtable pointer, claims the
 * root and returns.
 */
void
trunk_memtable_flush(trunk_handle *spl, uint64 generation)
{
   trunk_compacted_memtable *cmt =
      trunk_get_compacted_memtable(spl, generation);
   cmt->mt_args.spl        = spl;
   cmt->mt_args.generation = generation;
   task_enqueue(spl->ts,
                TASK_TYPE_MEMTABLE,
                trunk_memtable_flush_internal_virtual,
                &cmt->mt_args,
                FALSE);
}

void
trunk_memtable_flush_virtual(void *arg, uint64 generation)
{
   trunk_handle *spl = arg;
   trunk_memtable_flush(spl, generation);
}

static inline uint64
trunk_memtable_root_addr_for_lookup(trunk_handle *spl,
                                    uint64        generation,
                                    bool         *is_compacted,
                                    char         *sig)
{
   memtable *mt = trunk_get_memtable(spl, generation);
   platform_assert(memtable_ok_to_lookup(mt));

   if (memtable_ok_to_lookup_compacted(mt)) {
      // lookup in packed tree
      *is_compacted = TRUE;
      trunk_compacted_memtable *cmt =
         trunk_get_compacted_memtable(spl, generation);
      // copy the signature from the cmt to `sig`
      memcpy(sig, cmt->branch.sig, HASH_SIZE);
      return cmt->branch.root_addr;
   } else {
      *is_compacted = FALSE;
      return mt->root_addr;
   }
}

/*
 * trunk_memtable_lookup
 *
 * Pre-conditions:
 *    If *found
 *       `data` has the most recent answer.
 *       the current memtable is older than the most recent answer
 *
 * Post-conditions:
 *    if *found, the data can be found in `data`.
 */
static platform_status
trunk_memtable_lookup(trunk_handle      *spl,
                      uint64             generation,
                      char              *key,
                      merge_accumulator *data)
{
   cache *const        cc  = spl->cc;
   btree_config *const cfg = &spl->cfg.btree_cfg;
   bool                memtable_is_compacted;
   page_reference      root_ref;
   uint64              root_addr = trunk_memtable_root_addr_for_lookup(
      spl, generation, &memtable_is_compacted, root_ref.hash);
   trunk_default_log_if_enabled(spl, "%s pid=%lu: memtable_is_compacted=%d\n", __func__, platform_get_tid(),  memtable_is_compacted);
   root_ref.addr = root_addr;
   page_type type =
      memtable_is_compacted ? PAGE_TYPE_BRANCH : PAGE_TYPE_MEMTABLE;
   platform_status rc;
   bool            local_found;
   rc = btree_lookup_and_merge(
      cc, cfg, &root_ref, type, trunk_key_slice(spl, key), data, &local_found);
   return rc;
}

/*
 *-----------------------------------------------------------------------------
 * Filter functions
 *-----------------------------------------------------------------------------
 */

static inline routing_config *
trunk_routing_cfg(trunk_handle *spl)
{
   return &spl->cfg.filter_cfg;
}

static inline void
trunk_inc_filter(trunk_handle *spl, routing_filter *filter)
{
   debug_assert(filter->addr != 0);
   mini_unkeyed_inc_ref(spl->cc, filter->meta_head);
}

static inline void
trunk_dec_filter(trunk_handle *spl, routing_filter *filter)
{
   if (filter->addr == 0) {
      return;
   }
   cache *cc = spl->cc;
   routing_filter_zap(cc, filter);
}

/*
 * Scratch space used for filter building.
 */
typedef struct trunk_filter_scratch {
   char           start_key[MAX_KEY_SIZE];
   char           end_key[MAX_KEY_SIZE];
   uint16         height;
   bool           should_build[TRUNK_MAX_PIVOTS];
   routing_filter old_filter[TRUNK_MAX_PIVOTS];
   uint16         value[TRUNK_MAX_PIVOTS];
   routing_filter filter[TRUNK_MAX_PIVOTS];
   uint32        *fp_arr;
} trunk_filter_scratch;

static inline void
trunk_filter_scratch_init(trunk_compact_bundle_req *compact_req,
                          trunk_filter_scratch     *filter_scratch)
{
   ZERO_CONTENTS(filter_scratch);
   filter_scratch->fp_arr = compact_req->fp_arr;
}
static inline bool
trunk_compact_bundle_node_has_split(trunk_handle             *spl,
                                    trunk_compact_bundle_req *req,
                                    page_handle              *node)
{
   return !trunk_key_equal(spl, req->end_key, trunk_max_key(spl, node));
}

static inline platform_status
trunk_compact_bundle_node_get(trunk_handle             *spl,
                              trunk_compact_bundle_req *req,
                              page_handle             **node)
{
   return trunk_node_get_by_key_and_height(
      spl, req->start_key, req->height, node);
}

static inline platform_status
trunk_filter_build_node_get_and_claim(trunk_handle         *spl,
                                      trunk_filter_scratch *req,
                                      page_handle         **node)
{
   platform_status rc =
      trunk_node_get_by_key_and_height(spl, req->start_key, req->height, node);
   if (!SUCCESS(rc)) {
      return rc;
   }
   trunk_node_claim(spl, node);
   if (trunk_height(spl, *node) != req->height) {
      trunk_node_unclaim(spl, *node);
      trunk_node_unget(spl, node);
      return trunk_filter_build_node_get_and_claim(spl, req, node);
   }
   return rc;
}

static inline bool
trunk_build_filter_should_abort(trunk_compact_bundle_req *req,
                                page_handle              *node)
{
   trunk_handle *spl = req->spl;
   if (trunk_is_leaf(spl, node)
       && trunk_compact_bundle_node_has_split(spl, req, node))
   {
      platform_stream_handle stream;
      platform_status rc = trunk_open_log_stream_if_enabled(spl, &stream);
      platform_assert_status_ok(rc);
      trunk_log_stream_if_enabled(
         spl,
         &stream,
         "build_filter leaf abort: range %s-%s, height %u, bundle %u\n",
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->start_key)),
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->end_key)),
         req->height,
         req->bundle_no);
      trunk_log_node_if_enabled(&stream, spl, node);
      trunk_close_log_stream_if_enabled(spl, &stream);
      return TRUE;
   }
   return FALSE;
}

static inline bool
trunk_build_filter_should_skip(trunk_compact_bundle_req *req, page_handle *node)
{
   trunk_handle *spl = req->spl;
   if (!trunk_bundle_live(spl, node, req->bundle_no)) {
      platform_stream_handle stream;
      platform_status rc = trunk_open_log_stream_if_enabled(spl, &stream);
      platform_assert_status_ok(rc);
      trunk_log_stream_if_enabled(
         spl,
         &stream,
         "build_filter flush abort: range %s-%s, height %u, bundle %u\n",
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->start_key)),
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->end_key)),
         req->height,
         req->bundle_no);
      trunk_log_node_if_enabled(&stream, spl, node);
      trunk_close_log_stream_if_enabled(spl, &stream);
      return TRUE;
   }
   return FALSE;
}

static inline bool
trunk_build_filter_should_reenqueue(trunk_compact_bundle_req *req,
                                    page_handle              *node)
{
   trunk_handle *spl = req->spl;
   if (req->bundle_no != trunk_start_bundle(spl, node)) {
      platform_stream_handle stream;
      platform_status rc = trunk_open_log_stream_if_enabled(spl, &stream);
      platform_assert_status_ok(rc);
      trunk_log_stream_if_enabled(
         spl,
         &stream,
         "build_filter reenqueuing: range %s-%s, height %u, bundle %u\n",
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->start_key)),
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->end_key)),
         req->height,
         req->bundle_no);
      trunk_log_node_if_enabled(&stream, spl, node);
      trunk_close_log_stream_if_enabled(spl, &stream);
      return TRUE;
   }
   return FALSE;
}

static inline void
trunk_prepare_build_filter(trunk_handle             *spl,
                           trunk_compact_bundle_req *compact_req,
                           trunk_filter_scratch     *filter_scratch,
                           page_handle              *node)
{
   uint16 height = trunk_height(spl, node);
   platform_assert(compact_req->height == height);
   platform_assert(compact_req->bundle_no == trunk_start_bundle(spl, node));

   trunk_filter_scratch_init(compact_req, filter_scratch);

   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (trunk_bundle_live_for_pivot(
             spl, node, compact_req->bundle_no, pivot_no)) {
         uint64 pos = trunk_process_generation_to_pos(
            spl, compact_req, pdata->generation);
         platform_assert(pos != TRUNK_MAX_PIVOTS);
         filter_scratch->old_filter[pos] = pdata->filter;
         filter_scratch->value[pos] =
            trunk_pivot_whole_branch_count(spl, node, pdata);
         filter_scratch->should_build[pos] = TRUE;
      }
   }

   // copy the node's start and end key so that replacement can determine when
   // to stop
   trunk_key_copy(spl, filter_scratch->start_key, trunk_min_key(spl, node));
   trunk_key_copy(spl, filter_scratch->end_key, trunk_max_key(spl, node));
   filter_scratch->height = height;
}

static inline void
trunk_process_generation_to_fp_bounds(trunk_handle             *spl,
                                      trunk_compact_bundle_req *req,
                                      uint64                    generation,
                                      uint32                   *fp_start,
                                      uint32                   *fp_end)
{
   uint64 pos          = 0;
   uint64 fp_start_int = 0;
   while (pos != TRUNK_MAX_PIVOTS && req->pivot_generation[pos] != generation) {
      fp_start_int += req->output_pivot_tuple_count[pos];
      pos++;
   }
   if (pos + 1 == TRUNK_MAX_PIVOTS) {
      platform_assert(FALSE);
   }
   uint64 fp_end_int = fp_start_int + req->output_pivot_tuple_count[pos];
   *fp_start         = fp_start_int;
   *fp_end           = fp_end_int;
}

static inline void
trunk_build_filters(trunk_handle             *spl,
                    trunk_compact_bundle_req *compact_req,
                    trunk_filter_scratch     *filter_scratch)
{
   threadid tid;
   uint64   filter_build_start;
   uint16   height;
   if (spl->cfg.use_stats) {
      tid                = platform_get_tid();
      height             = compact_req->height;
      filter_build_start = platform_get_timestamp();
   }
   for (uint64 pos = 0; pos < TRUNK_MAX_PIVOTS; pos++) {
      if (!filter_scratch->should_build[pos]) {
         continue;
      }
      routing_filter old_filter = filter_scratch->old_filter[pos];
      uint32         fp_start, fp_end;
      uint64         generation = compact_req->pivot_generation[pos];
      trunk_process_generation_to_fp_bounds(
         spl, compact_req, generation, &fp_start, &fp_end);
      uint32 *fp_arr           = filter_scratch->fp_arr + fp_start;
      uint32  num_fingerprints = fp_end - fp_start;
      if (num_fingerprints == 0) {
         if (old_filter.addr != 0) {
            trunk_inc_filter(spl, &old_filter);
         }
         filter_scratch->filter[pos] = old_filter;
         continue;
      }
      routing_filter  new_filter;
      routing_config *filter_cfg = &spl->cfg.filter_cfg;
      uint16          value      = filter_scratch->value[pos];
      uint64 new_filter_id       = trunk_get_filter_id(spl);
      platform_status rc         = routing_filter_add(spl->cc,
                                              filter_cfg,
                                              spl->heap_id,
                                              &old_filter,
                                              &new_filter,
                                              new_filter_id, 
                                              fp_arr,
                                              num_fingerprints,
                                              value);
      platform_assert(SUCCESS(rc));

      filter_scratch->filter[pos]       = new_filter;
      filter_scratch->should_build[pos] = FALSE;
      if (spl->cfg.use_stats) {
         spl->stats[tid].filters_built[height]++;
         spl->stats[tid].filter_tuples[height] += num_fingerprints;
      }
   }

   if (spl->cfg.use_stats) {
      spl->stats[tid].filter_time_ns[height] +=
         platform_timestamp_elapsed(filter_build_start);
   }
}

static inline void
trunk_replace_routing_filter(trunk_handle             *spl,
                             trunk_compact_bundle_req *compact_req,
                             trunk_filter_scratch     *filter_scratch,
                             page_handle              *node)
{
   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      uint64            pos =
         trunk_process_generation_to_pos(spl, compact_req, pdata->generation);
      if (!trunk_bundle_live_for_pivot(
             spl, node, compact_req->bundle_no, pivot_no)) {
         if (pos != TRUNK_MAX_PIVOTS && filter_scratch->filter[pos].addr != 0) {
            trunk_dec_filter(spl, &filter_scratch->filter[pos]);
            ZERO_CONTENTS(&filter_scratch->filter[pos]);
         }
         continue;
      }
      platform_assert(pos != TRUNK_MAX_PIVOTS);
      debug_assert(pdata->generation < compact_req->max_pivot_generation);
      trunk_dec_filter(spl, &pdata->filter);
      pdata->filter = filter_scratch->filter[pos];
      ZERO_CONTENTS(&filter_scratch->filter[pos]);

      // Move the tuples count from the bundle to whole branch
      uint64 bundle_num_tuples = compact_req->output_pivot_tuple_count[pos];
      debug_assert(pdata->num_tuples_bundle >= bundle_num_tuples);
      debug_assert((bundle_num_tuples == 0) == (pdata->filter.addr == 0));
      pdata->num_tuples_bundle -= bundle_num_tuples;
      pdata->num_tuples_whole += bundle_num_tuples;

      // Move the kv_bytes count from the bundle to whole branch
      uint64 bundle_num_kv_bytes = compact_req->output_pivot_kv_byte_count[pos];
      debug_assert(pdata->num_kv_bytes_bundle >= bundle_num_kv_bytes);
      pdata->num_kv_bytes_bundle -= bundle_num_kv_bytes;
      pdata->num_kv_bytes_whole += bundle_num_kv_bytes;

      uint64 num_tuples_to_reclaim = trunk_pivot_tuples_to_reclaim(spl, pdata);
      if (pdata->srq_idx != -1 && spl->cfg.reclaim_threshold != UINT64_MAX) {
         srq_update(&spl->srq, pdata->srq_idx, num_tuples_to_reclaim);
         srq_print(&spl->srq);
      } else if ((num_tuples_to_reclaim > TRUNK_MIN_SPACE_RECL)
                 && (spl->cfg.reclaim_threshold != UINT64_MAX))
      {
         srq_data data  = {.ref              = { .addr = node->disk_addr },
                           .pivot_generation = pdata->generation,
                           .priority         = num_tuples_to_reclaim};
         pdata->srq_idx = srq_insert(&spl->srq, data);
         srq_print(&spl->srq);
      }
   }
}

/*
 * Asynchronous task function which builds routing filters for a compacted
 * bundle
 */
void
trunk_bundle_build_filters(void *arg, void *scratch)
{
   trunk_compact_bundle_req *compact_req = (trunk_compact_bundle_req *)arg;
   trunk_handle             *spl         = compact_req->spl;

   trunk_update_lock(spl);

   page_handle *node_path[TRUNK_MAX_HEIGHT] = { NULL };
   int idx[TRUNK_MAX_HEIGHT] = { TRUNK_MAX_PIVOTS };
   page_reference ref_array[TRUNK_MAX_HEIGHT] = {0};
   int root_height;
   int node_height;
   page_reference new_root_ref = spl->root_ref;
   page_reference node_ref;

   bool should_continue_build_filters = TRUE;
   while (should_continue_build_filters) {
      page_handle    *node = NULL;
      trunk_get_cow_path(spl, &new_root_ref, compact_req->start_key, node_path, ref_array, idx, &root_height, compact_req->height);
      node_ref = ref_array[compact_req->height];
      node_height = compact_req->height;
      node = trunk_node_get(spl, &node_ref);
      trunk_default_log_if_enabled(
         spl, "%s: pid=%lu performed cow path to build filters, root_addr=%lu, root_height=%d, node_addr=%lu, node_height=%d\n",
         __func__, platform_get_tid(), new_root_ref.addr, root_height, node->disk_addr, node_height);

      platform_stream_handle stream;
      trunk_open_log_stream_if_enabled(spl, &stream);
      trunk_log_stream_if_enabled(
         spl,
         &stream,
         "build_filter: range %s-%s, height %u, bundle %u\n",
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), compact_req->start_key)),
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), compact_req->end_key)),
         compact_req->height,
         compact_req->bundle_no);
      trunk_log_node_if_enabled(&stream, spl, node);
      if (trunk_build_filter_should_abort(compact_req, node)) {
         trunk_log_stream_if_enabled(spl, &stream, "leaf split, aborting\n");
         trunk_node_unget(spl, &node);
         goto out;
      }
      if (trunk_build_filter_should_skip(compact_req, node)) {
         trunk_log_stream_if_enabled(
            spl, &stream, "bundle flushed, skipping\n");
         goto next_node;
      }

      if (trunk_build_filter_should_reenqueue(compact_req, node)) {
         task_enqueue(spl->ts,
                      TASK_TYPE_NORMAL,
                      trunk_bundle_build_filters,
                      compact_req,
                      FALSE);
         trunk_log_stream_if_enabled(
            spl, &stream, "out of order, reequeuing\n");
         trunk_close_log_stream_if_enabled(spl, &stream);
         trunk_node_unget(spl, &node);
         // NOTE: function return here
         // let us update the root of the trunk
         spl->root_ref = new_root_ref;
         trunk_update_unlock(spl);
         trunk_default_log_if_enabled(
            spl, "%s: pid=%lu, abort after reenqueue the task\n", __func__, platform_get_tid());
         return;
      }

      debug_assert(trunk_verify_node(spl, node));
      trunk_filter_scratch filter_scratch = {0};

      new_root_ref = ref_array[root_height];

      trunk_prepare_build_filter(spl, compact_req, &filter_scratch, node);
      trunk_node_unget(spl, &node);

      trunk_build_filters(spl, compact_req, &filter_scratch);

      trunk_log_stream_if_enabled(spl, &stream, "Filters built\n");

      bool should_continue_replacing_filters = TRUE;
      while (should_continue_replacing_filters) {
         trunk_get_cow_path(spl, &new_root_ref, compact_req->start_key, node_path, ref_array, idx, &root_height, compact_req->height);
         node_ref = ref_array[compact_req->height];
         new_root_ref = ref_array[root_height];
         node = trunk_node_get(spl, &node_ref);
         trunk_default_log_if_enabled(
            spl, "%s: pid=%lu performed cow path to replace filters, root_addr=%lu, root_height=%d, node_addr=%lu, node_height=%d\n",
            __func__, platform_get_tid(), new_root_ref.addr, root_height, node->disk_addr, compact_req->height);
         trunk_node_claim(spl, &node);

         if (trunk_build_filter_should_abort(compact_req, node)) {
            trunk_log_stream_if_enabled(
               spl, &stream, "replace_filter abort leaf split\n");
            trunk_node_unclaim(spl, node);
            trunk_node_unget(spl, &node);
            for (uint64 pos = 0; pos < TRUNK_MAX_PIVOTS; pos++) {
               trunk_dec_filter(spl, &filter_scratch.filter[pos]);
            }
            goto out;
         }

         trunk_node_lock(spl, node);
         trunk_replace_routing_filter(spl, compact_req, &filter_scratch, node);
         if (trunk_bundle_live(spl, node, compact_req->bundle_no)) {
            // disable this line of code to not destroy the filters
            trunk_clear_bundle(spl, node, compact_req->bundle_no);
         }
         trunk_node_pre_unlock(spl, node, &new_root_ref,
                               &node_ref, node_height,
                               root_height, ref_array, idx, __LINE__);

         print_sig_if_enabled(spl, new_root_ref.hash, "new_root_hash");
         trunk_node_unlock(spl, node, NULL, __LINE__);
         trunk_node_unclaim(spl, node);
         debug_assert(trunk_verify_node(spl, node));

         trunk_log_node_if_enabled(&stream, spl, node);
         trunk_log_stream_if_enabled(
            spl, &stream, "Filters replaced in node:\n");
         trunk_log_stream_if_enabled(spl,
                                     &stream,
                                     "addr: %lu, height: %u\n",
                                     node->disk_addr,
                                     trunk_height(spl, node));
         trunk_log_stream_if_enabled(
            spl,
            &stream,
            "range: %s-%s\n",
            key_string(
               trunk_data_config(spl),
               slice_create(trunk_key_size(spl), compact_req->start_key)),
            key_string(
               trunk_data_config(spl),
               slice_create(trunk_key_size(spl), compact_req->end_key)));

         trunk_key_copy(
            spl, filter_scratch.start_key, trunk_max_key(spl, node));
         should_continue_replacing_filters = !trunk_key_equal(
            spl, filter_scratch.start_key, filter_scratch.end_key);
         if (should_continue_replacing_filters) {
            trunk_log_stream_if_enabled(
               spl,
               &stream,
               "replace_filter split: range %s-%s, height %u, bundle %u\n",
               key_string(
                  trunk_data_config(spl),
                  slice_create(trunk_key_size(spl), compact_req->start_key)),
               key_string(
                  trunk_data_config(spl),
                  slice_create(trunk_key_size(spl), compact_req->end_key)),
               compact_req->height,
               compact_req->bundle_no);
            debug_assert(compact_req->height != 0);
            trunk_node_unget(spl, &node);
         }
      } // should_continue_replacing_filters

      for (uint64 pos = 0; pos < TRUNK_MAX_PIVOTS; pos++) {
         trunk_dec_filter(spl, &filter_scratch.filter[pos]);
      }

   next_node:
      debug_assert(trunk_verify_node(spl, node));
      trunk_key_copy(spl, compact_req->start_key, trunk_max_key(spl, node));
      trunk_node_unget(spl, &node);
      should_continue_build_filters =
         !trunk_key_equal(spl, compact_req->start_key, compact_req->end_key);
      if (should_continue_build_filters) {
         trunk_log_stream_if_enabled(
            spl,
            &stream,
            "build_filter split: range %s-%s, height %u, bundle %u\n",
            key_string(
               trunk_data_config(spl),
               slice_create(trunk_key_size(spl), compact_req->start_key)),
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), compact_req->end_key)),
            compact_req->height,
            compact_req->bundle_no);
         debug_assert(compact_req->height != 0);
      }
      trunk_close_log_stream_if_enabled(spl, &stream);
   };

out:
   platform_free(spl->heap_id, compact_req->fp_arr);
   platform_free(spl->heap_id, compact_req);
   trunk_maybe_reclaim_space(spl);

   // FIXME: is this a good place to switch the root
   spl->root_ref = new_root_ref;
   trunk_update_unlock(spl);
   return;
}

static cache_async_result
trunk_filter_lookup_async(trunk_handle       *spl,
                          routing_config     *cfg,
                          routing_filter     *filter,
                          char               *key,
                          uint64             *found_values,
                          routing_async_ctxt *ctxt)
{
   slice key_slice = slice_create(cfg->data_cfg->key_size, key);
   return routing_filter_lookup_async(
      spl->cc, cfg, filter, key_slice, found_values, ctxt);
}

/*
 *-----------------------------------------------------------------------------
 * Flush Functions
 *-----------------------------------------------------------------------------
 */

/*
 * flush_into_bundle flushes all live branches (including fractional branches)
 * for the pivot from parent to a new bundle in child and initializes the
 * compact_bundle_req.
 *
 * NOTE: parent and child must be write locked.
 */
trunk_bundle *
trunk_flush_into_bundle(trunk_handle             *spl,    // IN
                        page_handle              *parent, // IN (modified)
                        page_handle              *child,  // IN (modified)
                        trunk_pivot_data         *pdata,  // IN
                        trunk_compact_bundle_req *req)    // IN/OUT
{
   debug_assert(trunk_verify_node(spl, child));

   platform_stream_handle stream;
   platform_status        rc = trunk_open_log_stream_if_enabled(spl, &stream);
   platform_assert_status_ok(rc);
   trunk_log_stream_if_enabled(spl,
                               &stream,
                               "flush from %lu to %lu\n",
                               parent->disk_addr,
                               child->disk_addr);
   trunk_log_node_if_enabled(&stream, spl, parent);
   trunk_log_node_if_enabled(&stream, spl, child);
   trunk_log_stream_if_enabled(
      spl, &stream, "----------------------------------------\n");
   req->spl                  = spl;
   req->height               = trunk_height(spl, child);
   // child's hdr is updated in this function
   req->bundle_no            = trunk_get_new_bundle(spl, child);
   req->max_pivot_generation = trunk_pivot_generation(spl, child);

   trunk_key_copy(spl, req->start_key, trunk_min_key(spl, child));
   trunk_key_copy(spl, req->end_key, trunk_max_key(spl, child));

   uint16 num_children = trunk_num_children(spl, child);
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, child, pivot_no);
      req->pivot_generation[pivot_no] = pdata->generation;
   }

   trunk_bundle *bundle = trunk_get_bundle(spl, child, req->bundle_no);

   // if there are whole branches, flush them into a subbundle
   if (trunk_branch_is_whole(spl, parent, pdata->start_branch)) {
      trunk_subbundle *child_sb = trunk_get_new_subbundle(spl, child, 1);
      bundle->start_subbundle   = trunk_subbundle_no(spl, child, child_sb);
      child_sb->state           = SB_STATE_UNCOMPACTED_INDEX;

      // create a subbundle from the whole branches of the parent
      child_sb->start_branch = trunk_end_branch(spl, child);
      trunk_log_stream_if_enabled(
         spl, &stream, "subbundle %hu\n", bundle->start_subbundle);
      for (uint16 branch_no = pdata->start_branch;
           trunk_branch_is_whole(spl, parent, branch_no);
           branch_no = trunk_add_branch_number(spl, branch_no, 1))
      {
         trunk_branch *parent_branch = trunk_get_branch(spl, parent, branch_no);
         trunk_log_stream_if_enabled(
            spl, &stream, "%lu\n", parent_branch->root_addr);
         trunk_branch *new_branch = trunk_get_new_branch(spl, child);
         *new_branch              = *parent_branch;
      }
      child_sb->end_branch = trunk_end_branch(spl, child);
      routing_filter *child_filter =
         trunk_subbundle_filter(spl, child, child_sb, 0);
      *child_filter = pdata->filter;
      ZERO_STRUCT(pdata->filter);
      debug_assert(trunk_subbundle_branch_count(spl, child, child_sb) != 0);
   } else {
      bundle->start_subbundle = trunk_end_subbundle(spl, child);
   }

   ////////////////////////////////////////////////////////////////////////
   ////////////////////////////////////////////////////////////////////////
   // for each subbundle in the parent, create a subbundle in the child
   if (trunk_pivot_bundle_count(spl, parent, pdata) != 0) {
      uint16 pivot_start_sb_no =
         trunk_pivot_start_subbundle(spl, parent, pdata);
      for (uint16 parent_sb_no = pivot_start_sb_no;
           parent_sb_no != trunk_end_subbundle(spl, parent);
           parent_sb_no = trunk_add_subbundle_number(spl, parent_sb_no, 1))
      {
         trunk_subbundle *parent_sb =
            trunk_get_subbundle(spl, parent, parent_sb_no);
         uint16 filter_count =
            trunk_subbundle_filter_count(spl, parent, parent_sb);
         trunk_subbundle *child_sb =
            trunk_get_new_subbundle(spl, child, filter_count);
         child_sb->state        = parent_sb->state;
         child_sb->start_branch = trunk_end_branch(spl, child);
         trunk_log_stream_if_enabled(spl,
                                     &stream,
                                     "subbundle %hu from subbundle %hu\n",
                                     trunk_subbundle_no(spl, child, child_sb),
                                     parent_sb_no);
         for (uint16 branch_no = parent_sb->start_branch;
              branch_no != parent_sb->end_branch;
              branch_no = trunk_add_branch_number(spl, branch_no, 1))
         {
            trunk_branch *parent_branch =
               trunk_get_branch(spl, parent, branch_no);
            trunk_log_stream_if_enabled(
               spl, &stream, "%lu\n", parent_branch->root_addr);
            trunk_branch *new_branch = trunk_get_new_branch(spl, child);
            *new_branch              = *parent_branch;
         }
         child_sb->end_branch = trunk_end_branch(spl, child);
         for (uint16 i = 0; i < filter_count; i++) {
            routing_filter *child_filter =
               trunk_subbundle_filter(spl, child, child_sb, i);
            routing_filter *parent_filter =
               trunk_subbundle_filter(spl, parent, parent_sb, i);
            *child_filter = *parent_filter;
            trunk_inc_filter(spl, child_filter);
         }
         debug_assert(trunk_subbundle_branch_count(spl, child, child_sb) != 0);
      }
   }
   bundle->end_subbundle = trunk_end_subbundle(spl, child);

   // clear the branches in the parent's pivot
   trunk_pivot_clear(spl, parent, pdata);

   trunk_log_stream_if_enabled(
      spl, &stream, "----------------------------------------\n");
   trunk_log_node_if_enabled(&stream, spl, parent);
   trunk_log_node_if_enabled(&stream, spl, child);
   trunk_log_stream_if_enabled(spl, &stream, "flush done\n");
   trunk_log_stream_if_enabled(spl, &stream, "\n");
   trunk_close_log_stream_if_enabled(spl, &stream);

   platform_assert(bundle->start_subbundle != bundle->end_subbundle,
                   "Flush into empty bundle.\n");

   return bundle;
}

/*
 * room_to_flush checks that there is enough physical space in child to flush
 * from parent.
 *
 * NOTE: parent and child must have at least read locks
 */
static inline bool
trunk_room_to_flush(trunk_handle     *spl,
                    page_handle      *parent,
                    page_handle      *child,
                    trunk_pivot_data *pdata)
{
   uint16 child_branches   = trunk_branch_count(spl, child);
   uint16 flush_branches   = trunk_pivot_branch_count(spl, parent, pdata);
   uint16 child_bundles    = trunk_bundle_count(spl, child);
   uint16 child_subbundles = trunk_subbundle_count(spl, child);
   uint16 flush_subbundles =
      trunk_pivot_subbundle_count(spl, parent, pdata) + 1;

   return child_branches + flush_branches < spl->cfg.hard_max_branches_per_node
          && child_bundles + 2 <= TRUNK_MAX_BUNDLES
          && child_subbundles + flush_subbundles + 1 < TRUNK_MAX_SUBBUNDLES;
}

/*
 * flush flushes from parent to the child indicated by pdata.
 *
 * Failure can occur if there is not enough space in the child.
 *
 * NOTE: parent must be write locked
 */
platform_status
trunk_flush(trunk_handle     *spl,
            page_handle      *parent,
            trunk_pivot_data *pdata,
            bool              is_space_rec)
{
   platform_status rc;

   uint64   wait_start, flush_start;
   threadid tid;
   if (spl->cfg.use_stats) {
      tid        = platform_get_tid();
      wait_start = platform_get_timestamp();
   }

   page_reference ref_p;
   page_reference ref_ch;

   page_reference ref = pdata->ref;
   page_handle *child = trunk_node_get(spl, &ref);
   trunk_node_claim(spl, &child);

   if (!trunk_room_to_flush(spl, parent, child, pdata)) {
      platform_error_log(
         "Flush failed: %lu %lu\n", parent->disk_addr, child->disk_addr);
      if (spl->cfg.use_stats) {
         if (parent->disk_addr == spl->root_ref.addr) {
            spl->stats[tid].root_failed_flushes++;
         } else {
            spl->stats[tid].failed_flushes[trunk_height(spl, parent)]++;
         }
      }
      trunk_node_unclaim(spl, child);
      trunk_node_unget(spl, &child);
      return STATUS_INVALID_STATE;
   }

   if ((!is_space_rec && pdata->srq_idx != -1)
       && spl->cfg.reclaim_threshold != UINT64_MAX)
   {
      // platform_default_log("Deleting %12lu-%lu (index %lu) from SRQ\n",
      //       parent->disk_addr, pdata->generation, pdata->srq_idx);
      srq_delete(&spl->srq, pdata->srq_idx);
      srq_print(&spl->srq);
      pdata->srq_idx = -1;
   }

   trunk_node_lock(spl, child);

   debug_assert(trunk_verify_node(spl, child));

   if (spl->cfg.use_stats) {
      if (parent->disk_addr == spl->root_ref.addr) {
         spl->stats[tid].root_flush_wait_time_ns +=
            platform_timestamp_elapsed(wait_start);
      } else {
         spl->stats[tid].flush_wait_time_ns[trunk_height(spl, parent)] +=
            platform_timestamp_elapsed(wait_start);
      }
      flush_start = platform_get_timestamp();
   }

   // flush the branch references into a new bundle in the child
   trunk_compact_bundle_req *req = TYPED_ZALLOC(spl->heap_id, req);
   trunk_bundle             *bundle =
      trunk_flush_into_bundle(spl, parent, child, pdata, req);

   trunk_tuples_in_bundle(spl,
                          child,
                          bundle,
                          req->input_pivot_tuple_count,
                          req->input_pivot_kv_byte_count);
   trunk_pivot_add_bundle_tuple_counts(spl,
                                       child,
                                       bundle,
                                       req->input_pivot_tuple_count,
                                       req->input_pivot_kv_byte_count);
   trunk_bundle_inc_pivot_rc(spl, child, bundle);
   req->type = is_space_rec ? TRUNK_COMPACTION_TYPE_FLUSH
                            : TRUNK_COMPACTION_TYPE_SPACE_REC;

   debug_assert(trunk_verify_node(spl, child));

   // split child if necessary
   if (trunk_needs_split(spl, child)) {
      if (trunk_is_leaf(spl, child)) {
         platform_free(spl->heap_id, req);
         uint16 child_idx = trunk_pdata_to_pivot_index(spl, parent, pdata);
         debug_assert(trunk_verify_node(spl, child));
         trunk_split_leaf(spl, parent, child, &ref_p, &ref_ch, child_idx);
         debug_assert(trunk_verify_node(spl, child));
         return STATUS_OK;
      } else {
         uint64 child_idx = trunk_pdata_to_pivot_index(spl, parent, pdata);
         trunk_split_index(spl, parent, child, child_idx);
      }
   }

   debug_assert(trunk_verify_node(spl, child));

   trunk_node_unlock(spl, child, &ref, __LINE__);

   // TODO(yizheng.jiao): Get rid of this copy
   memcpy(&pdata->ref, &ref, sizeof(ref));

   trunk_node_unclaim(spl, child);
   trunk_node_unget(spl, &child);

   trunk_default_log_if_enabled(
      spl,
      "compact_bundle enqueue: range %s-%s, height %u, bundle %u\n",
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->start_key)),
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->end_key)),
      req->height,
      req->bundle_no);
   rc =
      task_enqueue(spl->ts, TASK_TYPE_NORMAL, trunk_compact_bundle, req, FALSE);
   platform_assert_status_ok(rc);
   if (spl->cfg.use_stats) {
      flush_start = platform_timestamp_elapsed(flush_start);
      if (parent->disk_addr == spl->root_ref.addr) {
         spl->stats[tid].root_flush_time_ns += flush_start;
         if (flush_start > spl->stats[tid].root_flush_time_max_ns) {
            spl->stats[tid].root_flush_time_max_ns = flush_start;
         }
      } else {
         const uint32 h = trunk_height(spl, parent);
         spl->stats[tid].flush_time_ns[h] += flush_start;
         if (flush_start > spl->stats[tid].flush_time_max_ns[h]) {
            spl->stats[tid].flush_time_max_ns[h] = flush_start;
         }
      }
   }
   return rc;
}

/*
 * flush_fullest first flushes any pivots with too many live logical branches.
 * If the node is still full, it then flushes the pivot with the most tuples.
 */
platform_status
trunk_flush_fullest(trunk_handle *spl, page_handle *node)
{
   platform_status rc               = STATUS_OK;
   uint16          fullest_pivot_no = TRUNK_INVALID_PIVOT_NO;

   threadid tid;
   if (spl->cfg.use_stats) {
      tid = platform_get_tid();
   }

   /*
    * Note that trunk_num_children *must* be called at every loop iteration,
    * since flushes may cause splits, which in turn will change the number of
    * children
    */
   for (uint16 pivot_no = 0; pivot_no < trunk_num_children(spl, node);
        pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      // if a pivot has too many branches, just flush it here
      if (trunk_pivot_needs_flush(spl, node, pdata)) {
         rc = trunk_flush(spl, node, pdata, FALSE);
         if (!SUCCESS(rc)) {
            return rc;
         }
         if (spl->cfg.use_stats) {
            if (node->disk_addr == spl->root_ref.addr) {
               spl->stats[tid].root_count_flushes++;
            } else {
               spl->stats[tid].count_flushes[trunk_height(spl, node)]++;
            }
         }
      } else if (fullest_pivot_no == TRUNK_INVALID_PIVOT_NO
                 || (trunk_pivot_num_tuples(spl, node, pivot_no)
                     > trunk_pivot_num_tuples(spl, node, fullest_pivot_no)))
      {
         fullest_pivot_no = pivot_no;
      }
   }
   if (trunk_node_is_full(spl, node)) {
      if (spl->cfg.use_stats) {
         if (node->disk_addr == spl->root_ref.addr) {
            spl->stats[tid].root_full_flushes++;
         } else {
            spl->stats[tid].full_flushes[trunk_height(spl, node)]++;
         }
      }
      platform_assert(fullest_pivot_no != TRUNK_INVALID_PIVOT_NO);
      trunk_pivot_data *pdata =
         trunk_get_pivot_data(spl, node, fullest_pivot_no);
      return trunk_flush(spl, node, pdata, FALSE);
   }
   return rc;
}

void
save_pivots_to_compact_bundle_scratch(trunk_handle           *spl,     // IN
                                      page_handle            *node,    // IN
                                      compact_bundle_scratch *scratch) // IN/OUT
{
   uint32 num_pivot_keys = trunk_num_pivot_keys(spl, node);

   btree_config *cfg = &spl->cfg.btree_cfg;

   debug_assert(num_pivot_keys < ARRAY_SIZE(scratch->saved_pivot_keys));

   // Save all num_pivots regular pivots and the upper bound pivot
   for (uint32 i = 0; i < num_pivot_keys; i++) {
      memmove(&scratch->saved_pivot_keys[i].k,
              trunk_get_pivot(spl, node, i),
              cfg->data_cfg->key_size);
   }
}

/*
 * Branch iterator wrapper functions
 */

void
trunk_branch_iterator_init(trunk_handle   *spl,
                           btree_iterator *itor,
                           trunk_branch   *branch,
                           const char     *min_key,
                           const char     *max_key,
                           bool            do_prefetch,
                           bool            should_inc_ref)
{
   cache        *cc        = spl->cc;
   btree_config *btree_cfg = &spl->cfg.btree_cfg;
   uint64        root_addr = branch->root_addr;
   if (root_addr != 0 && should_inc_ref) {
      btree_inc_ref_range(cc,
                          btree_cfg,
                          root_addr,
                          trunk_key_slice(spl, min_key),
                          trunk_key_slice(spl, max_key));
   }
   page_reference *root_ref = (page_reference*)branch;
   btree_iterator_init(cc,
                       btree_cfg,
                       itor,
                       root_ref,
                       PAGE_TYPE_BRANCH,
                       trunk_key_slice(spl, min_key),
                       trunk_key_slice(spl, max_key),
                       do_prefetch,
                       0);
}

void
trunk_branch_iterator_deinit(trunk_handle   *spl,
                             btree_iterator *itor,
                             bool            should_dec_ref)
{
   if (itor->root_ref.addr == 0) {
      return;
   }
   cache        *cc        = spl->cc;
   btree_config *btree_cfg = &spl->cfg.btree_cfg;
   slice         min_key   = itor->min_key;
   slice         max_key   = itor->max_key;
   btree_iterator_deinit(itor);
   if (should_dec_ref) {
      btree_dec_ref_range(
         cc, btree_cfg, itor->root_ref.addr, min_key, max_key, PAGE_TYPE_BRANCH);
   }
}

/*
 *-----------------------------------------------------------------------------
 * btree skiperator
 *
 *       an iterator which can skip over tuples in branches which aren't live
 *-----------------------------------------------------------------------------
 */
static void
trunk_btree_skiperator_init(trunk_handle           *spl,
                            trunk_btree_skiperator *skip_itor,
                            page_handle            *node,
                            uint16                  branch_idx,
                            key_buffer pivots[static TRUNK_MAX_PIVOTS])
{
   ZERO_CONTENTS(skip_itor);
   skip_itor->super.ops = &trunk_btree_skiperator_ops;
   uint16 min_pivot_no  = 0;
   uint16 max_pivot_no  = trunk_num_children(spl, node);
   debug_assert(
      (max_pivot_no < TRUNK_MAX_PIVOTS), "max_pivot_no = %d", max_pivot_no);

   char *min_key     = pivots[min_pivot_no].k;
   char *max_key     = pivots[max_pivot_no].k;
   skip_itor->branch = *trunk_get_branch(spl, node, branch_idx);

   uint16 first_pivot      = 0;
   bool   iterator_started = FALSE;

   for (uint16 i = min_pivot_no; i < max_pivot_no + 1; i++) {
      bool branch_valid =
         i == max_pivot_no
            ? FALSE
            : trunk_branch_live_for_pivot(spl, node, branch_idx, i);
      if (branch_valid && !iterator_started) {
         first_pivot      = i;
         iterator_started = TRUE;
      }
      if (!branch_valid && iterator_started) {
         // create a new btree iterator
         char *pivot_min_key =
            first_pivot == min_pivot_no ? min_key : pivots[first_pivot].k;
         char *pivot_max_key        = i == max_pivot_no ? max_key : pivots[i].k;
         btree_iterator *btree_itor = &skip_itor->itor[skip_itor->end++];
         trunk_branch_iterator_init(spl,
                                    btree_itor,
                                    &skip_itor->branch,
                                    pivot_min_key,
                                    pivot_max_key,
                                    TRUE,
                                    TRUE);
         iterator_started = FALSE;
      }
   }

   bool at_end;
   if (skip_itor->curr != skip_itor->end) {
      iterator_at_end(&skip_itor->itor[skip_itor->curr].super, &at_end);
   } else {
      at_end = TRUE;
   }

   while (skip_itor->curr != skip_itor->end && at_end) {
      iterator_at_end(&skip_itor->itor[skip_itor->curr].super, &at_end);
      if (!at_end) {
         break;
      }
      skip_itor->curr++;
   }
}

void
trunk_btree_skiperator_get_curr(iterator *itor, slice *key, message *data)
{
   debug_assert(itor != NULL);
   trunk_btree_skiperator *skip_itor = (trunk_btree_skiperator *)itor;
   iterator_get_curr(&skip_itor->itor[skip_itor->curr].super, key, data);
}

platform_status
trunk_btree_skiperator_advance(iterator *itor)
{
   debug_assert(itor != NULL);
   trunk_btree_skiperator *skip_itor = (trunk_btree_skiperator *)itor;
   platform_status         rc =
      iterator_advance(&skip_itor->itor[skip_itor->curr].super);
   if (!SUCCESS(rc)) {
      return rc;
   }

   bool at_end;
   iterator_at_end(&skip_itor->itor[skip_itor->curr].super, &at_end);
   while (skip_itor->curr != skip_itor->end && at_end) {
      iterator_at_end(&skip_itor->itor[skip_itor->curr].super, &at_end);
      if (!at_end)
         break;
      skip_itor->curr++;
   }

   return STATUS_OK;
}

platform_status
trunk_btree_skiperator_at_end(iterator *itor, bool *at_end)
{
   trunk_btree_skiperator *skip_itor = (trunk_btree_skiperator *)itor;
   if (skip_itor->curr == skip_itor->end) {
      *at_end = TRUE;
      return STATUS_OK;
   }

   iterator_at_end(&skip_itor->itor[skip_itor->curr].super, at_end);
   return STATUS_OK;
}

void
trunk_btree_skiperator_print(iterator *itor)
{
   trunk_btree_skiperator *skip_itor = (trunk_btree_skiperator *)itor;
   platform_default_log("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
   platform_default_log("$$ skiperator: %p\n", skip_itor);
   platform_default_log("$$ curr: %lu\n", skip_itor->curr);
   iterator_print(&skip_itor->itor[skip_itor->curr].super);
}

void
trunk_btree_skiperator_deinit(trunk_handle           *spl,
                              trunk_btree_skiperator *skip_itor)
{
   for (uint64 i = 0; i < skip_itor->end; i++) {
      trunk_branch_iterator_deinit(spl, &skip_itor->itor[i], TRUE);
   }
}

/*
 *-----------------------------------------------------------------------------
 * Compaction Functions
 *-----------------------------------------------------------------------------
 */

static inline void
trunk_btree_pack_req_init(trunk_handle   *spl,
                          iterator       *itor,
                          btree_pack_req *req)
{
   btree_pack_req_init(req,
                       spl->cc,
                       &spl->cfg.btree_cfg,
                       itor,
                       spl->cfg.max_tuples_per_node,
                       spl->cfg.max_kv_bytes_per_node,
                       spl->cfg.filter_cfg.hash,
                       spl->cfg.filter_cfg.seed,
                       spl->heap_id);
}


/*
 * compact_bundle compacts a bundle of flushed branches into a single branch
 *
 * See "Interactions between Concurrent Processes"
 * (numbering here mirrors that section)
 *
 * Interacts with splitting in two ways:
 * 4. Internal node split occurs between job issue and this compact_bundle call:
 *    the bundle was split too, issue compact_bundle on the new siblings
 * 6. Leaf split occurs before this call or during compaction:
 *    the bundle will be compacted as part of the split, so this compaction is
 *    aborted if split occurred before this call or discarded if it occurred
 *    during compaction.
 *
 * Node splits are determined using generation numbers (in trunk_hdr)
 *   internal: generation number of left node is incremented on split
 *      -- given generation number g of a node, all the nodes it split
 *         into can be found by searching right until a node with
 *         generation number g is found
 *   leaf: generation numbers of all leaves affected by split are
 *         incremented
 *      -- can tell if a leaf has split by checking if generation number
 *         has changed
 *
 * Algorithm:
 * 1.  Acquire node read lock
 * 2.  Flush if node is full (acquires write lock)
 * 3.  If the node has split before this call (interaction 4), this
 *     bundle exists in the new split siblings, so issue compact_bundles
 *     for those nodes
 * 4.  Abort if node is a leaf and started splitting (interaction 6)
 * 5.  The bundle may have been completely flushed by step 2, if so abort
 * 6.  Build iterators
 * 7.  Release read lock
 * 8.  Perform compaction
 * 9.  Build filter
 * 10. Clean up
 * 11. Reacquire read lock
 * 12. For each newly split sibling replace bundle with new branch unless
 *        a. node if leaf which has split, in which case discard (interaction 6)
 *        b. node is internal and bundle has been flushed
 */
void
trunk_compact_bundle(void *arg, void *scratch_buf)
{
   platform_status                  rc;
   trunk_compact_bundle_req        *req          = arg;
   trunk_task_scratch              *task_scratch = scratch_buf;
   compact_bundle_scratch          *scratch = &task_scratch->compact_bundle;
   trunk_handle                    *spl     = req->spl;
   __attribute__((unused)) threadid tid;

   /*
    * 1. Acquire trunk update lock
    */
   trunk_update_lock(spl);

   page_handle *node_path[TRUNK_MAX_HEIGHT] = { NULL };
   int idx[TRUNK_MAX_HEIGHT] = { TRUNK_MAX_PIVOTS };
   page_reference ref_array[TRUNK_MAX_HEIGHT] = {0};
   int root_height;
   int node_height;

   trunk_default_log_if_enabled(spl, "%s pid=%ld: trunk_get_cow_path is called at %d\n", __func__, platform_get_tid(), __LINE__);
   trunk_get_cow_path(spl, &spl->root_ref, req->start_key, node_path, ref_array, idx, &root_height, req->height);

   page_reference new_root_ref = ref_array[root_height];
   page_reference node_ref = ref_array[req->height];
   page_handle *node = trunk_node_get(spl, &node_ref);
   node_height = req->height;

   /*
    * 2. Flush if node is full (acquires write lock)
    */
   bool flush_happened = FALSE;
   uint16 height = trunk_height(spl, node);
   if (height != 0 && trunk_node_is_full(spl, node)) {
      trunk_node_claim(spl, &node);
      trunk_node_lock(spl, node);
      rc = STATUS_OK;
      while (SUCCESS(rc) && trunk_node_is_full(spl, node)) {
         rc = trunk_flush_fullest(spl, node);
         flush_happened = TRUE;
      }
      trunk_node_pre_unlock(spl, node, &new_root_ref, &node_ref, 
                            node_height, root_height, ref_array, idx, __LINE__);

      trunk_node_unlock(spl, node, NULL, __LINE__);
      trunk_node_unclaim(spl, node);
   }

   // timers for stats if enabled
   uint64 compaction_start, pack_start;

   if (spl->cfg.use_stats) {
      tid              = platform_get_tid();
      compaction_start = platform_get_timestamp();
      spl->stats[tid].compactions[height]++;
   }

   /*
    * 3. If the node has split before this call (interaction 4), this
    *    bundle was copied to the new sibling[s], so issue compact_bundles for
    *    those nodes
    */
   if (trunk_compact_bundle_node_has_split(spl, req, node)) {
      if (height != 0) {
         trunk_compact_bundle_req *next_req =
            TYPED_MALLOC(spl->heap_id, next_req);
         memmove(next_req, req, sizeof(trunk_compact_bundle_req));
         trunk_key_copy(spl, next_req->start_key, trunk_max_key(spl, node));
         trunk_key_copy(spl, req->end_key, trunk_max_key(spl, node));

         trunk_default_log_if_enabled(
            spl,
            "compact_bundle split to: range %s-%s, height %u, bundle %u\n",
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->start_key)),
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->end_key)),
            next_req->height,
            next_req->bundle_no);
         rc = task_enqueue(
            spl->ts, TASK_TYPE_NORMAL, trunk_compact_bundle, next_req, FALSE);
         platform_assert_status_ok(rc);
      } else {
         /*
          * 4. Abort if node is a splitting leaf (interaction 6)
          */
         trunk_node_unget(spl, &node);
         trunk_default_log_if_enabled(
            spl,
            "compact_bundle abort leaf split: range %s-%s, height %u, bundle "
            "%u\n",
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->start_key)),
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->end_key)),
            req->height,
            req->bundle_no);
         platform_free(spl->heap_id, req);
         if (spl->cfg.use_stats) {
            spl->stats[tid].compactions_aborted_leaf_split[height]++;
            spl->stats[tid].compaction_time_wasted_ns[height] +=
               platform_timestamp_elapsed(compaction_start);
         }

         if (flush_happened == TRUE) {
            spl->root_ref = new_root_ref;
            platform_assert(0);
         }
         trunk_update_unlock(spl);
         trunk_default_log_if_enabled(spl, "%s pid=%lu: aborted due to split leaf at %d\n", __func__, platform_get_tid(), __LINE__);
         return;
      }
   }

   /*
    * 5. The bundle may have been completely flushed by 2., if so abort
    *       -- note this cannot happen in leaves (if the bundle isn't live, the
    *          generation number would change and it would be caught by step 4
    *          above).
    */
   if (!trunk_bundle_live(spl, node, req->bundle_no)) {
      debug_assert(height != 0);
      trunk_node_unget(spl, &node);
      trunk_default_log_if_enabled(
         spl,
         "compact_bundle abort flushed: range %s-%s, height %u, bundle %u\n",
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->start_key)),
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->end_key)),
         req->height,
         req->bundle_no);
      platform_free(spl->heap_id, req);
      if (spl->cfg.use_stats) {
         spl->stats[tid].compactions_aborted_flushed[height]++;
         spl->stats[tid].compaction_time_wasted_ns[height] +=
            platform_timestamp_elapsed(compaction_start);
      }
      spl->root_ref = new_root_ref;
      trunk_update_unlock(spl);
      return;
   }

   trunk_bundle *bundle       = trunk_get_bundle(spl, node, req->bundle_no);
   uint16 bundle_start_branch = trunk_bundle_start_branch(spl, node, bundle);
   uint16 bundle_end_branch   = trunk_bundle_end_branch(spl, node, bundle);
   uint16 num_branches        = trunk_bundle_branch_count(spl, node, bundle);

   /*
    * Update and delete messages need to be kept around until/unless they have
    * been applied all the way down to the very last branch tree.  Even once it
    * reaches the leaf, it isn't going to be applied to the last branch tree
    * unless the compaction includes the oldest B-tree in the leaf (the start
    * branch).
    */
   merge_behavior merge_mode;
   if (height == 0 && bundle_start_branch == trunk_start_branch(spl, node)) {
      merge_mode = MERGE_FULL;
   } else {
      merge_mode = MERGE_INTERMEDIATE;
   }

   platform_stream_handle stream;
   rc = trunk_open_log_stream_if_enabled(spl, &stream);
   platform_assert_status_ok(rc);
   trunk_log_stream_if_enabled(
      spl,
      &stream,
      "compact_bundle starting: addr %lu, range %s-%s, height %u, bundle %u\n",
      node->disk_addr,
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->start_key)),
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->end_key)),
      req->height,
      req->bundle_no);

   /*
    * 6. Build iterators
    */
   platform_assert(num_branches <= ARRAY_SIZE(scratch->skip_itor));
   trunk_btree_skiperator *skip_itor_arr = scratch->skip_itor;
   iterator              **itor_arr      = scratch->itor_arr;

   save_pivots_to_compact_bundle_scratch(spl, node, scratch);

   uint16 tree_offset = 0;
   for (uint16 branch_no = bundle_start_branch; branch_no != bundle_end_branch;
        branch_no        = trunk_add_branch_number(spl, branch_no, 1))
   {
      /*
       * We are iterating from oldest to newest branch
       */
      trunk_btree_skiperator_init(spl,
                                  &skip_itor_arr[tree_offset],
                                  node,
                                  branch_no,
                                  scratch->saved_pivot_keys);
      itor_arr[tree_offset] = &skip_itor_arr[tree_offset].super;
      tree_offset++;
   }
   trunk_log_node_if_enabled(&stream, spl, node);

   /*
    * 7. Release read lock
    */
   platform_assert(node_ref.addr == node->disk_addr);
   trunk_node_unget(spl, &node);

   /*
    * 8. Perform compaction
    */
   merge_iterator *merge_itor;
   rc = merge_iterator_create(spl->heap_id,
                              spl->cfg.data_cfg,
                              num_branches,
                              itor_arr,
                              merge_mode,
                              &merge_itor);
   platform_assert_status_ok(rc);
   btree_pack_req pack_req;
   trunk_btree_pack_req_init(spl, &merge_itor->super, &pack_req);
   req->fp_arr = pack_req.fingerprint_arr;
   if (spl->cfg.use_stats) {
      pack_start = platform_get_timestamp();
   }
   btree_pack(&pack_req);
   if (spl->cfg.use_stats) {
      spl->stats[tid].compaction_pack_time_ns[height] +=
         platform_timestamp_elapsed(pack_start);
   }

   trunk_branch new_branch;
   new_branch.root_addr = pack_req.root_ref.addr;
   memcpy(new_branch.sig, pack_req.root_ref.hash, HASH_SIZE);
   req->fp_arr = pack_req.fingerprint_arr;

   trunk_log_stream_if_enabled(
      spl, &stream, "output: %lu\n", new_branch.root_addr);
   if (spl->cfg.use_stats) {
      if (pack_req.num_tuples == 0) {
         spl->stats[tid].compactions_empty[height]++;
      }
      spl->stats[tid].compaction_tuples[height] += pack_req.num_tuples;
      if (pack_req.num_tuples > spl->stats[tid].compaction_max_tuples[height]) {
         spl->stats[tid].compaction_max_tuples[height] = pack_req.num_tuples;
      }
   }
   /*
    * 10. Clean up
    */
   rc = merge_iterator_destroy(spl->heap_id, &merge_itor);
   platform_assert_status_ok(rc);
   for (uint64 i = 0; i < num_branches; i++) {
      trunk_btree_skiperator_deinit(spl, &skip_itor_arr[i]);
   }

   trunk_default_log_if_enabled(spl, "%s pid=%ld: print new_root's signature after cleanup...\n", __func__, platform_get_tid());
   print_sig_if_enabled(spl, new_root_ref.hash, "root_root_hash");

   /*
    * 11. Reacquire read lock
    */
   // FIXME: For cow, node is a newly-created node
   // Need more think about how to handle this
   page_reference ref1 = node_ref;
   node = trunk_node_get(spl, &ref1);
   page_reference old_new_root_ref = new_root_ref;

   /*
    * 12. For each newly split sibling replace bundle with new branch
    */
   uint64 num_replacements = 0;
   bool   should_continue  = TRUE;
   while (should_continue) {
      platform_assert(node != NULL);
      trunk_node_claim(spl, &node);
      trunk_node_lock(spl, node);

      trunk_log_node_if_enabled(&stream, spl, node);

      /*
       * 12a. ...unless node is a leaf which has split, in which case discard
       *      (interaction 6)
       *
       *      For leaves, the split will cover the compaction and we do not
       *      need to look for the bundle in the split siblings, so simply
       *      exit.
       */
      if (trunk_is_leaf(spl, node)
          && trunk_compact_bundle_node_has_split(spl, req, node))
      {
         trunk_log_stream_if_enabled(
            spl,
            &stream,
            "compact_bundle discard split: range %s-%s, height %u, bundle %u\n",
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->start_key)),
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->end_key)),
            req->height,
            req->bundle_no);
         if (spl->cfg.use_stats) {
            spl->stats[tid].compactions_discarded_leaf_split[height]++;
            spl->stats[tid].compaction_time_wasted_ns[height] +=
               platform_timestamp_elapsed(compaction_start);
         }
         trunk_node_pre_unlock(spl, node, &new_root_ref, &node_ref, 
                               node_height, root_height,
                               ref_array, idx, __LINE__);
         trunk_node_unlock(spl, node, NULL, __LINE__);
         trunk_node_unclaim(spl, node);
         trunk_node_unget(spl, &node);

         if (pack_req.num_tuples != 0) {
            trunk_dec_ref(spl, &new_branch, FALSE);
         }
         platform_free(spl->heap_id, req->fp_arr);
         platform_free(spl->heap_id, req);
         // FIXME: release the node in node_path
         // Use the old_new_root_addr for new_root_addr
         new_root_ref = old_new_root_ref;
         goto out;
      }

      if (trunk_bundle_live(spl, node, req->bundle_no)) {
         if (pack_req.num_tuples != 0) {
            trunk_replace_bundle_branches(spl, node, &new_branch, req);
            num_replacements++;
            trunk_log_stream_if_enabled(spl,
                                        &stream,
                                        "inserted %lu into %lu\n",
                                        new_branch.root_addr,
                                        node->disk_addr);
         } else {
            trunk_replace_bundle_branches(spl, node, NULL, req);
            trunk_log_stream_if_enabled(
               spl, &stream, "compact_bundle empty %lu\n", node->disk_addr);
         }
      } else {
         /*
          * 12b. ...unless node is internal and bundle has been flushed
          */
         platform_assert(height != 0);
         trunk_log_stream_if_enabled(spl,
                                     &stream,
                                     "compact_bundle discarded flushed %lu\n",
                                     node->disk_addr);
      }
      trunk_log_node_if_enabled(&stream, spl, node);
      debug_assert(trunk_verify_node(spl, node));

      should_continue = trunk_compact_bundle_node_has_split(spl, req, node);
      if (!should_continue && num_replacements != 0 && pack_req.num_tuples != 0)
      {
         const char *max_key = trunk_max_key(spl, node);
         trunk_zap_branch_range(
            spl, &new_branch, max_key, NULL, PAGE_TYPE_BRANCH);
      }

      if (should_continue) {
         debug_assert(height != 0);
         trunk_key_copy(spl, req->start_key, trunk_max_key(spl, node));
      }

      trunk_node_pre_unlock(spl, node, &new_root_ref, &node_ref, 
                            node_height, root_height,
                            ref_array, idx, __LINE__);
      trunk_node_unlock(spl, node, NULL, __LINE__);
      trunk_node_unclaim(spl, node);
      trunk_node_unget(spl, &node);
      if (should_continue) {
         // FIXME(yizheng.jiao): This is to get the sibling node
         // to replace its bundle. Do we need to path-copying again here?
         // I guess so. We need to do path copying on top of the new tree
         old_new_root_ref = new_root_ref;
         memset(node_path, 0, sizeof(node_path));
         memset(idx, 0, sizeof(idx));
         memset(ref_array, 0, sizeof(ref_array));

         page_reference tmp_ref = new_root_ref;
         trunk_get_cow_path(spl, &tmp_ref, req->start_key, node_path, ref_array, idx, &root_height, req->height);

         new_root_ref = ref_array[root_height];
         node_ref = ref_array[req->height];
         node_height = req->height;
         node = trunk_node_get(spl, &node_ref);
      }
   }

   if (spl->cfg.use_stats) {
      if (req->type == TRUNK_COMPACTION_TYPE_SPACE_REC) {
         spl->stats[tid].space_rec_tuples_reclaimed[height] +=
            req->tuples_reclaimed;
      }
      if (req->type == TRUNK_COMPACTION_TYPE_SINGLE_LEAF_SPLIT) {
         spl->stats[tid].single_leaf_tuples += pack_req.num_tuples;
         if (pack_req.num_tuples > spl->stats[tid].single_leaf_max_tuples) {
            spl->stats[tid].single_leaf_max_tuples = pack_req.num_tuples;
         }
      }
   }
   if (num_replacements == 0) {
      if (pack_req.num_tuples != 0) {
         trunk_dec_ref(spl, &new_branch, FALSE);
      }
      if (spl->cfg.use_stats) {
         spl->stats[tid].compactions_discarded_flushed[height]++;
         spl->stats[tid].compaction_time_wasted_ns[height] +=
            platform_timestamp_elapsed(compaction_start);
      }
      platform_free(spl->heap_id, req);
   } else {
      if (spl->cfg.use_stats) {
         compaction_start = platform_timestamp_elapsed(compaction_start);
         spl->stats[tid].compaction_time_ns[height] += compaction_start;
         if (compaction_start > spl->stats[tid].compaction_time_max_ns[height])
         {
            spl->stats[tid].compaction_time_max_ns[height] = compaction_start;
         }
      }
      trunk_log_stream_if_enabled(
         spl,
         &stream,
         "build_filter enqueue: range %s-%s, height %u, bundle %u\n",
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->start_key)),
         key_string(trunk_data_config(spl),
                    slice_create(trunk_key_size(spl), req->end_key)),
         req->height,
         req->bundle_no);
      task_enqueue(
         spl->ts, TASK_TYPE_NORMAL, trunk_bundle_build_filters, req, TRUE);
   }
out:
   spl->root_ref = new_root_ref;
   trunk_update_unlock(spl);

   trunk_log_stream_if_enabled(spl, &stream, "\n");
   trunk_close_log_stream_if_enabled(spl, &stream);
}

bool
trunk_flush_node(trunk_handle *spl, page_reference *ref, void *arg)
{
   page_handle *node = trunk_node_get(spl, ref);
   trunk_node_claim(spl, &node);
   trunk_node_lock(spl, node);

   if (trunk_height(spl, node) != 0) {
      for (uint16 pivot_no = 0; pivot_no < trunk_num_children(spl, node);
           pivot_no++) {
         trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
         if (trunk_pivot_branch_count(spl, node, pdata) != 0) {
            platform_status rc = trunk_flush(spl, node, pdata, FALSE);
            platform_assert_status_ok(rc);
         }
      }
   }

   trunk_node_unlock(spl, node, ref, __LINE__);
   trunk_node_unclaim(spl, node);
   trunk_node_unget(spl, &node);

   task_perform_all(spl->ts);

   node = trunk_node_get(spl, ref);
   trunk_node_claim(spl, &node);
   trunk_node_lock(spl, node);

   if (trunk_height(spl, node) == 1) {
      for (uint16 pivot_no = 0; pivot_no < trunk_num_children(spl, node);
           pivot_no++) {
         trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
         page_reference   ch_ref = pdata->ref;
         page_handle      *leaf  = trunk_node_get(spl, &ch_ref);
         trunk_node_claim(spl, &leaf);
         trunk_node_lock(spl, leaf);
         trunk_split_leaf(spl, node, leaf, ref, &ch_ref, pivot_no);
      }
   }

   trunk_node_unlock(spl, node, ref, __LINE__);
   trunk_node_unclaim(spl, node);
   trunk_node_unget(spl, &node);

   task_perform_all(spl->ts);

   return TRUE;
}

void
trunk_force_flush(trunk_handle *spl)
{
   page_handle    *lock_page;
   uint64          generation;
   platform_status rc = memtable_maybe_rotate_and_get_insert_lock(
      spl->mt_ctxt, &generation, &lock_page);
   platform_assert_status_ok(rc);
   task_perform_all(spl->ts);
   memtable_unget_insert_lock(spl->mt_ctxt, lock_page);
   task_perform_all(spl->ts);
   trunk_for_each_node(spl, trunk_flush_node, NULL);
}


/*
 *-----------------------------------------------------------------------------
 * Splitting functions
 *-----------------------------------------------------------------------------
 */

static inline bool
trunk_needs_split(trunk_handle *spl, page_handle *node)
{
   if (trunk_is_leaf(spl, node)) {
      uint64 num_tuples = trunk_pivot_num_tuples(spl, node, 0);
      uint64 kv_bytes   = trunk_pivot_kv_bytes(spl, node, 0);
      return num_tuples > spl->cfg.max_tuples_per_node
             || kv_bytes > spl->cfg.max_kv_bytes_per_node
             || trunk_logical_branch_count(spl, node)
                   > spl->cfg.max_branches_per_node;
   }
   return trunk_num_children(spl, node) > spl->cfg.fanout;
}

int
trunk_split_index(trunk_handle *spl,
                  page_handle  *parent,
                  page_handle  *child,
                  uint64        pivot_no)
{
   platform_stream_handle stream;
   platform_status        rc = trunk_open_log_stream_if_enabled(spl, &stream);
   platform_assert_status_ok(rc);
   trunk_log_stream_if_enabled(spl,
                               &stream,
                               "split index %lu with parent %lu\n",
                               child->disk_addr,
                               parent->disk_addr);
   trunk_log_node_if_enabled(&stream, spl, parent);
   trunk_log_node_if_enabled(&stream, spl, child);
   page_handle *left_node           = child;
   uint16       target_num_children = trunk_num_children(spl, left_node) / 2;
   uint16       height              = trunk_height(spl, left_node);

   if (spl->cfg.use_stats)
      spl->stats[platform_get_tid()].index_splits++;

   // allocate right node and write lock it
   page_handle *right_node = trunk_alloc(spl, height);
   uint64       right_addr = right_node->disk_addr;

   // ALEX: Maybe worth figuring out the real page size
   memmove(right_node->data, left_node->data, trunk_page_size(&spl->cfg));
   char *right_start_pivot = trunk_get_pivot(spl, right_node, 0);
   char *left_split_pivot =
      trunk_get_pivot(spl, left_node, target_num_children);
   uint16 pivots_to_copy =
      trunk_num_pivot_keys(spl, left_node) - target_num_children;
   size_t bytes_to_copy = pivots_to_copy * trunk_pivot_size(spl);
   memmove(right_start_pivot, left_split_pivot, bytes_to_copy);

   uint16 start_filter = trunk_start_sb_filter(spl, left_node);
   uint16 end_filter   = trunk_end_sb_filter(spl, left_node);
   for (uint16 filter_no = start_filter; filter_no != end_filter;
        filter_no        = trunk_add_subbundle_filter_number(spl, filter_no, 1))
   {
      routing_filter *filter = trunk_get_sb_filter(spl, left_node, filter_no);
      trunk_inc_filter(spl, filter);
   }

   // set the headers appropriately
   trunk_hdr *left_hdr  = (trunk_hdr *)left_node->data;
   trunk_hdr *right_hdr = (trunk_hdr *)right_node->data;

   right_hdr->num_pivot_keys = left_hdr->num_pivot_keys - target_num_children;
   left_hdr->num_pivot_keys  = target_num_children + 1;

   left_hdr->generation++;
   trunk_reset_start_branch(spl, right_node);
   trunk_reset_start_branch(spl, left_node);

   // fix the entries in the reclamation queue
   uint16 right_num_children = trunk_num_children(spl, right_node);
   for (uint16 pivot_no = 0; pivot_no < right_num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, right_node, pivot_no);
      if (pdata->srq_idx != -1 && spl->cfg.reclaim_threshold != UINT64_MAX) {
         // platform_default_log("Deleting %12lu-%lu (index %lu) from SRQ\n",
         //       left_node->disk_addr, pdata->generation, pdata->srq_idx);
         srq_data data_to_reinsert = srq_delete(&spl->srq, pdata->srq_idx);
         data_to_reinsert.ref.addr     = right_addr;
         // platform_default_log("Reinserting %12lu-%lu into SRQ\n",
         //       right_addr, pdata->generation);
         pdata->srq_idx = srq_insert(&spl->srq, data_to_reinsert);
      }
   }

   // add right child to parent
   rc = trunk_add_pivot(spl, parent, right_node, pivot_no + 1);
   platform_assert(SUCCESS(rc));
   trunk_pivot_recount_num_tuples_and_kv_bytes(spl, parent, pivot_no);
   trunk_pivot_recount_num_tuples_and_kv_bytes(spl, parent, pivot_no + 1);

   trunk_log_stream_if_enabled(
      spl, &stream, "----------------------------------------\n");
   trunk_log_node_if_enabled(&stream, spl, parent);
   trunk_log_node_if_enabled(&stream, spl, left_node);
   trunk_log_node_if_enabled(&stream, spl, right_node);
   trunk_close_log_stream_if_enabled(spl, &stream);

   trunk_node_unlock(spl, right_node, NULL, __LINE__);
   trunk_node_unclaim(spl, right_node);
   trunk_node_unget(spl, &right_node);

   return 0;
}

/*
 * Estimate the number of unique keys in the pivot
 */
__attribute__((unused)) static inline uint64
trunk_pivot_estimate_unique_keys(trunk_handle     *spl,
                                 page_handle      *node,
                                 trunk_pivot_data *pdata)
{
   routing_filter filter[MAX_FILTERS];
   uint64         filter_no = 0;
   filter[filter_no++]      = pdata->filter;

   uint64 num_sb_fp     = 0;
   uint64 num_sb_unique = 0;
   for (uint16 sb_filter_no = trunk_start_sb_filter(spl, node);
        sb_filter_no != trunk_end_sb_filter(spl, node);
        sb_filter_no = trunk_add_subbundle_filter_number(spl, sb_filter_no, 1))
   {
      routing_filter *sb_filter = trunk_get_sb_filter(spl, node, sb_filter_no);
      num_sb_fp += sb_filter->num_fingerprints;
      num_sb_unique += sb_filter->num_unique;
      filter[filter_no++] = *sb_filter;
   }

   uint32 num_unique = routing_filter_estimate_unique_fp(
      spl->cc, &spl->cfg.filter_cfg, spl->heap_id, filter, filter_no);

   num_unique = routing_filter_estimate_unique_keys_from_count(
      &spl->cfg.filter_cfg, num_unique);

   uint64 num_leaf_sb_fp = 0;
   for (uint16 bundle_no = pdata->start_bundle;
        bundle_no != trunk_end_bundle(spl, node);
        bundle_no = trunk_add_bundle_number(spl, bundle_no, 1))
   {
      trunk_bundle *bundle = trunk_get_bundle(spl, node, bundle_no);
      num_leaf_sb_fp += bundle->num_tuples;
   }
   uint64 est_num_leaf_sb_unique = num_sb_unique * num_leaf_sb_fp / num_sb_fp;
   uint64 est_num_non_leaf_sb_unique = num_sb_fp - est_num_leaf_sb_unique;

   // platform_error_log("num_unique %u sb_fp %lu sb_unique %lu num_leaf_sb_fp
   // %lu\n",
   //       num_unique, num_sb_fp, num_sb_unique, num_leaf_sb_fp);
   // platform_error_log("est_leaf_sb_fp %lu est_non_leaf_sb_unique %lu\n",
   //       est_num_leaf_sb_unique, est_num_non_leaf_sb_unique);
   uint64 est_leaf_unique = num_unique - est_num_non_leaf_sb_unique;
   return est_leaf_unique;
}

/*
 *----------------------------------------------------------------------
 * trunk_single_leaf_threshold --
 *
 *      Returns an upper bound for the number of estimated tuples for which a
 *      leaf split can output a single leaf.
 *----------------------------------------------------------------------
 */
static inline uint64
trunk_single_leaf_threshold(trunk_handle *spl)
{
   return TRUNK_SINGLE_LEAF_THRESHOLD_PCT * spl->cfg.max_tuples_per_node / 100;
}

/*
 *----------------------------------------------------------------------
 * split_leaf splits a trunk leaf logically. It determines pivots to split
 * on, uses them to split the leaf and adds them to its parent. It then
 * issues compact_bundle jobs on each leaf to perform the actual compaction.
 *
 * Must be called with a lock on both the parent and child
 * Returns with lock on parent and releases child and all new leaves
 * The algorithm tries to downgrade to a claim as much as possible throughout
 *
 * The main loop starts with the current leaf (initially the original leaf),
 * then uses the rough iterator to find the next pivot. It copies the current
 * leaf to a new leaf, and sets the end key of the current leaf and start key
 * of the new leaf to the pivot. It then issues a compact_bundle job on the
 * current leaf and releases it. Finally, the loop continues with the new
 * leaf as current.
 *
 * Algorithm:
 * 1. Create a rough merge iterator on all the branches
 * 2. Use rough merge iterator to determine pivots for new leaves
 * 3. Clear old bundles from leaf and put all branches in a new bundle
 * 4. Create new leaf, adjust min/max keys and other metadata
 * 5. Add new leaf to parent
 * 6. Issue compact_bundle for last_leaf and release
 * 7. Repeat 4-6 on new leaf
 * 8. Clean up
 *----------------------------------------------------------------------
 */
void
trunk_split_leaf(trunk_handle *spl,
                 page_handle  *parent,
                 page_handle  *leaf,
                 page_reference *ref_parent,
                 page_reference *ref_leaf,
                 uint16        child_idx)
{
   const threadid      tid = platform_get_tid();
   trunk_task_scratch *task_scratch =
      task_system_get_thread_scratch(spl->ts, tid);
   split_leaf_scratch *scratch      = &task_scratch->split_leaf;
   uint64              num_branches = trunk_branch_count(spl, leaf);
   uint64              start_branch = trunk_start_branch(spl, leaf);


   debug_assert(trunk_verify_node(spl, parent));
   debug_assert(trunk_verify_node(spl, leaf));

   trunk_node_unlock(spl, parent, ref_parent, __LINE__);
   trunk_node_unlock(spl, leaf, ref_leaf, __LINE__);

   platform_stream_handle stream;
   platform_status        rc = trunk_open_log_stream_if_enabled(spl, &stream);
   platform_assert_status_ok(rc);
   trunk_log_stream_if_enabled(
      spl, &stream, "split_leaf addr %lu\n", leaf->disk_addr);

   uint64 split_start;
   if (spl->cfg.use_stats) {
      spl->stats[tid].leaf_splits++;
      split_start = platform_get_timestamp();
   }

   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, leaf, 0);
   uint64            estimated_unique_keys =
      trunk_pivot_estimate_unique_keys(spl, leaf, pdata);
   uint64 num_tuples = trunk_pivot_num_tuples(spl, leaf, 0);
   if (estimated_unique_keys > num_tuples * 19 / 20) {
      estimated_unique_keys = num_tuples;
   }
   trunk_compaction_type comp_type = TRUNK_COMPACTION_TYPE_LEAF_SPLIT;
   uint64                kv_bytes  = trunk_pivot_kv_bytes(spl, leaf, 0);
   uint64                estimated_unique_kv_bytes =
      estimated_unique_keys * kv_bytes / num_tuples;
   uint64 target_num_leaves =
      estimated_unique_kv_bytes / spl->cfg.target_leaf_kv_bytes;
   if (target_num_leaves <= 1) {
      if (estimated_unique_keys > trunk_single_leaf_threshold(spl)) {
         target_num_leaves = 2;
      } else {
         target_num_leaves = 1;
         comp_type         = TRUNK_COMPACTION_TYPE_SINGLE_LEAF_SPLIT;
         if (spl->cfg.use_stats) {
            spl->stats[tid].single_leaf_splits++;
         }
      }
   }
   uint64 target_leaf_kv_bytes = kv_bytes / target_num_leaves;
   uint16 num_leaves;

   // copy pivot (in parent) of leaf
   memmove(scratch->pivot[0], trunk_min_key(spl, leaf), trunk_key_size(spl));

   uint64 leaf0_num_tuples = estimated_unique_keys;
   uint64 leaf0_kv_bytes   = estimated_unique_kv_bytes;

   //atrunk_branch branches[TRUNK_RANGE_ITOR_MAX_BRANCHES];

   if (target_num_leaves != 1) {
      /*
       * 1. Create a rough merge iterator on all the branches
       *
       *    A rough merge iterator is a merge iterator on height 1
       * btree iterators. It uses height 1 pivots as a proxy for
       * a count of tuples.
       *
       *    This count is an estimate with multiple sources of error:
       *       -- Last leaves in each btree are not counted
       *          (there is no upper bound pivot)
       *       -- A selected pivot from a branch may be between pivots for other
       *          branches
       *       -- min_key may be between pivots
       *       -- updates and deletes may be resolved resulting in fewer output
       *          tuples
       */
      platform_assert(num_branches <= ARRAY_SIZE(scratch->btree_itor));
      btree_iterator *rough_btree_itor = scratch->btree_itor;
      iterator      **rough_itor       = scratch->rough_itor;
      char            min_key[MAX_KEY_SIZE];
      char            max_key[MAX_KEY_SIZE];
      memmove(min_key, trunk_get_pivot(spl, leaf, 0), trunk_key_size(spl));
      memmove(max_key, trunk_get_pivot(spl, leaf, 1), trunk_key_size(spl));

      for (uint64 branch_offset = 0; branch_offset < num_branches;
           branch_offset++) {
         uint64 branch_no =
            trunk_add_branch_number(spl, start_branch, branch_offset);
         debug_assert(branch_no != trunk_end_branch(spl, leaf));
         trunk_branch *branch = trunk_get_branch(spl, leaf, branch_no);
         //branches[branch_offset] = *branch;
         // Copy addr and signature
         page_reference root_ref = { .addr = branch->root_addr };
         memcpy(root_ref.hash, branch->sig, HASH_SIZE);
         btree_iterator_init(spl->cc,
                             &spl->cfg.btree_cfg,
                             &rough_btree_itor[branch_offset],
                             &root_ref,
                             PAGE_TYPE_BRANCH,
                             trunk_key_slice(spl, min_key),
                             trunk_key_slice(spl, max_key),
                             TRUE,
                             1);
         rough_itor[branch_offset] = &rough_btree_itor[branch_offset].super;
      }

      merge_iterator *rough_merge_itor;
      platform_status rc = merge_iterator_create(spl->heap_id,
                                                 spl->cfg.data_cfg,
                                                 num_branches,
                                                 rough_itor,
                                                 MERGE_RAW,
                                                 &rough_merge_itor);
      platform_assert_status_ok(rc);

      /*
       * 2. Use rough merge iterator to determine pivots for new leaves
       */
      bool at_end;
      rc = iterator_at_end(&rough_merge_itor->super, &at_end);
      platform_assert_status_ok(rc);

      uint64 rough_count_kv_bytes;
      uint64 rough_count_num_tuples;
      for (num_leaves = 0; !at_end; num_leaves++) {
         rough_count_num_tuples = 0;
         rough_count_kv_bytes   = 0;
         while (!at_end
                && (rough_count_kv_bytes < target_leaf_kv_bytes
                    || num_leaves == target_num_leaves - 1))
         {
            slice   curr_key;
            message pivot_data_message;
            iterator_get_curr(
               &rough_merge_itor->super, &curr_key, &pivot_data_message);

            const btree_pivot_data *pivot_data =
               message_data(pivot_data_message);
            rough_count_num_tuples += pivot_data->num_kvs_in_subtree;
            rough_count_kv_bytes += pivot_data->key_bytes_in_subtree
                                    + pivot_data->message_bytes_in_subtree;
            iterator_advance(&rough_merge_itor->super);
            iterator_at_end(&rough_merge_itor->super, &at_end);
         }

         if (num_leaves == 0) {
            leaf0_num_tuples = rough_count_num_tuples;
            leaf0_kv_bytes   = rough_count_kv_bytes;
         }

         if (!at_end) {
            slice   curr_key;
            message dummy_data;
            iterator_get_curr(&rough_merge_itor->super, &curr_key, &dummy_data);
            debug_assert(slice_length(curr_key) == trunk_key_size(spl));
            // copy new pivot (in parent) of new leaf
            memmove(scratch->pivot[num_leaves + 1],
                    slice_data(curr_key),
                    trunk_key_size(spl));
         }
      }

      // clean up the iterators
      rc = merge_iterator_destroy(spl->heap_id, &rough_merge_itor);
      platform_assert_status_ok(rc);
      for (uint64 i = 0; i < num_branches; i++) {
         btree_iterator_deinit(&rough_btree_itor[i]);
      }
   } else {
      num_leaves = 1;
   }

   // copy max key of last new leaf (max key of leaf)
   memmove(scratch->pivot[num_leaves],
           trunk_max_key(spl, leaf),
           trunk_key_size(spl));

   platform_assert(num_leaves + trunk_num_pivot_keys(spl, parent)
                   <= spl->cfg.max_pivot_keys);

   /*
    * 3. Clear old bundles from leaf and put all branches in a new bundle
    */
   trunk_node_lock(spl, parent);
   trunk_log_node_if_enabled(&stream, spl, parent);
   trunk_node_lock(spl, leaf);
   trunk_log_node_if_enabled(&stream, spl, leaf);

   uint16 bundle_no = trunk_leaf_rebundle_all_branches(
      spl, leaf, leaf0_num_tuples, leaf0_kv_bytes, FALSE);
   trunk_inc_generation(spl, leaf);

   for (uint16 leaf_no = 0; leaf_no < num_leaves; leaf_no++) {
      /*
       * 4. Create new leaf, adjust min/max keys and other metadata
       *
       *    Have lock on leaf (original leaf or last iteration) and parent
       *    This loop :
       *    1. allocates new_leaf
       *    2. copies leaf to new_leaf
       *    3. sets min_key and max_key on new_leaf
       *    4. sets next_addr on leaf
       *    5. incs all branches ref counts
       *    6. sets new_leaf tuple_count
       *    7. adds new_leaf to parent
       */
      page_handle *new_leaf;
      if (leaf_no != 0) {
         // allocate a new leaf
         new_leaf = trunk_alloc(spl, 0);

         // copy leaf to new leaf
         memmove(new_leaf->data, leaf->data, trunk_page_size(&spl->cfg));
      } else {
         // just going to edit the min/max keys, etc. of original leaf
         new_leaf = leaf;
      }

      // adjust min key
      memmove(trunk_get_pivot(spl, new_leaf, 0),
              scratch->pivot[leaf_no],
              trunk_key_size(spl));
      // adjust max key
      memmove(trunk_get_pivot(spl, new_leaf, 1),
              scratch->pivot[leaf_no + 1],
              trunk_key_size(spl));

      // set new_leaf tuple_count
      trunk_bundle *bundle = trunk_get_bundle(spl, new_leaf, bundle_no);
      uint64        new_leaf_num_tuples[TRUNK_MAX_PIVOTS];
      uint64        new_leaf_kv_bytes[TRUNK_MAX_PIVOTS];
      trunk_tuples_in_bundle(
         spl, new_leaf, bundle, new_leaf_num_tuples, new_leaf_kv_bytes);
      trunk_pivot_clear_counts(spl, new_leaf, 0);
      trunk_pivot_set_bundle_counts(
         spl, new_leaf, 0, new_leaf_num_tuples[0], new_leaf_kv_bytes[0]);

      if (leaf_no != 0) {
         // inc the refs of all the branches
         for (uint16 branch_no = trunk_start_branch(spl, new_leaf);
              branch_no != trunk_end_branch(spl, new_leaf);
              branch_no = trunk_add_branch_number(spl, branch_no, 1))
         {
            trunk_branch *branch  = trunk_get_branch(spl, new_leaf, branch_no);
            const char   *min_key = trunk_min_key(spl, new_leaf);
            trunk_inc_intersection(spl, branch, min_key, FALSE);
         }

         // inc the refs of all the filters
         trunk_bundle *bundle = trunk_get_bundle(spl, new_leaf, bundle_no);
         uint16 start_filter = trunk_bundle_start_filter(spl, new_leaf, bundle);
         uint16 end_filter   = trunk_bundle_end_filter(spl, new_leaf, bundle);
         for (uint16 filter_no = start_filter; filter_no != end_filter;
              filter_no = trunk_add_subbundle_filter_number(spl, filter_no, 1))
         {
            routing_filter *filter =
               trunk_get_sb_filter(spl, new_leaf, filter_no);
            trunk_inc_filter(spl, filter);
         }

         /*
          * 5. Add new leaf to parent
          */
         platform_status rc =
            trunk_add_pivot(spl, parent, new_leaf, child_idx + leaf_no);
         platform_assert(SUCCESS(rc));

         /*
          * 6. Issue compact_bundle for leaf and release
          */
         trunk_compact_bundle_req *req = TYPED_ZALLOC(spl->heap_id, req);
         req->spl                      = spl;
         req->type                     = comp_type;
         req->bundle_no                = bundle_no;
         req->max_pivot_generation     = trunk_pivot_generation(spl, leaf);
         req->pivot_generation[0]      = trunk_pivot_generation(spl, leaf) - 1;
         req->input_pivot_tuple_count[0] = trunk_pivot_num_tuples(spl, leaf, 0);
         req->input_pivot_kv_byte_count[0] = trunk_pivot_kv_bytes(spl, leaf, 0);
         trunk_key_copy(spl, req->start_key, trunk_min_key(spl, leaf));
         trunk_key_copy(spl, req->end_key, trunk_max_key(spl, leaf));

         trunk_default_log_if_enabled(
            spl,
            "compact_bundle enqueue: range %s-%s, height %u, bundle %u\n",
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->start_key)),
            key_string(trunk_data_config(spl),
                       slice_create(trunk_key_size(spl), req->end_key)),
            req->height,
            req->bundle_no);
         rc = task_enqueue(
            spl->ts, TASK_TYPE_NORMAL, trunk_compact_bundle, req, FALSE);
         platform_assert(SUCCESS(rc));

         trunk_log_node_if_enabled(&stream, spl, leaf);

         debug_assert(trunk_verify_node(spl, leaf));
         trunk_set_pivot_data_ref(spl, parent, leaf_no + child_idx - 1, leaf);
         trunk_node_unlock(spl, leaf, NULL, __LINE__);
         trunk_node_unclaim(spl, leaf);
         trunk_node_unget(spl, &leaf);
      }

      leaf = new_leaf;
   }

   // set next_addr of leaf (from last iteration)
   trunk_compact_bundle_req *req = TYPED_ZALLOC(spl->heap_id, req);
   req->spl                      = spl;
   // req->height already 0
   req->bundle_no                    = bundle_no;
   req->max_pivot_generation         = trunk_pivot_generation(spl, leaf);
   req->pivot_generation[0]          = trunk_pivot_generation(spl, leaf) - 1;
   req->input_pivot_tuple_count[0]   = trunk_pivot_num_tuples(spl, leaf, 0);
   req->input_pivot_kv_byte_count[0] = trunk_pivot_kv_bytes(spl, leaf, 0);
   req->type                         = comp_type;
   trunk_key_copy(spl, req->start_key, trunk_min_key(spl, leaf));
   trunk_key_copy(spl, req->end_key, trunk_max_key(spl, leaf));

   // issue compact_bundle for leaf and release
   trunk_default_log_if_enabled(
      spl,
      "compact_bundle enqueue: range %s-%s, height %u, bundle %u\n",
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->start_key)),
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->end_key)),
      req->height,
      req->bundle_no);
   rc =
      task_enqueue(spl->ts, TASK_TYPE_NORMAL, trunk_compact_bundle, req, FALSE);
   platform_assert(SUCCESS(rc));

   trunk_log_node_if_enabled(&stream, spl, parent);
   trunk_log_node_if_enabled(&stream, spl, leaf);

   debug_assert(trunk_verify_node(spl, leaf));
   trunk_set_pivot_data_ref(spl, parent, num_leaves + child_idx - 1, leaf);
   trunk_node_unlock(spl, leaf, NULL, __LINE__);
   trunk_node_unclaim(spl, leaf);
   trunk_node_unget(spl, &leaf);

   /*
    * 8. Clean up
    */
   trunk_close_log_stream_if_enabled(spl, &stream);

   if (spl->cfg.use_stats) {
      // Doesn't include the original leaf
      spl->stats[tid].leaf_splits_leaves_created += num_leaves - 1;
      uint64 split_time = platform_timestamp_elapsed(split_start);
      spl->stats[tid].leaf_split_time_ns += split_time;
      platform_timestamp_elapsed(split_start);
      if (split_time > spl->stats[tid].leaf_split_max_time_ns) {
         spl->stats[tid].leaf_split_max_time_ns = split_time;
      }
   }
}


int
trunk_split_root(trunk_handle *spl, page_handle *root)
{
   trunk_hdr *root_hdr = (trunk_hdr *)root->data;

   // allocate a new child node
   page_handle *child     = trunk_alloc(spl, root_hdr->height);
   trunk_hdr   *child_hdr = (trunk_hdr *)child->data;

   // copy root to child, fix up root, then split
   memmove(child_hdr, root_hdr, trunk_page_size(&spl->cfg));
   // num_pivot_keys is changed by add_pivot_new_root below
   root_hdr->height++;
   // leave generation and pivot_generation
   root_hdr->start_branch      = 0;
   root_hdr->start_frac_branch = 0;
   root_hdr->end_branch        = 0;
   root_hdr->start_bundle      = 0;
   root_hdr->end_bundle        = 0;
   root_hdr->start_subbundle   = 0;
   root_hdr->end_subbundle     = 0;
   root_hdr->start_sb_filter   = 0;
   root_hdr->end_sb_filter     = 0;

   trunk_add_pivot_new_root(spl, root, child);

   trunk_split_index(spl, root, child, 0);

   trunk_set_ref_new_root(spl, root, child);

   trunk_node_unlock(spl, child, NULL, __LINE__);
   trunk_node_unclaim(spl, child);
   trunk_node_unget(spl, &child);

   return 0;
}


/*
 *-----------------------------------------------------------------------------
 * Range functions and iterators
 *
 *      trunk_node_iterator
 *      trunk_iterator
 *-----------------------------------------------------------------------------
 */
void
trunk_range_iterator_get_curr(iterator *itor, slice *key, message *data);
platform_status
trunk_range_iterator_at_end(iterator *itor, bool *at_end);
platform_status
trunk_range_iterator_advance(iterator *itor);
void
trunk_range_iterator_deinit(trunk_range_iterator *range_itor);

const static iterator_ops trunk_range_iterator_ops = {
   .get_curr = trunk_range_iterator_get_curr,
   .at_end   = trunk_range_iterator_at_end,
   .advance  = trunk_range_iterator_advance,
};

platform_status
trunk_range_iterator_init(trunk_handle         *spl,
                          trunk_range_iterator *range_itor,
                          const char           *min_key,
                          const char           *max_key,
                          uint64                num_tuples)
{
   range_itor->spl          = spl;
   range_itor->super.ops    = &trunk_range_iterator_ops;
   range_itor->num_branches = 0;
   range_itor->num_tuples   = num_tuples;
   if (min_key == NULL) {
      min_key = spl->cfg.data_cfg->min_key;
   }
   memmove(range_itor->min_key, min_key, trunk_key_size(spl));
   if (max_key) {
      range_itor->has_max_key = TRUE;
      memmove(range_itor->max_key, max_key, trunk_key_size(spl));
   } else {
      range_itor->has_max_key = FALSE;
      memset(range_itor->max_key, 0, trunk_key_size(spl));
   }

   const char *hard_max_key = max_key ? max_key : spl->cfg.data_cfg->max_key;
   if (trunk_key_compare(spl, min_key, hard_max_key) == 0) {
      range_itor->at_end = TRUE;
      return STATUS_OK;
   }

   if (max_key && trunk_key_compare(spl, max_key, min_key) <= 0) {
      range_itor->at_end = TRUE;
      return STATUS_OK;
   }

   range_itor->at_end = FALSE;

   ZERO_ARRAY(range_itor->compacted);

   // grab the lookup lock
   page_handle *mt_lookup_lock_page = memtable_get_lookup_lock(spl->mt_ctxt);

   // memtables
   ZERO_ARRAY(range_itor->branch);
   // Note this iteration is in descending generation order
   range_itor->memtable_start_gen = memtable_generation(spl->mt_ctxt);
   range_itor->memtable_end_gen   = memtable_generation_retired(spl->mt_ctxt);
   range_itor->num_memtable_branches =
      range_itor->memtable_start_gen - range_itor->memtable_end_gen;
   for (uint64 mt_gen = range_itor->memtable_start_gen;
        mt_gen != range_itor->memtable_end_gen;
        mt_gen--)
   {
      platform_assert(
         (range_itor->num_branches < TRUNK_RANGE_ITOR_MAX_BRANCHES),
         "range_itor->num_branches=%lu should be < "
         " TRUNK_RANGE_ITOR_MAX_BRANCHES (%d).",
         range_itor->num_branches,
         TRUNK_RANGE_ITOR_MAX_BRANCHES);
      debug_assert(range_itor->num_branches < ARRAY_SIZE(range_itor->branch));

      bool   compacted;
      page_reference ref;
      uint64 root_addr =
         trunk_memtable_root_addr_for_lookup(spl, mt_gen, &compacted, ref.hash);
      ref.addr = root_addr;
      range_itor->compacted[range_itor->num_branches] = compacted;
      if (compacted) {
         // We need to pass page reference for compacted memtable
         platform_assert(FALSE);
         btree_block_dec_ref(spl->cc, &spl->cfg.btree_cfg, root_addr);
      } else {
         trunk_memtable_inc_ref(spl, mt_gen);
      }

      range_itor->branch[range_itor->num_branches].root_addr = root_addr;

      range_itor->num_branches++;
   }

   page_handle *node = trunk_node_get(spl, &spl->root_ref);
   memtable_unget_lookup_lock(spl->mt_ctxt, mt_lookup_lock_page);

   // index btrees
   uint16 height = trunk_height(spl, node);
   for (uint16 h = height; h > 0; h--) {
      uint16 pivot_no =
         trunk_find_pivot(spl, node, range_itor->min_key, less_than_or_equal);
      debug_assert(pivot_no < trunk_num_children(spl, node));
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);

      for (uint16 branch_offset = 0;
           branch_offset != trunk_pivot_branch_count(spl, node, pdata);
           branch_offset++)
      {
         platform_assert(
            (range_itor->num_branches < TRUNK_RANGE_ITOR_MAX_BRANCHES),
            "range_itor->num_branches=%lu should be < "
            " TRUNK_RANGE_ITOR_MAX_BRANCHES (%d).",
            range_itor->num_branches,
            TRUNK_RANGE_ITOR_MAX_BRANCHES);

         debug_assert(range_itor->num_branches
                      < ARRAY_SIZE(range_itor->branch));
         uint16 branch_no = trunk_subtract_branch_number(
            spl, trunk_end_branch(spl, node), branch_offset + 1);
         range_itor->branch[range_itor->num_branches] =
            *trunk_get_branch(spl, node, branch_no);
         range_itor->compacted[range_itor->num_branches] = TRUE;
         uint64 root_addr =
            range_itor->branch[range_itor->num_branches].root_addr;
         btree_block_dec_ref(spl->cc, &spl->cfg.btree_cfg, root_addr);
         range_itor->num_branches++;
      }

      page_reference ref = pdata->ref;
      page_handle *child = trunk_node_get(spl, &ref);
      trunk_node_unget(spl, &node);
      node = child;
   }

   // leaf btrees
   for (uint16 branch_offset = 0;
        branch_offset != trunk_branch_count(spl, node);
        branch_offset++)
   {
      uint16 branch_no = trunk_subtract_branch_number(
         spl, trunk_end_branch(spl, node), branch_offset + 1);
      range_itor->branch[range_itor->num_branches] =
         *trunk_get_branch(spl, node, branch_no);
      uint64 root_addr = range_itor->branch[range_itor->num_branches].root_addr;
      btree_block_dec_ref(spl->cc, &spl->cfg.btree_cfg, root_addr);
      range_itor->compacted[range_itor->num_branches] = TRUE;
      range_itor->num_branches++;
   }

   // have a leaf, use to get rebuild key
   const char *rebuild_key =
      !range_itor->has_max_key
            || trunk_key_compare(spl, trunk_max_key(spl, node), max_key) < 0
         ? trunk_max_key(spl, node)
         : max_key;
   memmove(range_itor->rebuild_key, rebuild_key, trunk_key_size(spl));
   if (max_key && trunk_key_compare(spl, max_key, rebuild_key) < 0) {
      memcpy(range_itor->local_max_key, max_key, trunk_key_size(spl));
   } else {
      memcpy(range_itor->local_max_key, rebuild_key, trunk_key_size(spl));
   }

   trunk_node_unget(spl, &node);

   for (uint64 i = 0; i < range_itor->num_branches; i++) {
      uint64          branch_no  = range_itor->num_branches - i - 1;
      btree_iterator *btree_itor = &range_itor->btree_itor[branch_no];
      trunk_branch   *branch     = &range_itor->branch[branch_no];
      if (range_itor->compacted[branch_no]) {
         bool do_prefetch =
            range_itor->compacted[branch_no] && num_tuples > TRUNK_PREFETCH_MIN
               ? TRUE
               : FALSE;
         trunk_branch_iterator_init(spl,
                                    btree_itor,
                                    branch,
                                    range_itor->min_key,
                                    range_itor->local_max_key,
                                    do_prefetch,
                                    FALSE);
      } else {
         uint64 mt_root_addr = branch->root_addr;
         bool   is_live      = branch_no == 0;
         trunk_memtable_iterator_init(spl,
                                      btree_itor,
                                      mt_root_addr,
                                      range_itor->min_key,
                                      range_itor->local_max_key,
                                      is_live,
                                      FALSE);
      }
      range_itor->itor[i] = &btree_itor->super;
   }

   platform_status rc = merge_iterator_create(spl->heap_id,
                                              spl->cfg.data_cfg,
                                              range_itor->num_branches,
                                              range_itor->itor,
                                              MERGE_FULL,
                                              &range_itor->merge_itor);
   if (!SUCCESS(rc)) {
      return rc;
   }

   bool at_end;
   iterator_at_end(&range_itor->merge_itor->super, &at_end);

   /*
    * if the merge itor is already exhausted, and there are more keys in the
    * db/range, move to next leaf
    */
   if (at_end) {
      trunk_range_iterator_deinit(range_itor);
      if (1
          && trunk_key_compare(
                spl, range_itor->local_max_key, spl->cfg.data_cfg->max_key)
                != 0
          && (0 || !range_itor->has_max_key
              || trunk_key_compare(
                    spl, range_itor->local_max_key, range_itor->max_key)
                    < 0))
      {
         rc = trunk_range_iterator_init(spl,
                                        range_itor,
                                        range_itor->rebuild_key,
                                        max_key,
                                        range_itor->num_tuples);
         if (!SUCCESS(rc)) {
            return rc;
         }
         iterator_at_end(&range_itor->merge_itor->super, &at_end);
      }
   }

   range_itor->at_end = at_end;

   return rc;
}

void
trunk_range_iterator_get_curr(iterator *itor, slice *key, message *data)
{
   debug_assert(itor != NULL);
   trunk_range_iterator *range_itor = (trunk_range_iterator *)itor;
   iterator_get_curr(&range_itor->merge_itor->super, key, data);
}

platform_status
trunk_range_iterator_advance(iterator *itor)
{
   debug_assert(itor != NULL);
   trunk_range_iterator *range_itor = (trunk_range_iterator *)itor;
   iterator_advance(&range_itor->merge_itor->super);
   range_itor->num_tuples++;
   bool at_end;
   iterator_at_end(&range_itor->merge_itor->super, &at_end);
   platform_status rc;
   // robj: shouldn't this be a while loop, like in the init function?
   if (at_end) {
      trunk_range_iterator_deinit(range_itor);
      if (range_itor->has_max_key) {
         rc = trunk_range_iterator_init(range_itor->spl,
                                        range_itor,
                                        range_itor->rebuild_key,
                                        range_itor->max_key,
                                        range_itor->num_tuples);
      } else {
         rc = trunk_range_iterator_init(range_itor->spl,
                                        range_itor,
                                        range_itor->rebuild_key,
                                        NULL,
                                        range_itor->num_tuples);
      }
      if (!SUCCESS(rc)) {
         return rc;
      }
      if (!range_itor->at_end) {
         iterator_at_end(&range_itor->merge_itor->super, &at_end);
         platform_assert(!at_end);
      }
   }

   return STATUS_OK;
}

platform_status
trunk_range_iterator_at_end(iterator *itor, bool *at_end)
{
   debug_assert(itor != NULL);
   trunk_range_iterator *range_itor = (trunk_range_iterator *)itor;

   *at_end = range_itor->at_end;
   return STATUS_OK;
}

void
trunk_range_iterator_deinit(trunk_range_iterator *range_itor)
{
   // If the iterator is at end, then it has already been deinitialized
   if (range_itor->at_end) {
      return;
   }
   trunk_handle *spl = range_itor->spl;
   merge_iterator_destroy(range_itor->spl->heap_id, &range_itor->merge_itor);
   for (uint64 i = 0; i < range_itor->num_branches; i++) {
      btree_iterator *btree_itor = &range_itor->btree_itor[i];
      if (range_itor->compacted[i]) {
         uint64 root_addr = btree_itor->root_ref.addr;
         trunk_branch_iterator_deinit(spl, btree_itor, FALSE);
         btree_unblock_dec_ref(spl->cc, &spl->cfg.btree_cfg, root_addr);
      } else {
         uint64 mt_gen = range_itor->memtable_start_gen - i;
         trunk_memtable_iterator_deinit(spl, btree_itor, mt_gen, FALSE);
         trunk_memtable_dec_ref(spl, mt_gen);
      }
   }
}

/*
 * Given a node addr and pivot generation, find the pivot with that generation
 * among the node and its split descendents
 *
 * Returns node with a write loc
 */
trunk_pivot_data *
trunk_find_pivot_from_generation(trunk_handle *spl,
                                 page_handle  *leaf,
                                 uint64        pivot_generation)
{
   uint16 num_children = trunk_num_children(spl, leaf);
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, leaf, pivot_no);
      if (pivot_generation == pdata->generation) {
         return pdata;
      }
   }
   return NULL;
}

platform_status
trunk_compact_leaf(trunk_handle *spl, page_handle *leaf)
{
   const threadid tid = platform_get_tid();

   platform_stream_handle stream;
   platform_status        rc = trunk_open_log_stream_if_enabled(spl, &stream);
   platform_assert_status_ok(rc);
   trunk_log_stream_if_enabled(
      spl, &stream, "compact_leaf addr %lu\n", leaf->disk_addr);
   trunk_log_node_if_enabled(&stream, spl, leaf);

   uint64 sr_start;
   if (spl->cfg.use_stats) {
      spl->stats[tid].space_recs[0]++;
      sr_start = platform_get_timestamp();
   }

   // Clear old bundles from leaf and put all branches in a new bundle
   uint64 num_tuples = trunk_pivot_num_tuples(spl, leaf, 0);
   uint64 kv_bytes   = trunk_pivot_kv_bytes(spl, leaf, 0);
   uint16 bundle_no =
      trunk_leaf_rebundle_all_branches(spl, leaf, num_tuples, kv_bytes, TRUE);
   trunk_inc_generation(spl, leaf);

   // Issue compact_bundle for leaf and release
   trunk_compact_bundle_req *req = TYPED_ZALLOC(spl->heap_id, req);
   req->spl                      = spl;
   // req->height already 0
   req->bundle_no                    = bundle_no;
   req->max_pivot_generation         = trunk_pivot_generation(spl, leaf);
   req->pivot_generation[0]          = trunk_pivot_generation(spl, leaf) - 1;
   req->input_pivot_tuple_count[0]   = trunk_pivot_num_tuples(spl, leaf, 0);
   req->input_pivot_kv_byte_count[0] = trunk_pivot_kv_bytes(spl, leaf, 0);
   req->type                         = TRUNK_COMPACTION_TYPE_SPACE_REC;
   trunk_key_copy(spl, req->start_key, trunk_min_key(spl, leaf));
   trunk_key_copy(spl, req->end_key, trunk_max_key(spl, leaf));

   trunk_default_log_if_enabled(
      spl,
      "compact_bundle enqueue: range %s-%s, height %u, bundle %u\n",
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->start_key)),
      key_string(trunk_data_config(spl),
                 slice_create(trunk_key_size(spl), req->end_key)),
      req->height,
      req->bundle_no);
   rc =
      task_enqueue(spl->ts, TASK_TYPE_NORMAL, trunk_compact_bundle, req, FALSE);
   platform_assert(SUCCESS(rc));

   trunk_log_node_if_enabled(&stream, spl, leaf);

   debug_assert(trunk_verify_node(spl, leaf));

   /*
    * 8. Clean up
    */
   trunk_close_log_stream_if_enabled(spl, &stream);

   if (spl->cfg.use_stats) {
      // Doesn't include the original leaf
      uint64 sr_time = platform_timestamp_elapsed(sr_start);
      spl->stats[tid].space_rec_time_ns[0] += sr_time;
   }

   return STATUS_OK;
}

/*
 *-----------------------------------------------------------------------------
 * Space reclamation
 *-----------------------------------------------------------------------------
 */
bool
trunk_should_reclaim_space(trunk_handle *spl)
{
   if (spl->cfg.reclaim_threshold == UINT64_MAX) {
      return FALSE;
   }
   if (spl->cfg.reclaim_threshold == 0) {
      return TRUE;
   }
   uint64 in_use         = allocator_in_use(spl->al);
   bool   should_reclaim = in_use > spl->cfg.reclaim_threshold;
   return should_reclaim;
}

platform_status
trunk_reclaim_space(trunk_handle *spl)
{
   platform_assert(spl->cfg.reclaim_threshold != UINT64_MAX);
   while (TRUE) {
      // platform_default_log("Extract from SRQ\n");
      srq_data space_rec = srq_extract_max(&spl->srq);
      if (!srq_data_found(&space_rec)) {
         return STATUS_NOT_FOUND;
      }
      page_handle *node = trunk_node_get(spl, &space_rec.ref);
      trunk_node_claim(spl, &node);
      trunk_pivot_data *pdata = trunk_find_pivot_from_generation(
         spl, node, space_rec.pivot_generation);
      if (pdata == NULL) {
         trunk_node_unclaim(spl, node);
         trunk_node_unget(spl, &node);
         continue;
      }
      pdata->srq_idx = -1;

      // platform_default_log("Space rec: %lu-%u\n",
      //       node->disk_addr, trunk_pdata_to_pivot_index(spl, node,
      //       pdata));

      trunk_node_lock(spl, node);
      if (trunk_is_leaf(spl, node)) {
         trunk_compact_leaf(spl, node);
      } else {
         uint64 sr_start;
         if (spl->cfg.use_stats) {
            sr_start = platform_get_timestamp();
         }
         platform_status rc = trunk_flush(spl, node, pdata, TRUE);
         if (spl->cfg.use_stats) {
            const threadid tid    = platform_get_tid();
            uint16         height = trunk_height(spl, node);
            spl->stats[tid].space_recs[height]++;
            spl->stats[tid].space_rec_time_ns[height] +=
               platform_timestamp_elapsed(sr_start);
         }
         if (!SUCCESS(rc)) {
            trunk_node_unlock(spl, node, &space_rec.ref, __LINE__);
            trunk_node_unclaim(spl, node);
            trunk_node_unget(spl, &node);
            continue;
         }
      }
      trunk_node_unlock(spl, node, &space_rec.ref, __LINE__);
      trunk_node_unclaim(spl, node);
      trunk_node_unget(spl, &node);
      return STATUS_OK;
   }
}

void
trunk_maybe_reclaim_space(trunk_handle *spl)
{
   while (trunk_should_reclaim_space(spl)) {
      platform_status rc = trunk_reclaim_space(spl);
      if (STATUS_IS_EQ(rc, STATUS_NOT_FOUND)) {
         break;
      }
   }
}

/*
 *-----------------------------------------------------------------------------
 * Main Splinter API functions
 *
 *      insert
 *      lookup
 *      range
 *-----------------------------------------------------------------------------
 */

platform_status
trunk_insert(trunk_handle *spl, char *key, message data)
{
   timestamp                            ts;
   __attribute((unused)) const threadid tid = platform_get_tid();
   if (spl->cfg.use_stats) {
      ts = platform_get_timestamp();
   }

   if (message_class(data) == MESSAGE_TYPE_DELETE) {
      data = DELETE_MESSAGE;
   }

   platform_status rc = trunk_memtable_insert(spl, key, data);
   if (!SUCCESS(rc)) {
      goto out;
   }
   if (!task_system_use_bg_threads(spl->ts)) {
      task_perform_one(spl->ts);
   }

   if (spl->cfg.use_stats) {
      switch (message_class(data)) {
         case MESSAGE_TYPE_INSERT:
            spl->stats[tid].insertions++;
            platform_histo_insert(spl->stats[tid].insert_latency_histo,
                                  platform_timestamp_elapsed(ts));
            break;
         case MESSAGE_TYPE_UPDATE:
            spl->stats[tid].updates++;
            platform_histo_insert(spl->stats[tid].update_latency_histo,
                                  platform_timestamp_elapsed(ts));
            break;
         case MESSAGE_TYPE_DELETE:
            spl->stats[tid].deletions++;
            platform_histo_insert(spl->stats[tid].delete_latency_histo,
                                  platform_timestamp_elapsed(ts));
            break;
         default:
            platform_assert(0);
      }
   }

out:
   return rc;
}

bool
trunk_filter_lookup(trunk_handle      *spl,
                    page_handle       *node,
                    routing_filter    *filter,
                    routing_config    *cfg,
                    uint16             start_branch,
                    const char        *key,
                    merge_accumulator *data)
{
   uint16   height;
   threadid tid;
   if (spl->cfg.use_stats) {
      tid    = platform_get_tid();
      height = trunk_height(spl, node);
   }

   uint64 found_values;
   slice  key_slice = slice_create(cfg->data_cfg->key_size, (void *)key);
   platform_status rc =
      routing_filter_lookup(spl->cc, cfg, filter, key_slice, &found_values);
   platform_assert_status_ok(rc);
   if (spl->cfg.use_stats) {
      spl->stats[tid].filter_lookups[height]++;
   }
   uint16 next_value =
      routing_filter_get_next_value(found_values, ROUTING_NOT_FOUND);
   while (next_value != ROUTING_NOT_FOUND) {
      uint16 branch_no = trunk_add_branch_number(spl, start_branch, next_value);
      trunk_branch   *branch = trunk_get_branch(spl, node, branch_no);
      bool            local_found;
      platform_status rc;
      rc = trunk_btree_lookup_and_merge(spl, branch, key, data, &local_found);
      platform_assert_status_ok(rc);
      if (spl->cfg.use_stats) {
         spl->stats[tid].branch_lookups[height]++;
      }
      if (local_found) {
         message msg = merge_accumulator_to_message(data);
         if (message_is_definitive(msg)) {
            return FALSE;
         }
      } else if (spl->cfg.use_stats) {
         spl->stats[tid].filter_false_positives[height]++;
      }
      next_value = routing_filter_get_next_value(found_values, next_value);
   }
   return TRUE;
}

bool
trunk_compacted_subbundle_lookup(trunk_handle      *spl,
                                 page_handle       *node,
                                 trunk_subbundle   *sb,
                                 const char        *key,
                                 merge_accumulator *data)
{
   debug_assert(sb->state == SB_STATE_COMPACTED);
   debug_assert(trunk_subbundle_branch_count(spl, node, sb) == 1);
   uint16   height;
   threadid tid;
   if (spl->cfg.use_stats) {
      tid    = platform_get_tid();
      height = trunk_height(spl, node);
   }

   uint16 filter_count = trunk_subbundle_filter_count(spl, node, sb);
   for (uint16 filter_no = 0; filter_no != filter_count; filter_no++) {
      if (spl->cfg.use_stats) {
         spl->stats[tid].filter_lookups[height]++;
      }
      uint64          found_values;
      routing_filter *filter = trunk_subbundle_filter(spl, node, sb, filter_no);
#ifdef SGX_TEST
      debug_assert(filter->ref.addr != 0);
#else
      debug_assert(filter->addr != 0);
#endif
      slice key_slice = slice_create(spl->cfg.data_cfg->key_size, (void *)key);
      platform_status rc = routing_filter_lookup(
         spl->cc, &spl->cfg.filter_cfg, filter, key_slice, &found_values);
      platform_assert_status_ok(rc);
      if (found_values) {
         uint16          branch_no = sb->start_branch;
         trunk_branch   *branch    = trunk_get_branch(spl, node, branch_no);
         bool            local_found;
         platform_status rc;
         rc =
            trunk_btree_lookup_and_merge(spl, branch, key, data, &local_found);
         platform_assert_status_ok(rc);
         if (spl->cfg.use_stats) {
            spl->stats[tid].branch_lookups[height]++;
         }
         if (local_found) {
            message msg = merge_accumulator_to_message(data);
            if (message_is_definitive(msg)) {
               return FALSE;
            }
         } else if (spl->cfg.use_stats) {
            spl->stats[tid].filter_false_positives[height]++;
         }
         return TRUE;
      }
   }
   return TRUE;
}

bool
trunk_bundle_lookup(trunk_handle      *spl,
                    page_handle       *node,
                    trunk_bundle      *bundle,
                    const char        *key,
                    merge_accumulator *data)
{
   uint16 sb_count = trunk_bundle_subbundle_count(spl, node, bundle);
   for (uint16 sb_off = 0; sb_off != sb_count; sb_off++) {
      uint16 sb_no = trunk_subtract_subbundle_number(
         spl, bundle->end_subbundle, sb_off + 1);
      trunk_subbundle *sb = trunk_get_subbundle(spl, node, sb_no);
      bool             should_continue;
      if (sb->state == SB_STATE_COMPACTED) {
         should_continue =
            trunk_compacted_subbundle_lookup(spl, node, sb, key, data);
      } else {
         routing_filter *filter = trunk_subbundle_filter(spl, node, sb, 0);
         routing_config *cfg    = &spl->cfg.filter_cfg;
#ifdef SGX_TEST
         debug_assert(filter->ref.addr != 0);
#else
         debug_assert(filter->addr != 0);
#endif
         should_continue = trunk_filter_lookup(
            spl, node, filter, cfg, sb->start_branch, key, data);
      }
      if (!should_continue) {
         return should_continue;
      }
   }
   return TRUE;
}

bool
trunk_pivot_lookup(trunk_handle      *spl,
                   page_handle       *node,
                   trunk_pivot_data  *pdata,
                   const char        *key,
                   merge_accumulator *data)
{
   // first check in bundles
   uint16 num_bundles = trunk_pivot_bundle_count(spl, node, pdata);
   for (uint16 bundle_off = 0; bundle_off != num_bundles; bundle_off++) {
      uint16 bundle_no = trunk_subtract_bundle_number(
         spl, trunk_end_bundle(spl, node), bundle_off + 1);
      debug_assert(trunk_bundle_live(spl, node, bundle_no));
      trunk_bundle *bundle = trunk_get_bundle(spl, node, bundle_no);
      bool should_continue = trunk_bundle_lookup(spl, node, bundle, key, data);
      if (!should_continue) {
         return should_continue;
      }
   }

   routing_config *cfg = &spl->cfg.filter_cfg;
   return trunk_filter_lookup(
      spl, node, &pdata->filter, cfg, pdata->start_branch, key, data);
}

// If any change is made in here, please make similar change in
// trunk_lookup_async
platform_status
trunk_lookup(trunk_handle *spl, char *key, merge_accumulator *result)
{
   // look in memtables

   // 1. get read lock on lookup lock
   //     --- 2. for [mt_no = mt->generation..mt->gen_to_incorp]
   // 2. for gen = mt->generation; mt[gen % ...].gen == gen; gen --;
   //                also handles switch to READY ^^^^^

   merge_accumulator_set_to_null(result);

   bool         found_in_memtable   = FALSE;
   page_handle *mt_lookup_lock_page = memtable_get_lookup_lock(spl->mt_ctxt);
   uint64       mt_gen_start        = memtable_generation(spl->mt_ctxt);
   uint64       mt_gen_end          = memtable_generation_retired(spl->mt_ctxt);
   for (uint64 mt_gen = mt_gen_start; mt_gen != mt_gen_end; mt_gen--) {
      platform_status rc;
      rc = trunk_memtable_lookup(spl, mt_gen, key, result);
      platform_assert_status_ok(rc);
      if (merge_accumulator_is_definitive(result)) {
         found_in_memtable = TRUE;
         goto found_final_answer_early;
      }
   }

   // hold root read lock to prevent memtable flush
   page_handle *node = trunk_node_get(spl, &spl->root_ref);

   // release memtable lookup lock
   memtable_unget_lookup_lock(spl->mt_ctxt, mt_lookup_lock_page);

   // look in index nodes
   uint16 height = trunk_height(spl, node);
   for (uint16 h = height; h > 0; h--) {
      uint16 pivot_no = trunk_find_pivot(spl, node, key, less_than_or_equal);
      debug_assert(pivot_no < trunk_num_children(spl, node));
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      bool should_continue = trunk_pivot_lookup(spl, node, pdata, key, result);
      if (!should_continue) {
         goto found_final_answer_early;
      }
      page_reference ref = pdata->ref;
      page_handle *child = trunk_node_get(spl, &ref);
      trunk_node_unget(spl, &node);
      node = child;
   }

   // look in leaf
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, 0);
   bool should_continue    = trunk_pivot_lookup(spl, node, pdata, key, result);
   if (!should_continue) {
      goto found_final_answer_early;
   }

   debug_assert(merge_accumulator_is_null(result)
                || merge_accumulator_message_class(result)
                      == MESSAGE_TYPE_UPDATE);
   if (!merge_accumulator_is_null(result)) {
      data_merge_tuples_final(
         spl->cfg.data_cfg, trunk_key_slice(spl, key), result);
   }
found_final_answer_early:

   if (found_in_memtable) {
      // release memtable lookup lock
      memtable_unget_lookup_lock(spl->mt_ctxt, mt_lookup_lock_page);
   } else {
      trunk_node_unget(spl, &node);
   }
   if (spl->cfg.use_stats) {
      threadid tid = platform_get_tid();
      if (!merge_accumulator_is_null(result)) {
         spl->stats[tid].lookups_found++;
      } else {
         spl->stats[tid].lookups_not_found++;
      }
   }

   /* Normalize DELETE messages to return a null merge_accumulator */
   if (!merge_accumulator_is_null(result)
       && merge_accumulator_message_class(result) == MESSAGE_TYPE_DELETE)
   {
      merge_accumulator_set_to_null(result);
   }

   return STATUS_OK;
}

/*
 * trunk_async_set_state sets the state of the async splinter
 * lookup state machine.
 */
static inline void
trunk_async_set_state(trunk_async_ctxt *ctxt, trunk_async_state new_state)
{
   ctxt->prev_state = ctxt->state;
   ctxt->state      = new_state;
}


/*
 * trunk_async_callback
 *
 *      Callback that's called when the async cache get for a trunk
 *      node loads a page for the child into the cache. This function
 *      moves the async splinter lookup state machine's state ahead,
 *      and calls the upper layer callback that'll re-enqueue the
 *      spinter lookup for dispatch.
 */
static void
trunk_async_callback(cache_async_ctxt *cache_ctxt)
{
   trunk_async_ctxt *ctxt =
      container_of(cache_ctxt, trunk_async_ctxt, cache_ctxt);
   platform_assert(SUCCESS(cache_ctxt->status));
   platform_assert(cache_ctxt->page);
   //   platform_default_log("%s:%d tid %2lu: ctxt %p is callback with page
   //   %p\n",
   //                __FILE__, __LINE__, platform_get_tid(), ctxt,
   //                cache_ctxt->page);
   ctxt->was_async = TRUE;
   // Move state machine ahead and requeue for dispatch
   if (UNLIKELY(ctxt->state == async_state_get_root_reentrant)) {
      trunk_async_set_state(ctxt, async_state_trunk_node_lookup);
   } else {
      debug_assert((ctxt->state == async_state_get_child_trunk_node_reentrant),
                   "ctxt->state=%d != expected state=%d",
                   ctxt->state,
                   async_state_get_child_trunk_node_reentrant);
      trunk_async_set_state(ctxt, async_state_unget_parent_trunk_node);
   }
   ctxt->cb(ctxt);
}


/*
 * trunk_filter_async_callback
 *
 *      Callback that's called when the async filter get api has loaded
 *      a page into cache. This just requeues the splinter lookup for
 *      dispatch at the same state, so that async filter get can be
 *      called again.
 */
static void
trunk_filter_async_callback(routing_async_ctxt *filter_ctxt)
{
   trunk_async_ctxt *ctxt =
      container_of(filter_ctxt, trunk_async_ctxt, filter_ctxt);
   //   platform_default_log("%s:%d tid %2lu: ctxt %p is callback\n",
   //                __FILE__, __LINE__, platform_get_tid(), ctxt);
   // Requeue for dispatch
   ctxt->cb(ctxt);
}

/*
 * trunk_btree_async_callback
 *
 *      Callback that's called when the async btree
 *      lookup api has loaded a page into cache. This just requeues
 *      the splinter lookup for dispatch at the same state, so that
 *      async btree lookup can be called again.
 */
static void
trunk_btree_async_callback(btree_async_ctxt *btree_ctxt)
{
   trunk_async_ctxt *ctxt =
      container_of(btree_ctxt, trunk_async_ctxt, btree_ctxt);
   //   platform_default_log("%s:%d tid %2lu: ctxt %p is callback\n",
   //                __FILE__, __LINE__, platform_get_tid(), ctxt);
   // Requeue for dispatch
   ctxt->cb(ctxt);
}


/*
 * Async splinter lookup. Caller must have called trunk_async_ctxt_init()
 * on the context before the first invocation.
 *
 * This uses hand over hand locking to descend the trunk tree and
 * every time a child node needs to be looked up from the cache, it
 * uses the async get api. A reference to the parent node is held in
 * trunk_async_ctxt->trunk_node while a reference to the child page
 * is obtained by the cache_get_async() into
 * trunk_async_ctxt->cache_ctxt->page
 *
 * Returns:
 *    async_success: results are available in *found and *result
 *    async_locked: caller needs to retry
 *    async_no_reqs: caller needs to retry but may want to throttle
 *    async_io_started: async IO was started; the caller will be informed
 *      via callback when it's done. After callback is called, the caller
 *      must call this again from thread context with the same key and result
 *      as the first invocation.
 *
 * Side-effects:
 *    Maintains state in *result. This helps avoid copying data between
 *    invocations. Caller must use the same pointers to key, result and
 *    found in different invocations of a lookup until it returns
 *    async_success. Caller must not modify the contents of those
 *    pointers.
 */
cache_async_result
trunk_lookup_async(trunk_handle      *spl,    // IN
                   char              *key,    // IN
                   merge_accumulator *result, // OUT
                   trunk_async_ctxt  *ctxt)    // IN/OUT
{
   cache_async_result res = 0;
   threadid           tid;

#if TRUNK_DEBUG
   cache_enable_sync_get(spl->cc, FALSE);
#endif
   if (spl->cfg.use_stats) {
      tid = platform_get_tid();
   }
   page_handle *node = ctxt->trunk_node;
   bool         done = FALSE;

   do {
      switch (ctxt->state) {
         case async_state_start:
         {
            merge_accumulator_set_to_null(result);
            trunk_async_set_state(ctxt, async_state_lookup_memtable);
            // fallthrough
         }
         case async_state_lookup_memtable:
         {
            ctxt->mt_lock_page  = memtable_get_lookup_lock(spl->mt_ctxt);
            uint64 mt_gen_start = memtable_generation(spl->mt_ctxt);
            uint64 mt_gen_end   = memtable_generation_retired(spl->mt_ctxt);
            for (uint64 mt_gen = mt_gen_start; mt_gen != mt_gen_end; mt_gen--) {
               platform_status rc;
               rc = trunk_memtable_lookup(spl, mt_gen, key, result);
               platform_assert_status_ok(rc);
               if (merge_accumulator_is_definitive(result)) {
                  trunk_async_set_state(ctxt,
                                        async_state_found_final_answer_early);
                  break;
               }
            }
            // fallthrough
         }
         case async_state_get_root_reentrant:
         {
            cache_ctxt_init(
               spl->cc, trunk_async_callback, NULL, &ctxt->cache_ctxt);
            res = trunk_node_get_async(spl, &spl->root_ref, ctxt);
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
                  trunk_async_set_state(ctxt, async_state_trunk_node_lookup);
                  platform_assert(node == NULL);
                  ctxt->trunk_node = node = ctxt->cache_ctxt.page;
                  memtable_unget_lookup_lock(spl->mt_ctxt, ctxt->mt_lock_page);
                  ctxt->mt_lock_page = NULL;
                  break;
               default:
                  platform_assert(0);
            }
            break;
         }
         case async_state_trunk_node_lookup:
         {
            ctxt->height = trunk_height(spl, node);
            uint16 pivot_no =
               trunk_find_pivot(spl, node, key, less_than_or_equal);
            debug_assert(pivot_no < trunk_num_children(spl, node));
            ctxt->pdata = trunk_get_pivot_data(spl, node, pivot_no);
            ctxt->sb_no = trunk_start_subbundle_for_lookup(spl, node);
            ctxt->end_sb_no =
               trunk_pivot_end_subbundle_for_lookup(spl, node, ctxt->pdata);
            ctxt->filter_no = 0;
            char key_str[128];
            trunk_key_to_string(spl, key, key_str);
            trunk_async_set_state(ctxt, async_state_subbundle_lookup);
            // fallthrough
         }
         case async_state_subbundle_lookup:
         {
            if (ctxt->sb_no == ctxt->end_sb_no) {
               debug_assert(ctxt->filter_no == 0);
               ctxt->lookup_state = async_lookup_state_pivot;
               trunk_async_set_state(ctxt, async_state_pivot_lookup);
               break;
            }
            ctxt->sb = trunk_get_subbundle(spl, node, ctxt->sb_no);
            if (ctxt->sb->state == SB_STATE_COMPACTED) {
               ctxt->lookup_state = async_lookup_state_compacted_subbundle;
            } else {
               ctxt->lookup_state = async_lookup_state_subbundle;
            }
            debug_assert(ctxt->filter_no
                         < trunk_subbundle_filter_count(spl, node, ctxt->sb));
            ctxt->filter =
               trunk_subbundle_filter(spl, node, ctxt->sb, ctxt->filter_no);
            trunk_async_set_state(ctxt, async_state_filter_lookup_start);
            break;
         }
         case async_state_pivot_lookup:
         {
            ctxt->sb     = NULL;
            ctxt->filter = &ctxt->pdata->filter;
            trunk_async_set_state(ctxt, async_state_filter_lookup_start);
            // fall through
         }
         case async_state_filter_lookup_start:
         {
            ctxt->value = ROUTING_NOT_FOUND;
            if (ctxt->filter->addr == 0) {
               platform_assert(ctxt->lookup_state == async_lookup_state_pivot);
               trunk_async_set_state(ctxt, async_state_next_in_node);
               break;
            }
            if (spl->cfg.use_stats) {
               spl->stats[tid].filter_lookups[ctxt->height]++;
            }
            routing_filter_ctxt_init(&ctxt->filter_ctxt,
                                     &ctxt->cache_ctxt,
                                     trunk_filter_async_callback);
            trunk_async_set_state(ctxt, async_state_filter_lookup_reentrant);
            break;
         }
         case async_state_filter_lookup_reentrant:
         {
            // bool is_leaf;
            // switch (ctxt->lookup_state) {
            //    case async_lookup_state_pivot:
            //       is_leaf = ctxt->height == 0;
            //       break;
            //    case async_lookup_state_subbundle:
            //       debug_assert(ctxt->sb != NULL);
            //       is_leaf = ctxt->sb->state == SB_STATE_UNCOMPACTED_LEAF;
            //       break;
            //    case async_lookup_state_compacted_subbundle:
            //       is_leaf = FALSE;
            //       break;
            // }

            routing_config *filter_cfg = trunk_routing_cfg(spl);

            res = trunk_filter_lookup_async(spl,
                                            filter_cfg,
                                            ctxt->filter,
                                            key,
                                            &ctxt->found_values,
                                            &ctxt->filter_ctxt);
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
                  // I don't own the cache context, filter does
                  trunk_async_set_state(ctxt, async_state_btree_lookup_start);
                  break;
               default:
                  platform_assert(0);
            }
            break;
         }
         case async_state_btree_lookup_start:
         {
            uint16 branch_no;
            switch (ctxt->lookup_state) {
               case async_lookup_state_pivot:
                  debug_assert(ctxt->pdata != NULL);
                  ctxt->value = routing_filter_get_next_value(
                     ctxt->found_values, ctxt->value);
                  if (ctxt->value == ROUTING_NOT_FOUND) {
                     trunk_async_set_state(ctxt, async_state_next_in_node);
                     continue;
                  }
                  branch_no = trunk_add_branch_number(
                     spl, ctxt->pdata->start_branch, ctxt->value);
                  break;
               case async_lookup_state_subbundle:
                  debug_assert(ctxt->sb != NULL);
                  ctxt->value = routing_filter_get_next_value(
                     ctxt->found_values, ctxt->value);
                  if (ctxt->value == ROUTING_NOT_FOUND) {
                     trunk_async_set_state(ctxt, async_state_next_in_node);
                     continue;
                  }
                  branch_no = trunk_add_branch_number(
                     spl, ctxt->sb->start_branch, ctxt->value);
                  branch_no = ctxt->sb->start_branch + ctxt->value;
                  break;
               case async_lookup_state_compacted_subbundle:
                  debug_assert(ctxt->sb != NULL);
                  if (ctxt->found_values == 0) {
                     ctxt->value = ROUTING_NOT_FOUND;
                     trunk_async_set_state(ctxt, async_state_next_in_node);
                     continue;
                  }
                  branch_no = ctxt->sb->start_branch;
                  break;
            }
            ctxt->branch = trunk_get_branch(spl, node, branch_no);
            btree_ctxt_init(&ctxt->btree_ctxt,
                            &ctxt->cache_ctxt,
                            trunk_btree_async_callback);
            trunk_async_set_state(ctxt, async_state_btree_lookup_reentrant);
            break;
         }
         case async_state_btree_lookup_reentrant:
         {
            res = trunk_btree_lookup_and_merge_async(
               spl, ctxt->branch, key, result, &ctxt->btree_ctxt);
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
                  // I don't own the cache context, btree does
                  if (merge_accumulator_is_definitive(result)) {
                     trunk_async_set_state(
                        ctxt, async_state_found_final_answer_early);
                     break;
                  } else if (spl->cfg.use_stats) {
                     const uint16 height = trunk_height(spl, node);
                     spl->stats[tid].filter_false_positives[height]++;
                  }
                  trunk_async_set_state(ctxt, async_state_next_in_node);
                  break;
               default:
                  platform_assert(0);
            }
            break;
         }
         case async_state_next_in_node:
         {
            switch (ctxt->lookup_state) {
               case async_lookup_state_pivot:
                  debug_assert(ctxt->filter_no == 0);
                  if (ctxt->value == ROUTING_NOT_FOUND) {
                     trunk_async_set_state(ctxt, async_state_trunk_node_done);
                  } else {
                     trunk_async_set_state(ctxt,
                                           async_state_btree_lookup_start);
                  }
                  continue;
               case async_lookup_state_subbundle:
                  debug_assert(ctxt->filter_no == 0);
                  if (ctxt->value == ROUTING_NOT_FOUND) {
                     ctxt->sb_no =
                        trunk_subtract_subbundle_number(spl, ctxt->sb_no, 1);
                     trunk_async_set_state(ctxt, async_state_subbundle_lookup);
                     break;
                  } else {
                     trunk_async_set_state(ctxt,
                                           async_state_btree_lookup_start);
                  }
                  continue;
               case async_lookup_state_compacted_subbundle:
                  if (ctxt->found_values != 0) {
                     ctxt->sb_no =
                        trunk_subtract_subbundle_number(spl, ctxt->sb_no, 1);
                     ctxt->filter_no = 0;
                  } else {
                     ctxt->filter_no++;
                     uint16 sb_filter_count =
                        trunk_subbundle_filter_count(spl, node, ctxt->sb);
                     if (ctxt->filter_no >= sb_filter_count) {
                        debug_assert(ctxt->filter_no == sb_filter_count);
                        ctxt->sb_no =
                           trunk_subtract_subbundle_number(spl, ctxt->sb_no, 1);
                        ctxt->filter_no = 0;
                     }
                  }
                  trunk_async_set_state(ctxt, async_state_subbundle_lookup);
                  continue;
            }
            break;
         }
         case async_state_trunk_node_done:
         {
            if (ctxt->height == 0) {
               if (!merge_accumulator_is_null(result)
                   && merge_accumulator_message_class(result)
                         != MESSAGE_TYPE_INSERT)
               {
                  data_merge_tuples_final(
                     spl->cfg.data_cfg, trunk_key_slice(spl, key), result);
               }
               trunk_async_set_state(ctxt, async_state_end);
               break;
            } else {
               trunk_async_set_state(
                  ctxt, async_state_get_child_trunk_node_reentrant);
               break;
            }
         }
         case async_state_get_child_trunk_node_reentrant:
         {
            cache_ctxt_init(
               spl->cc, trunk_async_callback, NULL, &ctxt->cache_ctxt);
            debug_assert(ctxt->pdata != NULL);
            page_reference ref = ctxt->pdata->ref;
            res = trunk_node_get_async(spl, &ref, ctxt);
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
                  trunk_async_set_state(ctxt,
                                        async_state_unget_parent_trunk_node);
                  break;
               default:
                  platform_assert(0);
            }
            break;
         }
         case async_state_unget_parent_trunk_node:
         {
            if (ctxt->was_async) {
               trunk_node_async_done(spl, ctxt);
            }
            trunk_node_unget(spl, &node);
            ctxt->pdata      = NULL;
            ctxt->trunk_node = node = ctxt->cache_ctxt.page;
            trunk_async_set_state(ctxt, async_state_trunk_node_lookup);
            break;
         }
         case async_state_found_final_answer_early:
         {
            trunk_async_set_state(ctxt, async_state_end);
            break;
         }
         case async_state_end:
         {
            if (ctxt->mt_lock_page != NULL) {
               memtable_unget_lookup_lock(spl->mt_ctxt, ctxt->mt_lock_page);
               ctxt->mt_lock_page = NULL;
               debug_assert(node == NULL);
            } else {
               trunk_node_unget(spl, &node);
            }
            ctxt->trunk_node = NULL;
            if (spl->cfg.use_stats) {
               if (!merge_accumulator_is_null(result)) {
                  spl->stats[tid].lookups_found++;
               } else {
                  spl->stats[tid].lookups_not_found++;
               }
            }

            if (!merge_accumulator_is_null(result)) {
               message_type type = merge_accumulator_message_class(result);
               debug_assert(type == MESSAGE_TYPE_DELETE
                            || type == MESSAGE_TYPE_INSERT);
               if (type == MESSAGE_TYPE_DELETE) {
                  merge_accumulator_set_to_null(result);
               }
            }

            res  = async_success;
            done = TRUE;
            break;
         }
         default:
            platform_assert(0);
      }
   } while (!done);
#if TRUNK_DEBUG
   cache_enable_sync_get(spl->cc, TRUE);
#endif

   return res;
}


platform_status
trunk_range(trunk_handle  *spl,
            const char    *start_key,
            uint64         num_tuples,
            tuple_function func,
            void          *arg)
{
   trunk_range_iterator *range_itor = TYPED_MALLOC(spl->heap_id, range_itor);
   platform_status       rc =
      trunk_range_iterator_init(spl, range_itor, start_key, NULL, num_tuples);
   if (!SUCCESS(rc)) {
      goto destroy_range_itor;
   }

   bool at_end;
   iterator_at_end(&range_itor->super, &at_end);

   for (int i = 0; i < num_tuples && !at_end; i++) {
      slice   key;
      message data;
      iterator_get_curr(&range_itor->super, &key, &data);
      func(key, data, arg);
      iterator_advance(&range_itor->super);
      iterator_at_end(&range_itor->super, &at_end);
   }

destroy_range_itor:
   trunk_range_iterator_deinit(range_itor);
   platform_free(spl->heap_id, range_itor);
   return rc;
}


/*
 *-----------------------------------------------------------------------------
 * Create/destroy
 * XXX Fix this api to return platform_status
 *-----------------------------------------------------------------------------
 */
trunk_handle *
trunk_create(trunk_config     *cfg,
             allocator        *al,
             cache            *cc,
             task_system      *ts,
             allocator_root_id id,
             platform_heap_id  hid)
{
   trunk_handle *spl = TYPED_FLEXIBLE_STRUCT_ZALLOC(
      hid, spl, compacted_memtable, TRUNK_NUM_MEMTABLES);
   memmove(&spl->cfg, cfg, sizeof(*cfg));
   spl->al = al;
   spl->cc = cc;
   debug_assert(id != INVALID_ALLOCATOR_ROOT_ID);
   spl->id      = id;
   spl->heap_id = hid;
   spl->ts      = ts;

   srq_init(&spl->srq, platform_get_module_id(), hid);

   // get a free node for the root
   //    we don't use the mini allocator for this, since the root doesn't
   //    maintain constant height
   platform_status rc =
      allocator_alloc(spl->al, &spl->root_ref.addr, PAGE_TYPE_TRUNK);
   platform_assert_status_ok(rc);
   page_handle *root = cache_alloc(spl->cc, spl->root_ref.addr, PAGE_TYPE_TRUNK);
   trunk_hdr   *root_hdr = (trunk_hdr *)root->data;
   ZERO_CONTENTS(root_hdr);

   // set up the mini allocator
   //    we use the root extent as the initial mini_allocator head
   uint64 meta_addr = spl->root_ref.addr + trunk_page_size(cfg);
   // The trunk uses an unkeyed mini allocator
   mini_init(&spl->mini,
             cc,
             spl->cfg.data_cfg,
             meta_addr,
             0,
             TRUNK_MAX_HEIGHT,
             PAGE_TYPE_TRUNK,
             FALSE);

   // set up the memtable context
   memtable_config *mt_cfg = &spl->cfg.mt_cfg;
   spl->mt_ctxt            = memtable_context_create(
      spl->heap_id, cc, mt_cfg, trunk_memtable_flush_virtual, spl);

   // set up the log
   if (spl->cfg.use_log) {
      uint64 log_gen_id = trunk_get_log_gen_id(spl);
      spl->log = log_create(cc, spl->cfg.log_cfg, log_gen_id, spl->heap_id);
   }

   // ALEX: For now we assume an init means destroying any present super blocks
   trunk_set_super_block(spl, FALSE, FALSE, TRUE);

   // set up the initial leaf
   page_handle *leaf     = trunk_alloc(spl, 0);
   trunk_hdr   *leaf_hdr = (trunk_hdr *)leaf->data;
   memset(leaf_hdr, 0, trunk_page_size(&spl->cfg));
   const char *min_key = spl->cfg.data_cfg->min_key;
   const char *max_key = spl->cfg.data_cfg->max_key;
   trunk_set_initial_pivots(spl, leaf, min_key, max_key);
   trunk_inc_pivot_generation(spl, leaf);

   // compute the hash of the leaf first
   cache_hash(spl->cc, leaf, leaf->disk_addr);

   // add leaf to root and fix up root
   root_hdr->height = 1;
   trunk_add_pivot_new_root(spl, root, leaf);
   // set up the reference in the root
   trunk_set_ref_new_root(spl, root, leaf);

   trunk_inc_pivot_generation(spl, root);

   // compute the hash of the root node
   cache_hash(spl->cc, root, root->disk_addr);
   memcpy(spl->root_ref.hash, cache_get_page_hash(spl->cc, root), HASH_SIZE);

   trunk_node_unlock(spl, leaf, NULL, __LINE__);
   trunk_node_unclaim(spl, leaf);
   trunk_node_unget(spl, &leaf);

   trunk_node_unlock(spl, root, &spl->root_ref, __LINE__);
   trunk_node_unclaim(spl, root);
   trunk_node_unget(spl, &root);

   // initialize trunk update lock
   platform_mutex_init(
      &spl->update_lock, platform_get_module_id(), spl->heap_id);


   if (spl->cfg.use_stats) {
      spl->stats = TYPED_ARRAY_ZALLOC(spl->heap_id, spl->stats, MAX_THREADS);
      platform_assert(spl->stats);
      for (uint64 i = 0; i < MAX_THREADS; i++) {
         platform_status rc;
         rc = platform_histo_create(spl->heap_id,
                                    LATENCYHISTO_SIZE + 1,
                                    latency_histo_buckets,
                                    &spl->stats[i].insert_latency_histo);
         platform_assert_status_ok(rc);
         rc = platform_histo_create(spl->heap_id,
                                    LATENCYHISTO_SIZE + 1,
                                    latency_histo_buckets,
                                    &spl->stats[i].update_latency_histo);
         platform_assert_status_ok(rc);
         rc = platform_histo_create(spl->heap_id,
                                    LATENCYHISTO_SIZE + 1,
                                    latency_histo_buckets,
                                    &spl->stats[i].delete_latency_histo);
         platform_assert_status_ok(rc);
      }
      init_hash_counters();
   }
   return spl;
}

/*
 * Open (mount) an existing splinter database
 */
trunk_handle *
trunk_mount(trunk_config     *cfg,
            allocator        *al,
            cache            *cc,
            task_system      *ts,
            allocator_root_id id,
            platform_heap_id  hid)
{
   trunk_handle *spl = TYPED_FLEXIBLE_STRUCT_ZALLOC(
      hid, spl, compacted_memtable, TRUNK_NUM_MEMTABLES);
   memmove(&spl->cfg, cfg, sizeof(*cfg));
   spl->al = al;
   spl->cc = cc;
   debug_assert(id != INVALID_ALLOCATOR_ROOT_ID);
   spl->id      = id;
   spl->heap_id = hid;
   spl->ts      = ts;

   srq_init(&spl->srq, platform_get_module_id(), hid);

   // find the dismounted super block
   spl->root_ref.addr                  = 0;
   uint64             meta_tail        = 0;
   uint64             latest_timestamp = 0;
   page_handle       *super_page;
   trunk_super_block *super = trunk_get_super_block_if_valid(spl, &super_page);
   if (super != NULL) {
      if (super->dismounted && super->timestamp > latest_timestamp) {
         spl->root_ref   = super->root_ref;
         meta_tail        = super->meta_tail;
         latest_timestamp = super->timestamp;
      }
      trunk_release_super_block(spl, super_page);
   }
   if (spl->root_ref.addr == 0) {
      return NULL;
   }

   trunk_init_filter_id(spl, super->latest_filter_id);
   trunk_init_log_gen_id(spl, super->latest_log_gen_id);

   uint64 meta_head = spl->root_ref.addr + trunk_page_size(&spl->cfg);

   memtable_config *mt_cfg = &spl->cfg.mt_cfg;
   spl->mt_ctxt            = memtable_context_create(
      spl->heap_id, cc, mt_cfg, trunk_memtable_flush_virtual, spl);

   // The trunk uses an unkeyed mini allocator
   mini_init(&spl->mini,
             cc,
             spl->cfg.data_cfg,
             meta_head,
             meta_tail,
             TRUNK_MAX_HEIGHT,
             PAGE_TYPE_TRUNK,
             FALSE);
   if (spl->cfg.use_log) {
      uint64 log_gen_id = trunk_get_log_gen_id(spl);
      spl->log = log_create(cc, spl->cfg.log_cfg, log_gen_id, spl->heap_id);
   }

   trunk_set_super_block(spl, FALSE, FALSE, FALSE);

   // initialize trunk update lock
   platform_mutex_init(
      &spl->update_lock, platform_get_module_id(), spl->heap_id);

   if (spl->cfg.use_stats) {
      spl->stats = TYPED_ARRAY_ZALLOC(spl->heap_id, spl->stats, MAX_THREADS);
      platform_assert(spl->stats);
      for (uint64 i = 0; i < MAX_THREADS; i++) {
         platform_status rc;
         rc = platform_histo_create(spl->heap_id,
                                    LATENCYHISTO_SIZE + 1,
                                    latency_histo_buckets,
                                    &spl->stats[i].insert_latency_histo);
         platform_assert_status_ok(rc);
         rc = platform_histo_create(spl->heap_id,
                                    LATENCYHISTO_SIZE + 1,
                                    latency_histo_buckets,
                                    &spl->stats[i].update_latency_histo);
         platform_assert_status_ok(rc);
         rc = platform_histo_create(spl->heap_id,
                                    LATENCYHISTO_SIZE + 1,
                                    latency_histo_buckets,
                                    &spl->stats[i].delete_latency_histo);
         platform_assert_status_ok(rc);
      }
      init_hash_counters();
   }
   return spl;
}

/*
 * This function is only safe to call when all other calls to spl have returned
 * and all tasks have been complete.
 */
void
trunk_prepare_for_shutdown(trunk_handle *spl)
{
   // write current memtable to disk
   // (any others must already be flushing/flushed)

   if (!memtable_is_empty(spl->mt_ctxt)) {
      /*
       * memtable_force_finalize is not thread safe. Note also, we do not hold
       * the insert lock or rotate while flushing the memtable.
       */

      uint64 generation = memtable_force_finalize(spl->mt_ctxt);
      trunk_memtable_flush(spl, generation);
   }

   // finish any outstanding tasks and destroy task system for this table.
   task_perform_all(spl->ts);

   // destroy memtable context (and its memtables)
   memtable_context_destroy(spl->heap_id, spl->mt_ctxt);

   // release the trunk mini allocator
   mini_release(&spl->mini, NULL_SLICE);

   // flush all dirty pages in the cache
   cache_flush(spl->cc);

   print_hash_counters();
}

bool
trunk_node_destroy(trunk_handle *spl, page_reference *ref, void *arg)
{
   page_handle *node = trunk_node_get(spl, ref);
   trunk_node_claim(spl, &node);
   trunk_node_lock(spl, node);
   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (pdata->filter.addr != 0) {
         trunk_dec_filter(spl, &pdata->filter);
      }
      for (uint16 branch_no = pdata->start_branch;
           branch_no != trunk_end_branch(spl, node);
           branch_no = trunk_add_branch_number(spl, branch_no, 1))
      {
         trunk_branch *branch    = trunk_get_branch(spl, node, branch_no);
         const char   *start_key = trunk_get_pivot(spl, node, pivot_no);
         const char   *end_key   = trunk_get_pivot(spl, node, pivot_no + 1);

         trunk_zap_branch_range(
            spl, branch, start_key, end_key, PAGE_TYPE_BRANCH);
      }
   }
   uint16 start_filter = trunk_start_sb_filter(spl, node);
   uint16 end_filter   = trunk_end_sb_filter(spl, node);
   for (uint16 filter_no = start_filter; filter_no != end_filter; filter_no++) {
      routing_filter *filter = trunk_get_sb_filter(spl, node, filter_no);
      trunk_dec_filter(spl, filter);
   }

   trunk_node_unlock(spl, node, ref, __LINE__);
   trunk_node_unclaim(spl, node);
   trunk_node_unget(spl, &node);
   return TRUE;
}

/*
 * Destroy a database such that it cannot be re-opened later
 */
void
trunk_destroy(trunk_handle *spl)
{
   srq_deinit(&spl->srq);

   trunk_prepare_for_shutdown(spl);

   trunk_for_each_node(spl, trunk_node_destroy, NULL);
   mini_unkeyed_dec_ref(spl->cc, spl->mini.meta_head, PAGE_TYPE_TRUNK, FALSE);

   // clear out this splinter table from the meta page.
   allocator_remove_super_addr(spl->al, spl->id);

   // destroy trunk update lock
   platform_mutex_destroy(&spl->update_lock);

   if (spl->cfg.use_stats) {
      for (uint64 i = 0; i < MAX_THREADS; i++) {
         platform_histo_destroy(spl->heap_id,
                                spl->stats[i].insert_latency_histo);
         platform_histo_destroy(spl->heap_id,
                                spl->stats[i].update_latency_histo);
         platform_histo_destroy(spl->heap_id,
                                spl->stats[i].delete_latency_histo);
      }
      platform_free(spl->heap_id, spl->stats);
   }

   // release the log
   if (spl->cfg.use_log) {
      platform_free(spl->heap_id, spl->log);
   }
   platform_free(spl->heap_id, spl);
}

/*
 * Close (dismount) a database without destroying it.
 * It can be re-opened later with trunk_mount().
 */
void
trunk_dismount(trunk_handle *spl)
{
   srq_deinit(&spl->srq);
   trunk_prepare_for_shutdown(spl);

   trunk_set_super_block(spl, FALSE, TRUE, FALSE);
   // destroy trunk update lock
   platform_mutex_destroy(&spl->update_lock);

   if (spl->cfg.use_stats) {
      for (uint64 i = 0; i < MAX_THREADS; i++) {
         platform_histo_destroy(spl->heap_id,
                                spl->stats[i].insert_latency_histo);
         platform_histo_destroy(spl->heap_id,
                                spl->stats[i].update_latency_histo);
         platform_histo_destroy(spl->heap_id,
                                spl->stats[i].delete_latency_histo);
      }
      platform_free(spl->heap_id, spl->stats);
   }
   platform_free(spl->heap_id, spl);
}

/*
 *-----------------------------------------------------------------------------
 * trunk_perform_task
 *
 *      do a batch of tasks
 *-----------------------------------------------------------------------------
 */
void
trunk_perform_tasks(trunk_handle *spl)
{
   task_perform_all(spl->ts);
   cache_cleanup(spl->cc);
}

/*
 *-----------------------------------------------------------------------------
 * Debugging and info functions
 *-----------------------------------------------------------------------------
 */


/*
 * verify_node checks that the node is valid in the following places:
 *    1. values in the trunk header
 *    2. pivots are coherent (in order)
 *    3. check tuple counts (index nodes only, leaves have estimates)
 *    4. bundles are coherent (subbundles are contiguous and non-overlapping)
 *    5. subbundles are coherent (branches are contiguous and non-overlapping)
 *    6. start_frac (resp end_branch) is first (resp last) branch in a subbundle
 */
bool
trunk_verify_node(trunk_handle *spl, page_handle *node)
{
   bool   is_valid = FALSE;
   uint64 addr     = node->disk_addr;

   // check values in trunk hdr (currently just num_pivot_keys)
   if (trunk_num_pivot_keys(spl, node) > spl->cfg.max_pivot_keys) {
      platform_error_log("trunk_verify: too many pivots\n");
      platform_error_log("addr: %lu\n", addr);
      goto out;
   }

   // check that pivots are coherent
   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      const char *pivot      = trunk_get_pivot(spl, node, pivot_no);
      const char *next_pivot = trunk_get_pivot(spl, node, pivot_no + 1);
      if (trunk_key_compare(spl, pivot, next_pivot) >= 0) {
         platform_error_log("trunk_verify: pivots out of order\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
   }
   // check that pivot generations are < hdr->pivot_generation
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (pdata->generation >= trunk_pivot_generation(spl, node)) {
         platform_error_log("trunk_verify: pivot generation out of bound\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
   }
   // check that pivot tuple counts are correct
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      uint64 tuple_count        = 0;
      uint64 kv_bytes           = 0;
      uint16 pivot_start_branch = trunk_pivot_start_branch(spl, node, pivot_no);
      for (uint16 branch_no = pivot_start_branch;
           branch_no != trunk_end_branch(spl, node);
           branch_no = trunk_add_branch_number(spl, branch_no, 1))
      {
         uint64 local_tuple_count = 0;
         uint64 local_kv_bytes    = 0;
         trunk_pivot_branch_tuple_counts(spl,
                                         node,
                                         pivot_no,
                                         branch_no,
                                         &local_tuple_count,
                                         &local_kv_bytes);
         tuple_count += local_tuple_count;
         kv_bytes += local_kv_bytes;
      }
      if (trunk_pivot_num_tuples(spl, node, pivot_no) != tuple_count) {
         platform_error_log("trunk_verify: pivot num tuples incorrect\n");
         platform_error_log("reported %lu, actual %lu\n",
                            trunk_pivot_num_tuples(spl, node, pivot_no),
                            tuple_count);
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
#if 0
      if (trunk_pivot_kv_bytes(spl, node, pivot_no) != kv_bytes) {
         platform_error_log("trunk_verify: pivot kv_bytes incorrect\n");
         platform_error_log("reported %lu, actual %lu\n",
                            trunk_pivot_kv_bytes(spl, node, pivot_no),
                            kv_bytes);
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
#endif
   }

   // check that tuple and kv_byte counts are either both 0 or both non-0
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      if ((trunk_pivot_num_tuples_whole(spl, node, pivot_no) == 0)
          != (trunk_pivot_kv_bytes_whole(spl, node, pivot_no) == 0))
      {
         platform_error_log("trunk_verify: whole branch num_tuples and "
                            "kv_bytes not both zero or non-zero\n");
         platform_error_log(
            "addr: %lu, pivot_no: %u, num_tuples: %lu, kv_bytes: %lu\n",
            addr,
            pivot_no,
            trunk_pivot_num_tuples_whole(spl, node, pivot_no),
            trunk_pivot_kv_bytes_whole(spl, node, pivot_no));
         goto out;
      }

      if ((trunk_pivot_num_tuples_bundle(spl, node, pivot_no) == 0)
          != (trunk_pivot_kv_bytes_bundle(spl, node, pivot_no) == 0))
      {
         platform_error_log("trunk_verify: bundle num_tuples and "
                            "kv_bytes not both zero or non-zero\n");
         platform_error_log(
            "addr: %lu, pivot_no: %u, num_tuples: %lu, kv_bytes: %lu\n",
            addr,
            pivot_no,
            trunk_pivot_num_tuples_bundle(spl, node, pivot_no),
            trunk_pivot_kv_bytes_bundle(spl, node, pivot_no));
         goto out;
      }
   }

   // check that pivot branches and bundles are valid
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (!trunk_branch_valid(spl, node, pdata->start_branch)) {
         platform_error_log("trunk_verify: invalid pivot start branch\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
      if (!trunk_bundle_valid(spl, node, pdata->start_bundle)) {
         platform_error_log("trunk_verify: invalid pivot start bundle\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
   }

   // check bundles are coherent
   trunk_bundle *last_bundle = NULL;
   for (uint16 bundle_no = trunk_start_bundle(spl, node);
        bundle_no != trunk_end_bundle(spl, node);
        bundle_no = trunk_add_bundle_number(spl, bundle_no, 1))
   {
      trunk_bundle *bundle = trunk_get_bundle(spl, node, bundle_no);
      if (bundle_no == trunk_start_bundle(spl, node)) {
         if (trunk_start_subbundle(spl, node) != bundle->start_subbundle) {
            platform_error_log("trunk_verify: start_subbundle mismatch\n");
            platform_error_log("addr: %lu\n", addr);
            goto out;
         }
      } else {
         if (last_bundle->end_subbundle != bundle->start_subbundle) {
            platform_error_log("trunk_verify: "
                               "bundles have mismatched subbundles\n");
            platform_error_log("addr: %lu, bundle_no=%d, last_bundle->end_subbundle=%d,  bundle->start_subbundle=%d\n",
                                  addr, bundle_no, last_bundle->end_subbundle, bundle->start_subbundle);
            goto out;
         }
      }
      if (bundle_no + 1 == trunk_end_bundle(spl, node)) {
         if (bundle->end_subbundle != trunk_end_subbundle(spl, node)) {
            platform_error_log("trunk_verify: end_subbundle mismatch\n");
            platform_error_log("addr: %lu\n", addr);
            goto out;
         }
      }
      if (bundle->start_subbundle == bundle->end_subbundle) {
         platform_error_log("trunk_verify: empty bundle\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }

      last_bundle = bundle;
   }

   // check subbundles are coherent
   trunk_subbundle *last_sb = NULL;
   for (uint16 sb_no = trunk_start_subbundle(spl, node);
        sb_no != trunk_end_subbundle(spl, node);
        sb_no = trunk_add_subbundle_number(spl, sb_no, 1))
   {
      trunk_subbundle *sb = trunk_get_subbundle(spl, node, sb_no);
      if (sb_no == trunk_start_subbundle(spl, node)) {
         if (sb->start_branch != trunk_start_frac_branch(spl, node)) {
            platform_error_log("trunk_verify: start_branch mismatch\n");
            platform_error_log("addr: %lu\n", addr);
            goto out;
         }
      } else {
         if (sb->start_branch != last_sb->end_branch) {
            platform_error_log("trunk_verify: "
                               "subbundles have mismatched branches\n");
            platform_error_log("addr: %lu\n", addr);
            goto out;
         }
      }
      if (sb_no + 1 == trunk_end_subbundle(spl, node)) {
         if (sb->end_branch != trunk_end_branch(spl, node)) {
            platform_error_log("trunk_verify: end_branch mismatch\n");
            platform_error_log("addr: %lu\n", addr);
            goto out;
         }
      }
      for (uint16 filter_no = sb->start_filter; filter_no != sb->end_filter;
           filter_no = trunk_add_subbundle_filter_number(spl, filter_no, 1))
      {
         if (!trunk_sb_filter_valid(spl, node, filter_no)) {
            platform_error_log("trunk_verify: invalid subbundle filter\n");
            platform_error_log(
               "sb_no: %u, filter_no: %u, start_filter: %u, end_filter: %u\n",
               sb_no,
               filter_no,
               trunk_start_sb_filter(spl, node),
               trunk_end_sb_filter(spl, node));
            platform_error_log("addr: %lu\n", addr);
            goto out;
         }
      }

      last_sb = sb;
   }

   // check that sb filters match in hdr and subbundles
   if (trunk_subbundle_count(spl, node) != 0) {
      uint16           hdr_sb_filter_start = trunk_start_sb_filter(spl, node);
      uint16           sb_start            = trunk_start_subbundle(spl, node);
      trunk_subbundle *sb = trunk_get_subbundle(spl, node, sb_start);
      uint16           subbundle_sb_filter_start = sb->start_filter;
      if (hdr_sb_filter_start != subbundle_sb_filter_start) {
         platform_error_log(
            "trunk_verify: header and subbundle start filters do not match\n");
         platform_error_log("header: %u, subbundle: %u\n",
                            hdr_sb_filter_start,
                            subbundle_sb_filter_start);
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }

      uint16 hdr_sb_filter_end = trunk_end_sb_filter(spl, node);
      uint16 sb_end            = trunk_end_subbundle(spl, node);
      uint16 sb_last = trunk_subtract_subbundle_number(spl, sb_end, 1);
      sb             = trunk_get_subbundle(spl, node, sb_last);
      uint16 subbundle_sb_filter_end = sb->end_filter;
      if (hdr_sb_filter_end != subbundle_sb_filter_end) {
         platform_error_log(
            "trunk_verify: header and subbundle end filters do not match\n");
         platform_error_log("header: %u, subbundle: %u\n",
                            hdr_sb_filter_end,
                            subbundle_sb_filter_end);
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
   } else {
      if (trunk_start_sb_filter(spl, node) != trunk_end_sb_filter(spl, node)) {
         platform_error_log(
            "trunk_verify: subbundle filters without subbundles\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
   }


   // check that pivot start branches and start bundles are coherent
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (!trunk_bundle_live(spl, node, pdata->start_bundle)) {
         if (1 && pdata->start_branch != trunk_end_branch(spl, node)
             && trunk_bundle_count(spl, node) != 0)
         {
            platform_error_log("trunk_verify: pivot start bundle doesn't "
                               "match start branch\n");
            platform_error_log("addr: %lu\n", addr);
            goto out;
         }
      } else {
         trunk_bundle *bundle =
            trunk_get_bundle(spl, node, pdata->start_bundle);
         trunk_subbundle *sb =
            trunk_get_subbundle(spl, node, bundle->start_subbundle);
         if (pdata->start_branch != sb->start_branch) {
            if (!trunk_branch_in_range(spl,
                                       pdata->start_branch,
                                       trunk_start_branch(spl, node),
                                       sb->start_branch))
            {
               platform_error_log("trunk_verify: pivot start branch out of "
                                  "order with bundle start branch\n");
               platform_error_log("addr: %lu\n", addr);
               goto out;
            }
            if (pdata->start_bundle != trunk_start_bundle(spl, node)) {
               platform_error_log("trunk_verify: pivot start bundle "
                                  "incoherent with start branch\n");
               platform_error_log("addr: %lu\n", addr);
               goto out;
            }
         }
      }
   }

   // check that each pivot with nontrivial compacted branches has a filter
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (trunk_pivot_num_tuples_whole(spl, node, pivot_no) != 0
          && pdata->filter.addr == 0)
      {
         platform_error_log(
            "trunk_verify: pivot with whole tuples doesn't have filter\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
      if (trunk_pivot_kv_bytes_whole(spl, node, pivot_no) != 0
          && pdata->filter.addr == 0)
      {
         platform_error_log(
            "trunk_verify: pivot with whole kv_bytes doesn't have filter\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
   }


   // check that leaves only have a single pivot
   if (trunk_height(spl, node) == 0) {
      if (trunk_num_children(spl, node) != 1) {
         platform_error_log("trunk_verify: leaf with multiple children\n");
         platform_error_log("addr: %lu\n", addr);
         goto out;
      }
   }

   is_valid = TRUE;
out:
   if (!is_valid) {
      trunk_print_locked_node(Platform_error_log_handle, spl, node);
   }
   return is_valid;
}


/*
 * Scratch space used with trunk_verify_node_with_neighbors to verify that
 * pivots are coherent across neighboring nodes
 */
typedef struct trunk_verify_scratch {
   char last_key_seen[TRUNK_MAX_HEIGHT][MAX_KEY_SIZE];
} trunk_verify_scratch;

/*
 * verify_node_with_neighbors checks that the node has:
 * 1. coherent max key with successor's min key
 * 2. coherent pivots with children's min/max keys
 */
bool
trunk_verify_node_with_neighbors(trunk_handle         *spl,
                                 page_handle          *node,
                                 trunk_verify_scratch *scratch)
{
   bool   is_valid = FALSE;
   uint64 addr     = node->disk_addr;

   uint16 height = trunk_height(spl, node);
   // check node and predescessor have coherent pivots
   if (!trunk_key_equal(
          spl, scratch->last_key_seen[height], trunk_min_key(spl, node)))
   {
      platform_default_log("trunk_verify_node_with_neighbors: mismatched "
                           "pivots with predescessor\n");
      platform_default_log(
         "predescessor max key: %s\n",
         key_string(
            trunk_data_config(spl),
            slice_create(trunk_key_size(spl), scratch->last_key_seen[height])));
      goto out;
   }
   // set last key seen in scratch
   trunk_key_copy(
      spl, scratch->last_key_seen[height], trunk_max_key(spl, node));

   // don't need to verify coherence with children if node is a leaf
   if (trunk_is_leaf(spl, node)) {
      is_valid = TRUE;
      goto out;
   }

   // check node and each child have coherent pivots
   uint16 num_children = trunk_num_children(spl, node);
   for (uint16 pivot_no = 0; pivot_no != num_children; pivot_no++) {
      trunk_pivot_data *pdata      = trunk_get_pivot_data(spl, node, pivot_no);
      uint64            child_addr = pdata->ref.addr;
      page_reference    ref        = pdata->ref;
      page_handle      *child      = trunk_node_get(spl, &ref);

      // check pivot == child min key
      const char *pivot         = trunk_get_pivot(spl, node, pivot_no);
      const char *child_min_key = trunk_min_key(spl, child);
      if (trunk_key_compare(spl, pivot, child_min_key) != 0) {
         platform_default_log("trunk_verify_node_with_neighbors: "
                              "mismatched pivot with child min key\n");
         platform_default_log("0x%016lx%016lx%016lx\n",
                              *((uint64 *)pivot),
                              *(((uint64 *)pivot) + 1),
                              *(((uint64 *)pivot) + 2));
         platform_default_log("0x%016lx%016lx%016lx\n",
                              *((uint64 *)child_min_key),
                              *(((uint64 *)child_min_key) + 1),
                              *(((uint64 *)child_min_key) + 2));

         platform_default_log("addr: %lu\n", addr);
         platform_default_log("child addr: %lu\n", child_addr);
         trunk_node_unget(spl, &child);
         goto out;
      }
      const char *next_pivot    = trunk_get_pivot(spl, node, pivot_no + 1);
      const char *child_max_key = trunk_max_key(spl, child);
      if (trunk_key_compare(spl, next_pivot, child_max_key) != 0) {
         platform_default_log("trunk_verify_node_with_neighbors: "
                              "mismatched pivot with child max key\n");
         platform_default_log("addr: %lu\n", addr);
         platform_default_log("child addr: %lu\n", child_addr);
         trunk_node_unget(spl, &child);
         goto out;
      }

      trunk_node_unget(spl, &child);
   }

   is_valid = TRUE;
out:
   if (!is_valid) {
      trunk_print_locked_node(Platform_default_log_handle, spl, node);
   }
   return is_valid;
}

/*
 * Wrapper for trunk_for_each_node
 */
bool
trunk_verify_node_and_neighbors(trunk_handle *spl, page_reference *ref, void *arg)
{
   page_handle *node     = trunk_node_get(spl, ref);
   bool         is_valid = trunk_verify_node(spl, node);
   if (!is_valid) {
      goto out;
   }
   trunk_verify_scratch *scratch = (trunk_verify_scratch *)arg;
   is_valid = trunk_verify_node_with_neighbors(spl, node, scratch);

out:
   trunk_node_unget(spl, &node);
   return is_valid;
}

/*
 * verify_tree verifies each node with itself and its neighbors
 */
bool
trunk_verify_tree(trunk_handle *spl)
{
   trunk_verify_scratch scratch = {0};
   for (uint64 h = 0; h < TRUNK_MAX_HEIGHT; h++) {
      trunk_key_copy(
         spl, scratch.last_key_seen[h], trunk_data_config(spl)->min_key);
   }
   return trunk_for_each_node(spl, trunk_verify_node_and_neighbors, &scratch);
}

/*
 * Returns the amount of space used by each level of the tree
 */
bool
trunk_node_space_use(trunk_handle *spl, page_reference *ref, void *arg)
{
   uint64      *bytes_used_on_level = (uint64 *)arg;
   uint64       bytes_used_in_node  = 0;
   page_handle *node                = trunk_node_get(spl, ref);
   uint16       num_pivot_keys      = trunk_num_pivot_keys(spl, node);
   uint16       num_children        = trunk_num_children(spl, node);
   for (uint16 branch_no = trunk_start_branch(spl, node);
        branch_no != trunk_end_branch(spl, node);
        branch_no = trunk_add_branch_number(spl, branch_no, 1))
   {
      trunk_branch *branch    = trunk_get_branch(spl, node, branch_no);
      char         *start_key = NULL;
      char         *end_key   = NULL;
      for (uint16 pivot_no = 0; pivot_no < num_pivot_keys; pivot_no++) {
         if (1 && pivot_no != num_children
             && trunk_branch_live_for_pivot(spl, node, branch_no, pivot_no))
         {
            if (start_key == NULL) {
               start_key = trunk_get_pivot(spl, node, pivot_no);
            }
         } else {
            if (start_key != NULL) {
               end_key = trunk_get_pivot(spl, node, pivot_no);
               uint64 bytes_used_in_branch_range =
                  btree_space_use_in_range(spl->cc,
                                           &spl->cfg.btree_cfg,
                                           branch->root_addr,
                                           PAGE_TYPE_BRANCH,
                                           trunk_key_slice(spl, start_key),
                                           trunk_key_slice(spl, end_key));
               bytes_used_in_node += bytes_used_in_branch_range;
            }
            start_key = NULL;
            end_key   = NULL;
         }
      }
   }

   uint16 height = trunk_height(spl, node);
   bytes_used_on_level[height] += bytes_used_in_node;
   trunk_node_unget(spl, &node);
   return TRUE;
}

void
trunk_print_space_use(platform_log_handle *log_handle, trunk_handle *spl)
{
   uint64 bytes_used_by_level[TRUNK_MAX_HEIGHT] = {0};
   trunk_for_each_node(spl, trunk_node_space_use, bytes_used_by_level);

   platform_log(log_handle, "Space used by level:\n");
   for (uint16 i = 0; i <= trunk_tree_height(spl); i++) {
      platform_log(
         log_handle, "%u: %8luMiB\n", i, B_TO_MiB(bytes_used_by_level[i]));
   }
   platform_log(log_handle, "\n");
}

// clang-format off
void
trunk_print_locked_node(platform_log_handle *log_handle,
                        trunk_handle        *spl,
                        page_handle         *node)
{
   uint16 height = trunk_height(spl, node);
   // clang-format off
   platform_log(log_handle, "---------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "|          |     addr      | height | pvt gen |                                       |\n");
   platform_log(log_handle, "|  HEADER  |---------------|--------|---------|---------|-----------------------------|\n");
   platform_log(log_handle, "|          | %12lu^ | %6u | %7lu |                                       |\n",
      node->disk_addr,
      height,
      trunk_pivot_generation(spl, node));
   platform_log(log_handle, "|-------------------------------------------------------------------------------------------------|\n");
   platform_log(log_handle, "|                                       PIVOTS                                                    |\n");
   platform_log(log_handle, "|-------------------------------------------------------------------------------------------------|\n");
   platform_log(log_handle, "|         pivot key        |  child addr  |  filter addr | tuple count | kv bytes |  srq  |  gen  |\n");
   platform_log(log_handle, "|--------------------------|--------------|--------------|-------------|----------|-------|-------|\n");
   // clang-format on
   for (uint16 pivot_no = 0; pivot_no < trunk_num_pivot_keys(spl, node);
        pivot_no++)
   {
      char key_string[128];
      trunk_key_to_string(
         spl, trunk_get_pivot(spl, node, pivot_no), key_string);
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      if (pivot_no == trunk_num_pivot_keys(spl, node) - 1) {
         platform_log(log_handle,
                      "| %24s | %12s | %12s | %11s | %8s | %5s | %5s |\n",
                      key_string,
                      "",
                      "",
                      "",
                      "",
                      "",
                      "");
      } else {
         platform_log(log_handle,
                      "| %24s | %12lu | %12lu | %11lu | %8lu | %5ld | %5lu |\n",
                      key_string,
                      pdata->ref.addr,
                      pdata->filter.addr,
                      pdata->num_tuples_whole + pdata->num_tuples_bundle,
                      pdata->num_kv_bytes_whole + pdata->num_kv_bytes_bundle,
                      pdata->srq_idx,
                      pdata->generation);
      }
   }
   // clang-format off
   platform_log(log_handle, "|-------------------------------------------------------------------------------------------------|\n");
   platform_log(log_handle, "|                              BRANCHES AND [SUB]BUNDLES                                          |\n");
   platform_log(log_handle, "|-------------------------------------------------------------------------------------------------|\n");
   platform_log(log_handle, "|   # |          point addr         | filter1 addr | filter2 addr | filter3 addr |                |\n");
   platform_log(log_handle, "|     |    pivot/bundle/subbundle   |  num tuples  |              |              |                |\n");
   platform_log(log_handle, "|-----|--------------|--------------|--------------|--------------|--------------|----------------|\n");
   // clang-format on
   uint16 start_branch = trunk_start_branch(spl, node);
   uint16 end_branch   = trunk_end_branch(spl, node);
   uint16 start_bundle = trunk_start_bundle(spl, node);
   uint16 end_bundle   = trunk_end_bundle(spl, node);
   uint16 start_sb     = trunk_start_subbundle(spl, node);
   uint16 end_sb       = trunk_end_subbundle(spl, node);
   for (uint16 branch_no = start_branch; branch_no != end_branch;
        branch_no        = trunk_add_branch_number(spl, branch_no, 1))
   {
      for (uint16 pivot_no = 0; pivot_no < trunk_num_children(spl, node);
           pivot_no++) {
         if (branch_no == trunk_pivot_start_branch(spl, node, pivot_no)) {
            // clang-format off
            platform_log(log_handle, "|     |        -- pivot %2u --       |              |              |              |                |\n",
                                pivot_no);
            // clang-format on
         }
      }
      for (uint16 bundle_no = start_bundle; bundle_no != end_bundle;
           bundle_no        = trunk_add_bundle_number(spl, bundle_no, 1))
      {
         trunk_bundle *bundle = trunk_get_bundle(spl, node, bundle_no);
         if (branch_no == trunk_bundle_start_branch(spl, node, bundle)) {
            // clang-format off
            platform_log(log_handle, "|     |       -- bundle %2u --       | %12lu |              |              |                |\n",
                                bundle_no,
                                bundle->num_tuples);
            // clang-format on
         }
      }
      for (uint16 sb_no = start_sb; sb_no != end_sb;
           sb_no        = trunk_add_subbundle_number(spl, sb_no, 1))
      {
         trunk_subbundle *sb = trunk_get_subbundle(spl, node, sb_no);
         if (branch_no == sb->start_branch) {
            uint16 filter_count = trunk_subbundle_filter_count(spl, node, sb);
            // clang-format off
            platform_log(log_handle,
               "|     |  -- %2scomp subbundle %2u --  | %12lu | %12lu | %12lu | %14s |\n",
               sb->state == SB_STATE_COMPACTED ? "" : "un",
               sb_no,
               0 < filter_count ? trunk_subbundle_filter(spl, node, sb, 0)->addr : 0,
               1 < filter_count ? trunk_subbundle_filter(spl, node, sb, 1)->addr : 0,
               2 < filter_count ? trunk_subbundle_filter(spl, node, sb, 2)->addr : 0,
               3 < filter_count ? " *" : "  ");
            // clang-format on
         }
      }

      trunk_branch *branch = trunk_get_branch(spl, node, branch_no);
      // clang-format off
      platform_log(log_handle, "| %3u |         %12lu        |              |              |              |                |\n",
                          branch_no,
                          branch->root_addr);
      // clang-format on
   }
   // clang-format off
   platform_log(log_handle, "---------------------------------------------------------------------------------------------------\n");
   // clang-format on
   platform_log(log_handle, "\n");
}
// clang-format on

void
trunk_print_node(platform_log_handle *log_handle,
                 trunk_handle        *spl,
                 page_reference      *ref)
{
   if (!cache_page_valid(spl->cc, ref)) {
      platform_log(log_handle, "*******************\n");
      platform_log(log_handle, "** INVALID NODE \n");
      platform_log(log_handle, "** addr: %lu \n", ref->addr);
      platform_log(log_handle, "-------------------\n");
      return;
   }

   page_handle *node = trunk_node_get(spl, ref);
   trunk_print_locked_node(log_handle, spl, node);
   cache_unget(spl->cc, node);
}

void
trunk_print_subtree(trunk_handle        *spl,
                    page_reference      *ref,
                    platform_log_handle *log_handle)
{
   trunk_print_node(log_handle, spl, ref);
   page_handle *node = trunk_node_get(spl, ref);
   trunk_hdr   *hdr  = (trunk_hdr *)node->data;

   if (hdr->height != 0) {
      for (uint32 i = 0; i < trunk_num_children(spl, node); i++) {
         trunk_pivot_data *data = trunk_get_pivot_data(spl, node, i);
         page_reference ref = data->ref;
         trunk_print_subtree(spl, &ref, log_handle);
      }
   }
   cache_unget(spl->cc, node);
}

void
trunk_print_memtable(trunk_handle *spl, platform_log_handle *log_handle)
{
   uint64 curr_memtable =
      memtable_generation(spl->mt_ctxt) % TRUNK_NUM_MEMTABLES;
   platform_log(log_handle, "&&&&&&&&&&&&&&&&&&&\n");
   platform_log(log_handle, "&&  MEMTABLES \n");
   platform_log(log_handle, "&&  curr: %lu\n", curr_memtable);
   platform_log(log_handle, "-------------------\n");

   uint64 mt_gen_start = memtable_generation(spl->mt_ctxt);
   uint64 mt_gen_end   = memtable_generation_retired(spl->mt_ctxt);
   for (uint64 mt_gen = mt_gen_start; mt_gen != mt_gen_end; mt_gen--) {
      memtable *mt = trunk_get_memtable(spl, mt_gen);
      platform_log(log_handle,
                   "%lu: gen %lu ref_count %u state %d\n",
                   mt_gen,
                   mt->root_addr,
                   allocator_get_ref(spl->al, mt->root_addr),
                   mt->state);
   }
   platform_log(log_handle, "\n");
}

void
trunk_print(platform_log_handle *log_handle, trunk_handle *spl)
{
   trunk_print_memtable(spl, log_handle);
   trunk_print_subtree(spl, &spl->root_ref, log_handle);
}

// clang-format off
void
trunk_print_insertion_stats(platform_log_handle *log_handle, trunk_handle *spl)
{
   if (!spl->cfg.use_stats) {
      platform_log(log_handle, "Statistics are not enabled\n");
      return;
   }
   uint64 avg_flush_wait_time, avg_flush_time, num_flushes;
   uint64 avg_compaction_tuples, pack_time_per_tuple, avg_setup_time;
   fraction  avg_leaves_created;
   uint64 avg_filter_tuples, avg_filter_time, filter_time_per_tuple;
   uint32 h, rev_h;
   threadid thr_i;
   page_handle *node = trunk_node_get(spl, &spl->root_ref);
   uint32 height = trunk_height(spl, node);
   trunk_node_unget(spl, &node);

   trunk_stats *global;

   global = TYPED_ZALLOC(spl->heap_id, global);
   if (global == NULL) {
      platform_error_log("Out of memory for statistics");
      return;
   }

   platform_histo_handle insert_lat_accum, update_lat_accum, delete_lat_accum;
   platform_histo_create(spl->heap_id,
                         LATENCYHISTO_SIZE + 1,
                         latency_histo_buckets,
                         &insert_lat_accum);
   platform_histo_create(spl->heap_id,
                         LATENCYHISTO_SIZE + 1,
                         latency_histo_buckets,
                         &update_lat_accum);
   platform_histo_create(spl->heap_id,
                         LATENCYHISTO_SIZE + 1,
                         latency_histo_buckets,
                         &delete_lat_accum);

   for (thr_i = 0; thr_i < MAX_THREADS; thr_i++) {
      platform_histo_merge_in(insert_lat_accum,
                              spl->stats[thr_i].insert_latency_histo);
      platform_histo_merge_in(update_lat_accum,
                              spl->stats[thr_i].update_latency_histo);
      platform_histo_merge_in(delete_lat_accum,
                              spl->stats[thr_i].delete_latency_histo);
      for (h = 0; h <= height; h++) {
         global->flush_wait_time_ns[h]               += spl->stats[thr_i].flush_wait_time_ns[h];
         global->flush_time_ns[h]                    += spl->stats[thr_i].flush_time_ns[h];
         if (spl->stats[thr_i].flush_time_max_ns[h] >
             global->flush_time_max_ns[h]) {
            global->flush_time_max_ns[h] =
               spl->stats[thr_i].flush_time_max_ns[h];
         }
         global->full_flushes[h]                     += spl->stats[thr_i].full_flushes[h];
         global->count_flushes[h]                    += spl->stats[thr_i].count_flushes[h];

         global->compactions[h]                      += spl->stats[thr_i].compactions[h];
         global->compactions_aborted_flushed[h]      += spl->stats[thr_i].compactions_aborted_flushed[h];
         global->compactions_aborted_leaf_split[h]   += spl->stats[thr_i].compactions_aborted_leaf_split[h];
         global->compactions_discarded_flushed[h]    += spl->stats[thr_i].compactions_discarded_flushed[h];
         global->compactions_discarded_leaf_split[h] += spl->stats[thr_i].compactions_discarded_leaf_split[h];
         global->compactions_empty[h]                += spl->stats[thr_i].compactions_empty[h];
         global->compaction_tuples[h]                += spl->stats[thr_i].compaction_tuples[h];
         if (spl->stats[thr_i].compaction_max_tuples[h] > global->compaction_max_tuples[h]) {
            global->compaction_max_tuples[h] = spl->stats[thr_i].compaction_max_tuples[h];
         }
         global->compaction_time_ns[h]               += spl->stats[thr_i].compaction_time_ns[h];
         global->compaction_time_wasted_ns[h]        += spl->stats[thr_i].compaction_time_wasted_ns[h];
         global->compaction_pack_time_ns[h]          += spl->stats[thr_i].compaction_pack_time_ns[h];
         if (spl->stats[thr_i].compaction_time_max_ns[h] >
             global->compaction_time_max_ns[h]) {
            global->compaction_time_max_ns[h] =
               spl->stats[thr_i].compaction_time_max_ns[h];
         }
         global->root_compactions                    += spl->stats[thr_i].root_compactions;
         global->root_compaction_pack_time_ns        += spl->stats[thr_i].root_compaction_pack_time_ns;
         global->root_compaction_tuples              += spl->stats[thr_i].root_compaction_tuples;
         if (spl->stats[thr_i].root_compaction_max_tuples >
               global->root_compaction_max_tuples) {
            global->root_compaction_max_tuples =
               spl->stats[thr_i].root_compaction_max_tuples;
         }
         global->root_compaction_time_ns             += spl->stats[thr_i].root_compaction_time_ns;
         if (spl->stats[thr_i].root_compaction_time_max_ns >
               global->root_compaction_time_max_ns) {
            global->root_compaction_time_max_ns =
               spl->stats[thr_i].root_compaction_time_max_ns;
         }

         global->filters_built[h]                    += spl->stats[thr_i].filters_built[h];
         global->filter_tuples[h]                    += spl->stats[thr_i].filter_tuples[h];
         global->filter_time_ns[h]                   += spl->stats[thr_i].filter_time_ns[h];

         global->space_recs[h]                       += spl->stats[thr_i].space_recs[h];
         global->space_rec_time_ns[h]                += spl->stats[thr_i].space_rec_time_ns[h];
         global->space_rec_tuples_reclaimed[h]       += spl->stats[thr_i].space_rec_tuples_reclaimed[h];
         global->tuples_reclaimed[h]                 += spl->stats[thr_i].tuples_reclaimed[h];
      }
      global->insertions                  += spl->stats[thr_i].insertions;
      global->updates                     += spl->stats[thr_i].updates;
      global->deletions                   += spl->stats[thr_i].deletions;
      global->discarded_deletes           += spl->stats[thr_i].discarded_deletes;

      global->memtable_flushes            += spl->stats[thr_i].memtable_flushes;
      global->memtable_flush_wait_time_ns += spl->stats[thr_i].memtable_flush_wait_time_ns;
      global->memtable_flush_time_ns      += spl->stats[thr_i].memtable_flush_time_ns;
      if (spl->stats[thr_i].memtable_flush_time_max_ns >
          global->memtable_flush_time_max_ns) {
         global->memtable_flush_time_max_ns =
            spl->stats[thr_i].memtable_flush_time_max_ns;
      }
      global->memtable_flush_root_full    += spl->stats[thr_i].memtable_flush_root_full;
      global->root_full_flushes           += spl->stats[thr_i].root_full_flushes;
      global->root_count_flushes          += spl->stats[thr_i].root_count_flushes;
      global->root_flush_time_ns          += spl->stats[thr_i].root_flush_time_ns;
      if (spl->stats[thr_i].root_flush_time_max_ns >
          global->root_flush_time_max_ns) {
         global->root_flush_time_max_ns =
            spl->stats[thr_i].root_flush_time_max_ns;
      }
      global->root_flush_wait_time_ns     += spl->stats[thr_i].root_flush_wait_time_ns;
      global->index_splits                += spl->stats[thr_i].index_splits;

      global->leaf_splits                 += spl->stats[thr_i].leaf_splits;
      global->leaf_splits_leaves_created  += spl->stats[thr_i].leaf_splits_leaves_created;
      global->leaf_split_time_ns          += spl->stats[thr_i].leaf_split_time_ns;
      if (spl->stats[thr_i].leaf_split_max_time_ns >
            global->leaf_split_max_time_ns) {
         global->leaf_split_max_time_ns =
            spl->stats[thr_i].leaf_split_max_time_ns;
      }

      global->single_leaf_splits          += spl->stats[thr_i].single_leaf_splits;
      global->single_leaf_tuples          += spl->stats[thr_i].single_leaf_tuples;
      if (spl->stats[thr_i].single_leaf_max_tuples >
            global->single_leaf_max_tuples) {
         global->single_leaf_max_tuples = spl->stats[thr_i].single_leaf_max_tuples;
      }

      global->root_filters_built          += spl->stats[thr_i].root_filters_built;
      global->root_filter_tuples          += spl->stats[thr_i].root_filter_tuples;
      global->root_filter_time_ns         += spl->stats[thr_i].root_filter_time_ns;
   }

   platform_log(log_handle, "Overall Statistics\n");
   platform_log(log_handle, "------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "| height:            %10u\n", height);
   platform_log(log_handle, "| index nodes:       %10lu\n", global->index_splits + 1);
   platform_log(log_handle, "| leaves:            %10lu\n", global->leaf_splits_leaves_created + 1);
   platform_log(log_handle, "| insertions:        %10lu\n", global->insertions);
   platform_log(log_handle, "| updates:           %10lu\n", global->updates);
   platform_log(log_handle, "| deletions:         %10lu\n", global->deletions);
   platform_log(log_handle, "| completed deletes: %10lu\n", global->discarded_deletes);
   platform_log(log_handle, "------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "| root stalls:       %10lu\n", global->memtable_flush_root_full);
   platform_log(log_handle, "------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "\n");

   platform_log(log_handle, "Latency Histogram Statistics\n");
   platform_histo_print(insert_lat_accum, "Insert Latency Histogram (ns):", log_handle);
   platform_histo_print(update_lat_accum, "Update Latency Histogram (ns):", log_handle);
   platform_histo_print(delete_lat_accum, "Delete Latency Histogram (ns):", log_handle);
   platform_histo_destroy(spl->heap_id, insert_lat_accum);
   platform_histo_destroy(spl->heap_id, update_lat_accum);
   platform_histo_destroy(spl->heap_id, delete_lat_accum);


   platform_log(log_handle, "Flush Statistics\n");
   platform_log(log_handle, "---------------------------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "  height | avg wait time (ns) | avg flush time (ns) | max flush time (ns) | full flushes | count flushes |\n");
   platform_log(log_handle, "---------|--------------------|---------------------|---------------------|--------------|---------------|\n");

   // memtable
   num_flushes = global->memtable_flushes;
   avg_flush_wait_time = num_flushes == 0 ? 0 : global->memtable_flush_wait_time_ns / num_flushes;
   avg_flush_time = num_flushes == 0 ? 0 : global->memtable_flush_time_ns / num_flushes;
   platform_log(log_handle, "memtable | %18lu | %19lu | %19lu | %12lu | %13lu |\n",
                avg_flush_wait_time, avg_flush_time,
                global->memtable_flush_time_max_ns, num_flushes, 0UL);

   // root
   num_flushes = global->root_full_flushes + global->root_count_flushes;
   avg_flush_wait_time = num_flushes == 0 ? 0 : global->root_flush_wait_time_ns / num_flushes;
   avg_flush_time = num_flushes == 0 ? 0 : global->root_flush_time_ns / num_flushes;
   platform_log(log_handle, "    root | %18lu | %19lu | %19lu | %12lu | %13lu |\n",
                avg_flush_wait_time, avg_flush_time,
                global->root_flush_time_max_ns,
                global->root_full_flushes, global->root_count_flushes);

   for (h = 1; h < height; h++) {
      rev_h = height - h;
      num_flushes = global->full_flushes[rev_h] + global->count_flushes[rev_h];
      avg_flush_wait_time = num_flushes == 0 ? 0 : global->flush_wait_time_ns[rev_h] / num_flushes;
      avg_flush_time = num_flushes == 0 ? 0 : global->flush_time_ns[rev_h] / num_flushes;
      platform_log(log_handle, "%8u | %18lu | %19lu | %19lu | %12lu | %13lu |\n",
                   rev_h, avg_flush_wait_time, avg_flush_time,
                   global->flush_time_max_ns[rev_h],
                   global->full_flushes[rev_h], global->count_flushes[rev_h]);
   }
   platform_log(log_handle, "---------------------------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "\n");

   platform_log(log_handle, "Compaction Statistics\n");
   platform_log(log_handle, "------------------------------------------------------------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "  height | compactions | avg setup time (ns) | time / tuple (ns) | avg tuples | max tuples | max time (ns) | empty | aborted | discarded |\n");
   platform_log(log_handle, "---------|-------------|---------------------|-------------------|------------|------------|---------------|-------|---------|-----------|\n");

   avg_setup_time = global->root_compactions == 0 ? 0
      : (global->root_compaction_time_ns - global->root_compaction_pack_time_ns)
            / global->root_compactions;
   avg_compaction_tuples = global->root_compactions == 0 ? 0
      : global->root_compaction_tuples / global->root_compactions;
   pack_time_per_tuple = global->root_compaction_tuples == 0 ? 0
      : global->root_compaction_pack_time_ns / global->root_compaction_tuples;
   platform_log(log_handle, "    root | %11lu | %19lu | %17lu | %10lu | %10lu | %13lu | %5lu | %2lu | %2lu | %3lu | %3lu |\n",
         global->root_compactions, avg_setup_time, pack_time_per_tuple,
         avg_compaction_tuples, global->root_compaction_max_tuples,
         global->root_compaction_time_max_ns, 0UL, 0UL, 0UL, 0UL, 0UL);
   for (h = 1; h <= height; h++) {
      rev_h = height - h;
      avg_setup_time = global->compactions[rev_h] == 0 ? 0
         : (global->compaction_time_ns[rev_h] + global->compaction_time_wasted_ns[rev_h]
               - global->compaction_pack_time_ns[rev_h])
               / global->compactions[rev_h];
      avg_compaction_tuples = global->compactions[rev_h] == 0 ? 0
         : global->compaction_tuples[rev_h] / global->compactions[rev_h];
      pack_time_per_tuple = global->compaction_tuples[rev_h] == 0 ? 0
         : global->compaction_pack_time_ns[rev_h] / global->compaction_tuples[rev_h];
      platform_log(log_handle, "%8u | %11lu | %19lu | %17lu | %10lu | %10lu | %13lu | %5lu | %2lu | %2lu | %3lu | %3lu |\n",
            rev_h, global->compactions[rev_h], avg_setup_time, pack_time_per_tuple,
            avg_compaction_tuples, global->compaction_max_tuples[rev_h],
            global->compaction_time_max_ns[rev_h], global->compactions_empty[rev_h],
            global->compactions_aborted_flushed[rev_h], global->compactions_aborted_leaf_split[rev_h],
            global->compactions_discarded_flushed[rev_h], global->compactions_discarded_leaf_split[rev_h]);
   }
   platform_log(log_handle, "------------------------------------------------------------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "\n");

   if (global->leaf_splits == 0) {
      avg_leaves_created = zero_fraction;
   } else {
      avg_leaves_created = init_fraction(
            global->leaf_splits_leaves_created + global->leaf_splits,
            global->leaf_splits
      );
   }
   uint64 leaf_avg_split_time = global->leaf_splits == 0 ? 0
      : global->leaf_split_time_ns / global->leaf_splits;
   uint64 single_leaf_avg_tuples = global->single_leaf_splits == 0 ? 0 :
      global->single_leaf_tuples / global->single_leaf_splits;

   platform_log(log_handle, "Leaf Split Statistics\n");
   platform_log(log_handle, "--------------------------------------------------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "| leaf splits | avg leaves created | avg split time (ns) | max split time (ns) | single splits | ss avg tuples | ss max tuples |\n");
   platform_log(log_handle, "--------------|--------------------|---------------------|---------------------|---------------|---------------|---------------|\n");
   platform_log(log_handle, "| %11lu | "FRACTION_FMT(18, 2)" | %19lu | %19lu | %13lu | %13lu | %13lu |\n",
         global->leaf_splits, FRACTION_ARGS(avg_leaves_created),
         leaf_avg_split_time, global->leaf_split_max_time_ns,
         global->single_leaf_splits, single_leaf_avg_tuples,
         global->single_leaf_max_tuples);
   platform_log(log_handle, "-------------------------------------------------------------------------------------------------------------------------------|\n");
   platform_log(log_handle, "\n");

   platform_log(log_handle, "Filter Build Statistics\n");
   platform_log(log_handle, "---------------------------------------------------------------------------------\n");
   platform_log(log_handle, "| height |   built | avg tuples | avg build time (ns) | build_time / tuple (ns) |\n");
   platform_log(log_handle, "---------|---------|------------|---------------------|-------------------------|\n");

   avg_filter_tuples = global->root_filters_built == 0 ? 0 :
      global->root_filter_tuples / global->root_filters_built;
   avg_filter_time = global->root_filters_built == 0 ? 0 :
      global->root_filter_time_ns / global->root_filters_built;
   filter_time_per_tuple = global->root_filter_tuples == 0 ? 0 :
      global->root_filter_time_ns / global->root_filter_tuples;

   platform_log(log_handle, "|   root | %7lu | %10lu | %19lu | %23lu |\n",
         global->root_filters_built, avg_filter_tuples,
         avg_filter_time, filter_time_per_tuple);
   for (h = 1; h <= height; h++) {
      rev_h = height - h;
      avg_filter_tuples = global->filters_built[rev_h] == 0 ? 0 :
         global->filter_tuples[rev_h] / global->filters_built[rev_h];
      avg_filter_time = global->filters_built[rev_h] == 0 ? 0 :
         global->filter_time_ns[rev_h] / global->filters_built[rev_h];
      filter_time_per_tuple = global->filter_tuples[rev_h] == 0 ? 0 :
         global->filter_time_ns[rev_h] / global->filter_tuples[rev_h];
      platform_log(log_handle, "| %6u | %7lu | %10lu | %19lu | %23lu |\n",
            rev_h, global->filters_built[rev_h], avg_filter_tuples,
            avg_filter_time, filter_time_per_tuple);
   }
   platform_log(log_handle, "--------------------------------------------------------------------------------|\n");
   platform_log(log_handle, "\n");

   platform_log(log_handle, "Space Reclamation Statistics\n");
   platform_log(log_handle, "------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "| height | space recs | tuples reclaimed in sr | tuples reclaimed | tuples per rec |\n");
   platform_log(log_handle, "|--------|------------|------------------------|------------------|----------------|\n");

   for (h = 1; h <= height; h++) {
      rev_h = height - h;
      uint64 avg_tuples_per_sr = global->space_recs[rev_h] == 0 ?
         0 : global->space_rec_tuples_reclaimed[rev_h] / global->space_recs[rev_h];
      platform_log(log_handle, "| %6u | %10lu | %22lu | %16lu | %14lu |\n",
            rev_h, global->space_recs[rev_h],
            global->space_rec_tuples_reclaimed[rev_h],
            global->tuples_reclaimed[rev_h], avg_tuples_per_sr);
   }
   platform_log(log_handle, "------------------------------------------------------------------------------------\n");
   task_print_stats(spl->ts);
   platform_log(log_handle, "\n");
   platform_free(spl->heap_id, global);
}

void
trunk_print_lookup_stats(platform_log_handle *log_handle, trunk_handle *spl)
{
   if (!spl->cfg.use_stats) {
      platform_log(log_handle, "Statistics are not enabled\n");
      return;
   }

   threadid thr_i;
   uint32 h, rev_h;
   uint64 lookups;
   fraction avg_filter_lookups, avg_filter_false_positives, avg_branch_lookups;
   page_handle *node = trunk_node_get(spl, &spl->root_ref);
   uint32 height = trunk_height(spl, node);
   trunk_node_unget(spl, &node);

   trunk_stats *global;

   global = TYPED_ZALLOC(spl->heap_id, global);
   if (global == NULL) {
      platform_error_log("Out of memory for stats\n");
      return;
   }

   for (thr_i = 0; thr_i < MAX_THREADS; thr_i++) {
      for (h = 0; h <= height; h++) {
         global->filter_lookups[h]         += spl->stats[thr_i].filter_lookups[h];
         global->branch_lookups[h]         += spl->stats[thr_i].branch_lookups[h];
         global->filter_false_positives[h] += spl->stats[thr_i].filter_false_positives[h];
         global->filter_negatives[h]       += spl->stats[thr_i].filter_negatives[h];
      }
      global->lookups_found     += spl->stats[thr_i].lookups_found;
      global->lookups_not_found += spl->stats[thr_i].lookups_not_found;
   }
   lookups = global->lookups_found + global->lookups_not_found;

   platform_log(log_handle, "Overall Statistics\n");
   platform_log(log_handle, "-----------------------------------------------------------------------------------\n");
   platform_log(log_handle, "| height:            %u\n", height);
   platform_log(log_handle, "| lookups:           %lu\n", lookups);
   platform_log(log_handle, "| lookups found:     %lu\n", global->lookups_found);
   platform_log(log_handle, "| lookups not found: %lu\n", global->lookups_not_found);
   platform_log(log_handle, "-----------------------------------------------------------------------------------\n");
   platform_log(log_handle, "\n");

   platform_log(log_handle, "Filter/Branch Statistics\n");
   platform_log(log_handle, "-------------------------------------------------------------------------------------\n");
   platform_log(log_handle, "height   | avg filter lookups | avg false pos | false pos rate | avg branch lookups |\n");
   platform_log(log_handle, "---------|--------------------|---------------|----------------|--------------------|\n");

   for (h = 0; h <= height; h++) {
      rev_h = height - h;
      if (lookups == 0) {
         avg_filter_lookups = zero_fraction;
         avg_filter_false_positives = zero_fraction;
         avg_branch_lookups = zero_fraction;
      } else {
         avg_filter_lookups =
            init_fraction(global->filter_lookups[rev_h], lookups);
         avg_filter_false_positives =
            init_fraction(global->filter_false_positives[rev_h], lookups);
         avg_branch_lookups = init_fraction(global->branch_lookups[rev_h],
                                            lookups);
      }

      uint64 filter_negatives = global->filter_lookups[rev_h];
      fraction false_positives_in_revision;
      if (filter_negatives == 0) {
         false_positives_in_revision = zero_fraction;
      } else {
         false_positives_in_revision =
         init_fraction(global->filter_false_positives[rev_h],
                       filter_negatives);
      }
      platform_log(log_handle, "%8u | "FRACTION_FMT(18, 2)" | "FRACTION_FMT(13, 4)" | "
                   FRACTION_FMT(14, 4)" | "FRACTION_FMT(18, 4)"\n",
                   rev_h, FRACTION_ARGS(avg_filter_lookups),
                   FRACTION_ARGS(avg_filter_false_positives),
                   FRACTION_ARGS(false_positives_in_revision),
                   FRACTION_ARGS(avg_branch_lookups));
   }
   platform_log(log_handle, "------------------------------------------------------------------------------------|\n");
   platform_log(log_handle, "\n");
   platform_free(spl->heap_id, global);
}
// clang-format on


void
trunk_print_lookup(trunk_handle        *spl,
                   const char          *key,
                   platform_log_handle *log_handle)
{
   merge_accumulator data;
   merge_accumulator_init(&data, spl->heap_id);

   platform_stream_handle stream;
   platform_open_log_stream(&stream);
   uint64 mt_gen_start = memtable_generation(spl->mt_ctxt);
   uint64 mt_gen_end   = memtable_generation_retired(spl->mt_ctxt);
   for (uint64 mt_gen = mt_gen_start; mt_gen != mt_gen_end; mt_gen--) {
      bool   memtable_is_compacted;
      page_reference root_ref;
      uint64 root_addr = trunk_memtable_root_addr_for_lookup(
         spl, mt_gen, &memtable_is_compacted, root_ref.hash);
      root_ref.addr = root_addr;
      platform_status rc;
      rc = btree_lookup(spl->cc,
                        &spl->cfg.btree_cfg,
                        &root_ref,
                        PAGE_TYPE_MEMTABLE,
                        trunk_key_slice(spl, key),
                        &data);
      platform_assert_status_ok(rc);
      if (!merge_accumulator_is_null(&data)) {
         char    key_str[128];
         char    message_str[128];
         message msg = merge_accumulator_to_message(&data);
         trunk_key_to_string(spl, key, key_str);
         trunk_message_to_string(spl, msg, message_str);
         platform_log_stream(
            &stream,
            "Key %s found in memtable %lu (gen %lu comp %d) with data %s\n",
            key_str,
            root_addr,
            mt_gen,
            memtable_is_compacted,
            message_str);
         btree_print_lookup(spl->cc,
                            &spl->cfg.btree_cfg,
                            root_addr,
                            PAGE_TYPE_MEMTABLE,
                            trunk_key_slice(spl, key));
      }
   }

   page_handle *node   = trunk_node_get(spl, &spl->root_ref);
   uint16       height = trunk_height(spl, node);
   for (uint16 h = height; h > 0; h--) {
      trunk_print_locked_node(Platform_default_log_handle, spl, node);
      uint16 pivot_no = trunk_find_pivot(spl, node, key, less_than_or_equal);
      debug_assert(pivot_no < trunk_num_children(spl, node));
      trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, pivot_no);
      merge_accumulator_set_to_null(&data);
      trunk_pivot_lookup(spl, node, pdata, key, &data);
      if (!merge_accumulator_is_null(&data)) {
         char key_str[128];
         char message_str[128];
         trunk_key_to_string(spl, key, key_str);
         message msg = merge_accumulator_to_message(&data);
         trunk_message_to_string(spl, msg, message_str);
         platform_log_stream(&stream,
                             "Key %s found in node %lu pivot %u with data %s\n",
                             key_str,
                             node->disk_addr,
                             pivot_no,
                             message_str);
      } else {
         for (uint16 branch_no = pdata->start_branch;
              branch_no != trunk_end_branch(spl, node);
              branch_no = trunk_add_branch_number(spl, branch_no, 1))
         {
            trunk_branch   *branch = trunk_get_branch(spl, node, branch_no);
            platform_status rc;
            bool            local_found;
            merge_accumulator_set_to_null(&data);
            rc = trunk_btree_lookup_and_merge(
               spl, branch, key, &data, &local_found);
            platform_assert_status_ok(rc);
            if (local_found) {
               char key_str[128];
               char message_str[128];
               trunk_key_to_string(spl, key, key_str);
               message msg = merge_accumulator_to_message(&data);
               trunk_message_to_string(spl, msg, message_str);
               platform_log_stream(
                  &stream,
                  "!! Key %s found in branch %u of node %lu pivot %u "
                  "with data %s\n",
                  key_str,
                  branch_no,
                  node->disk_addr,
                  pivot_no,
                  message_str);
            }
         }
      }
      page_reference ref = pdata->ref;
      page_handle *child = trunk_node_get(spl, &ref);
      trunk_node_unget(spl, &node);
      node = child;
   }

   // look in leaf
   trunk_print_locked_node(Platform_default_log_handle, spl, node);
   trunk_pivot_data *pdata = trunk_get_pivot_data(spl, node, 0);
   merge_accumulator_set_to_null(&data);
   trunk_pivot_lookup(spl, node, pdata, key, &data);
   if (!merge_accumulator_is_null(&data)) {
      char key_str[128];
      char message_str[128];
      trunk_key_to_string(spl, key, key_str);
      message msg = merge_accumulator_to_message(&data);
      trunk_message_to_string(spl, msg, message_str);
      platform_log_stream(&stream,
                          "Key %s found in node %lu pivot %u with data %s\n",
                          key_str,
                          node->disk_addr,
                          0,
                          message_str);
   } else {
      for (uint16 branch_no = pdata->start_branch;
           branch_no != trunk_end_branch(spl, node);
           branch_no = trunk_add_branch_number(spl, branch_no, 1))
      {
         trunk_branch   *branch = trunk_get_branch(spl, node, branch_no);
         platform_status rc;
         bool            local_found;
         merge_accumulator_set_to_null(&data);
         rc =
            trunk_btree_lookup_and_merge(spl, branch, key, &data, &local_found);
         platform_assert_status_ok(rc);
         if (local_found) {
            char key_str[128];
            char message_str[128];
            trunk_key_to_string(spl, key, key_str);
            message msg = merge_accumulator_to_message(&data);
            trunk_message_to_string(spl, msg, message_str);
            platform_log_stream(
               &stream,
               "!! Key %s found in branch %u of node %lu pivot %u "
               "with data %s\n",
               key_str,
               branch_no,
               node->disk_addr,
               0,
               message_str);
         }
      }
   }
   trunk_node_unget(spl, &node);
   merge_accumulator_deinit(&data);
   platform_close_log_stream(&stream, Platform_default_log_handle);
}

void
trunk_reset_stats(trunk_handle *spl)
{
   if (spl->cfg.use_stats) {
      memset(spl->stats, 0, MAX_THREADS * sizeof(trunk_stats));
   }
}

void
trunk_branch_count_num_tuples(trunk_handle *spl,
                              page_handle  *node,
                              uint16        branch_no,
                              uint64       *num_tuples,
                              uint64       *kv_bytes)
{
   uint16 num_children = trunk_num_children(spl, node);
   *num_tuples         = 0;
   *kv_bytes           = 0;
   for (uint16 pivot_no = 0; pivot_no < num_children; pivot_no++) {
      if (trunk_branch_live_for_pivot(spl, node, branch_no, pivot_no)) {
         uint64 local_num_tuples;
         uint64 local_kv_bytes;
         trunk_pivot_branch_tuple_counts(
            spl, node, pivot_no, branch_no, &local_num_tuples, &local_kv_bytes);
         *num_tuples += local_num_tuples;
         *kv_bytes += local_kv_bytes;
      }
   }
}

bool
trunk_node_print_branches(trunk_handle *spl, page_reference *ref, void *arg)
{
   platform_log_handle *log_handle = (platform_log_handle *)arg;
   page_handle         *node       = trunk_node_get(spl, ref);

   platform_log(
      log_handle,
      "------------------------------------------------------------------\n");
   platform_log(
      log_handle, "| node %12lu height %u\n", ref->addr, trunk_height(spl, node));
   platform_log(
      log_handle,
      "------------------------------------------------------------------\n");
   uint16 num_pivot_keys = trunk_num_pivot_keys(spl, node);
   platform_log(log_handle, "| pivots:\n");
   for (uint16 pivot_no = 0; pivot_no < num_pivot_keys; pivot_no++) {
      char key_str[128];
      trunk_key_to_string(spl, trunk_get_pivot(spl, node, pivot_no), key_str);
      platform_log(log_handle, "| %u: %s\n", pivot_no, key_str);
   }

   // clang-format off
   platform_log(log_handle,
         "-----------------------------------------------------------------------------------\n");
   platform_log(log_handle,
         "| branch |     addr     |  num tuples  | num kv bytes |    space    |  space amp  |\n");
   platform_log(log_handle,
         "-----------------------------------------------------------------------------------\n");
   // clang-format on
   uint16 start_branch = trunk_start_branch(spl, node);
   uint16 end_branch   = trunk_end_branch(spl, node);
   for (uint16 branch_no = start_branch; branch_no != end_branch;
        branch_no        = trunk_add_branch_number(spl, branch_no, 1))
   {
      uint64 addr = trunk_get_branch(spl, node, branch_no)->root_addr;
      uint64 num_tuples_in_branch;
      uint64 kv_bytes_in_branch;
      trunk_branch_count_num_tuples(
         spl, node, branch_no, &num_tuples_in_branch, &kv_bytes_in_branch);
      uint64 kib_in_branch = 0;
      // trunk_branch_extent_count(spl, node, branch_no);
      kib_in_branch *= trunk_extent_size(&spl->cfg) / 1024;
      fraction space_amp =
         init_fraction(kib_in_branch * 1024, kv_bytes_in_branch);
      platform_log(
         log_handle,
         "| %6u | %12lu | %12lu | %9luKiB | %8luKiB |   " FRACTION_FMT(
            2, 2) "   |\n",
         branch_no,
         addr,
         num_tuples_in_branch,
         kv_bytes_in_branch / 1024,
         kib_in_branch,
         FRACTION_ARGS(space_amp));
   }
   platform_log(
      log_handle,
      "------------------------------------------------------------------\n");
   platform_log(log_handle, "\n");
   trunk_node_unget(spl, &node);
   return TRUE;
}

void
trunk_print_branches(platform_log_handle *log_handle, trunk_handle *spl)
{
   trunk_for_each_node(spl, trunk_node_print_branches, log_handle);
}

// bool
// trunk_node_print_extent_count(trunk_handle *spl,
//                                 uint64           addr,
//                                 void            *arg)
//{
//   page_handle *node = trunk_node_get(spl, addr);
//
//   uint16 start_branch = trunk_start_branch(spl, node);
//   uint16 end_branch = trunk_end_branch(spl, node);
//   uint64 num_extents = 0;
//   for (uint16 branch_no = start_branch;
//        branch_no != end_branch;
//        branch_no = trunk_add_branch_number(spl, branch_no, 1))
//   {
//      num_extents += trunk_branch_extent_count(spl, node, branch_no);
//   }
//   platform_default_log("%8lu\n", num_extents);
//   trunk_node_unget(spl, &node);
//   return TRUE;
//}
//
// void
// trunk_print_extent_counts(trunk_handle *spl)
//{
//   platform_default_log("extent counts:\n");
//   trunk_for_each_node(spl, trunk_node_print_extent_count, NULL);
//}


// basic validation of data_config
static void
trunk_validate_data_config(const data_config *cfg)
{
   platform_assert(cfg->key_compare != NULL);

   // basic check of key comparison
   int min_max_cmp =
      cfg->key_compare(cfg,
                       slice_create(cfg->min_key_length, cfg->min_key),
                       slice_create(cfg->max_key_length, cfg->max_key));
   platform_assert(min_max_cmp < 0, "min_key must compare < max_key");
}

/*
 *-----------------------------------------------------------------------------
 * trunk_config_init --
 *
 *       Initialize splinter config
 *       This function calls btree_config_init
 *-----------------------------------------------------------------------------
 */
void
trunk_config_init(trunk_config        *trunk_cfg,
                  cache_config        *cache_cfg,
                  data_config         *data_cfg,
                  log_config          *log_cfg,
                  uint64               memtable_capacity,
                  uint64               fanout,
                  uint64               max_branches_per_node,
                  uint64               btree_rough_count_height,
                  uint64               filter_remainder_size,
                  uint64               filter_index_size,
                  uint64               reclaim_threshold,
                  bool                 use_log,
                  bool                 use_stats,
                  bool                 verbose_logging,
                  platform_log_handle *log_handle)

{
   trunk_validate_data_config(data_cfg);

   uint64          trunk_pivot_size;
   uint64          bytes_for_branches;
   routing_config *filter_cfg = &trunk_cfg->filter_cfg;

   ZERO_CONTENTS(trunk_cfg);
   trunk_cfg->cache_cfg = cache_cfg;
   trunk_cfg->data_cfg  = data_cfg;
   trunk_cfg->log_cfg   = log_cfg;

   trunk_cfg->fanout                  = fanout;
   trunk_cfg->max_branches_per_node   = max_branches_per_node;
   trunk_cfg->reclaim_threshold       = reclaim_threshold;
   trunk_cfg->use_log                 = use_log;
#if 0
   trunk_cfg->use_stats               = use_stats;
#else
   trunk_cfg->use_stats               = TRUE;
#endif
   trunk_cfg->verbose_logging_enabled = verbose_logging;
   trunk_cfg->log_handle              = log_handle;

   trunk_pivot_size = data_cfg->key_size + trunk_pivot_message_size();
   // Setting hard limit and over overprovisioning
   trunk_cfg->max_pivot_keys = trunk_cfg->fanout + 7;
   uint64 header_bytes       = sizeof(trunk_hdr);

   uint64 pivot_bytes = (trunk_cfg->max_pivot_keys
                         * (data_cfg->key_size + sizeof(trunk_pivot_data)));
   uint64 branch_bytes =
      trunk_cfg->max_branches_per_node * sizeof(trunk_branch);
   uint64 trunk_node_min_size = header_bytes + pivot_bytes + branch_bytes;
   uint64 available_pivot_bytes =
      cache_config_page_size(cache_cfg) - header_bytes - branch_bytes;
   uint64 available_bytes_per_pivot =
      available_pivot_bytes / trunk_cfg->max_pivot_keys;
   uint64 available_bytes_per_pivot_key =
      available_bytes_per_pivot - sizeof(trunk_pivot_data);
   platform_assert(trunk_node_min_size < cache_config_page_size(cache_cfg),
                   "\nTrunk node does not fit in page size as configured.\n"
                   "hdr: %luB\n"
                   "pivots: %luB (max_pivot=%lu x %luB)\n"
                   "branches %luB (max_branches=%lu x %luB).\n"
                   "Maximum key size supported with current config: %luB.\n",
                   header_bytes,
                   pivot_bytes,
                   trunk_cfg->max_pivot_keys,
                   data_cfg->key_size + sizeof(trunk_pivot_data),
                   branch_bytes,
                   max_branches_per_node,
                   sizeof(trunk_branch),
                   available_bytes_per_pivot_key);

   bytes_for_branches = (trunk_page_size(trunk_cfg) - trunk_hdr_size()
                         - trunk_cfg->max_pivot_keys * trunk_pivot_size);
   trunk_cfg->hard_max_branches_per_node =
      bytes_for_branches / sizeof(trunk_branch) - 1;

   // Initialize point message btree
   btree_config_init(&trunk_cfg->btree_cfg,
                     cache_cfg,
                     trunk_cfg->data_cfg,
                     btree_rough_count_height);

   memtable_config_init(&trunk_cfg->mt_cfg,
                        &trunk_cfg->btree_cfg,
                        TRUNK_NUM_MEMTABLES,
                        memtable_capacity);

   // Has to be set after btree_config_init is called
   trunk_cfg->max_kv_bytes_per_node =
      trunk_cfg->fanout * trunk_cfg->mt_cfg.max_extents_per_memtable
      * cache_config_extent_size(cache_cfg);
   trunk_cfg->target_leaf_kv_bytes = trunk_cfg->max_kv_bytes_per_node / 2;
   trunk_cfg->max_tuples_per_node  = trunk_cfg->max_kv_bytes_per_node / 32;

   // filter config settings
   filter_cfg->cache_cfg = cache_cfg;

   filter_cfg->index_size     = filter_index_size;
   filter_cfg->seed           = 42;
   filter_cfg->hash           = trunk_cfg->data_cfg->key_hash;
   filter_cfg->data_cfg       = trunk_cfg->data_cfg;
   filter_cfg->log_index_size = 31 - __builtin_clz(filter_cfg->index_size);

   uint64 filter_max_fingerprints = trunk_cfg->max_tuples_per_node;
   uint64 filter_quotient_size = 64 - __builtin_clzll(filter_max_fingerprints);
   uint64 filter_fingerprint_size =
      filter_remainder_size + filter_quotient_size;
   filter_cfg->fingerprint_size = filter_fingerprint_size;
   uint64 max_value             = trunk_cfg->max_branches_per_node;
   size_t max_value_size        = 64 - __builtin_clzll(max_value);

   if (filter_fingerprint_size > 32 - max_value_size) {
      platform_error_log(
         "Fingerprint size %lu too large, max value size is %lu, "
         "setting to %lu\n",
         filter_fingerprint_size,
         max_value_size,
         32 - max_value_size);
      filter_cfg->fingerprint_size = 32 - max_value_size;
   }

   /*
    * Set filter index size
    *
    * In quick_filter_init() we have this assert:
    *   index / addrs_per_page < cfg->extent_size / cfg->page_size
    * where
    *   - cfg is of type quick_filter_config
    *   - index is less than num_indices, which equals to params.num_buckets /
    *     cfg->index_size. params.num_buckets should be less than
    *     trunk_cfg.max_tuples_per_node
    *   - addrs_per_page = cfg->page_size / sizeof(uint64)
    *   - pages_per_extent = cfg->extent_size / cfg->page_size
    *
    * Therefore we have the following constraints on filter-index-size:
    *   (max_tuples_per_node / filter_cfg.index_size) / addrs_per_page <
    *   pages_per_extent
    * ->
    *   max_tuples_per_node / filter_cfg.index_size < addrs_per_page *
    *   pages_per_extent
    * ->
    *   filter_cfg.index_size > (max_tuples_per_node / (addrs_per_page *
    *   pages_per_extent))
    */
   uint64 addrs_per_page   = trunk_page_size(trunk_cfg) / sizeof(uint64);
   uint64 pages_per_extent = trunk_pages_per_extent(trunk_cfg);
   while (filter_cfg->index_size <= (trunk_cfg->max_tuples_per_node
                                     / (addrs_per_page * pages_per_extent)))
   {
      platform_error_log("filter-index-size: %u is too small, "
                         "setting to %u\n",
                         filter_cfg->index_size,
                         filter_cfg->index_size * 2);
      filter_cfg->index_size *= 2;
      filter_cfg->log_index_size++;
   }
}

size_t
trunk_get_scratch_size()
{
   return sizeof(trunk_task_scratch);
}
