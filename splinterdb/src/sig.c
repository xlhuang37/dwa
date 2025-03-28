#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include "platform.h"

#include "ref.h"
#include "sig.h"

uint64 hash_compute_count;
uint64 hash_compute_branch_count;
uint64 hash_compute_log_count;
uint64 hash_compute_filter_count;
uint64 hash_compute_cow_btree_pack_count;
uint64 total_ns_compute_hash;

static unsigned char *key = (unsigned char*)"This is your secret";

int hmac(char *data, int data_len, char *sig, int sig_len)
{
  unsigned char *ret;
  // TODO(yizheng.jiao): we are using sha256
  // the digest is 32 bytes.
  unsigned char hash[32];
  unsigned int hash_len;

  platform_assert(sig_len == HASH_SIZE);
  ret = HMAC(EVP_sha256(),
             key,
             strlen((char *)key),
             (unsigned char*)data,
             data_len,
             hash,
             &hash_len);
  (void)ret;
  platform_assert(hash_len == 32);
  // HASH_SIZE is 16 bytes, what is why
  // we need to do the copy
  memcpy(sig, hash, HASH_SIZE);
  return 0;
}

void hexStr(char *data, int len, char *buf)
{
  char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                   '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  for (int i = 0; i < len; ++i) {
    buf[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    buf[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
}

void print_sig(char *data, int data_len, char *info)
{
   platform_default_log("==== %s print sig starts ==== data_len=%d, pid=%ld\n", info, data_len, platform_get_tid());
   char buf[36] = {0};
   hexStr(data, data_len, buf);
   platform_default_log("%s pid=%ld, hash=%s\n", info, platform_get_tid(), buf);
   platform_default_log("==== %s print sig ends ====, pid=%ld\n", info, platform_get_tid());
}

//////////////////////////////////////////////////
//////////////////////////////////////////////////
//////////////////////////////////////////////////
const char secret_key[10] = {'b', 'e', 't', 'r', 'e', 'e', 'g', 'o', 'o', 'd'};

static uint8_t aes_key[16] = {
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f'
};

static uint8_t aes_iv[12] = {
    'h', 'e', 'l', 'l',
    'o', 'w', 'o', 'r',
    'l', 'd', '0', '1'
};

// data, key, iv, aad : Input
// tags : Output
int ghash(char *data, int data_len, char *sig, int sig_len) {
  EVP_CIPHER_CTX *ctx;
  int outlen;

  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  //IV : 12 bytes (96bits)
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
  EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, aes_iv);
  //AAD : 16 bytes (128bits)
  EVP_EncryptUpdate(ctx, NULL, &outlen, (const unsigned char*)data, data_len);
  EVP_EncryptFinal_ex(ctx, NULL, &outlen);
  //tags : 16 bytes (128bits)
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, sig);
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

void init_hash_counters() {
   hash_compute_count = 0;
   hash_compute_branch_count = 0;
   hash_compute_log_count = 0;
   hash_compute_filter_count = 0;
   hash_compute_cow_btree_pack_count = 0;
   total_ns_compute_hash = 0;
}

void print_hash_counters() {
   platform_default_log("%s: hash_compute_count=%lu\n", __func__, hash_compute_count);
   platform_default_log("%s: hash_compute_log_count=%lu\n", __func__, hash_compute_log_count);
   platform_default_log("%s: hash_compute_filter_count=%lu\n", __func__, hash_compute_filter_count);
   platform_default_log("%s: hash_compute_branch_count=%lu\n", __func__, hash_compute_branch_count);
   platform_default_log("%s: hash_compute_cow_btree_pack_count=%lu\n", __func__, hash_compute_cow_btree_pack_count);
   platform_default_log("%s: total_ns_compute_hash=%lu\n", __func__, total_ns_compute_hash);
}


int trunk_hmac(char *data, int data_len, char *sig, int sig_len, enum page_type type) {
  uint64 hash_start = platform_get_timestamp();
  int ret = ghash(data, data_len, sig, sig_len);

  uint64 hash_time = platform_get_timestamp() - hash_start;
  total_ns_compute_hash += hash_time;
  hash_compute_count += 1;
  if (type == PAGE_TYPE_BRANCH) {
     hash_compute_branch_count += 1;
  } else if (type == PAGE_TYPE_LOG) {
     hash_compute_log_count += 1;
  } else if (type == PAGE_TYPE_FILTER) {
     hash_compute_filter_count += 1;
  } else {
     hash_compute_cow_btree_pack_count += 1;
  }
  return ret;
}
