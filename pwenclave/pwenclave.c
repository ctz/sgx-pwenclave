#include "pwenclave_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "pbkdf2.h"
#include "sha2.h"
#include "bitops.h"
#include "handy.h"

#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* globals: region key management. */
static uint32_t g_have_region_key = 0;
static sgx_aes_ctr_128bit_key_t g_region_key;

/* for debug purposes, print a string via an ocall */
static void debugf(const char *fmt, ...)
{
  char buf[256] = { 0 };
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  emit_debug(buf);
}

/* --- */

/* Fill in g_region_key by fetching a sealed copy from our caller
 * (via the read_region_data ocall) and then unsealing it. */
static uint32_t fetch_region_key(void)
{
  uint8_t blob[PWENCLAVE_MAX_BLOB_SIZE];
  uint8_t key[PWENCLAVE_REGIONKEY_LEN];
  uint32_t err, bloblen, keylen;

  if (read_region_data(&err, blob, sizeof blob, &bloblen))
    return SGX_ERROR_UNEXPECTED;
  if (err) return err;

  /* Now unseal. */
  keylen = sizeof key;
  if (sgx_unseal_data((const sgx_sealed_data_t *) blob, NULL, NULL, key, &keylen) ||
      keylen != PWENCLAVE_REGIONKEY_LEN)
    return PW_BLOB_INVALID;

  memcpy(g_region_key, key, sizeof key);
  g_have_region_key = 1;
  return PW_OK;
}

/* --- */

/* This structure is all the data needed for password verification. */
typedef struct
{
#define PWRECORD_VERSION 1
  uint32_t version;
#define PWRECORD_PBKDF2_ITERS 50000
  uint32_t iters;
  uint8_t salt[16];
  uint8_t hash[32];
} pwrecord;

#define PWRECORD_ENCODING_LEN (4 + 4 + 16 + 32)

/* Zeroes a password record */
static void pwrecord_clean(pwrecord *pwr)
{
  mem_clean(pwr, sizeof *pwr);
}

/* Generates a password record, with a random salt. */
static uint32_t pwrecord_fresh(pwrecord *pwr)
{
  pwr->version = PWRECORD_VERSION;
  pwr->iters = PWRECORD_PBKDF2_ITERS;
  if (sgx_read_rand(pwr->salt, sizeof pwr->salt))
    return PW_UNEXPECTED_FAILURE;
  memset(pwr->hash, 0, sizeof pwr->hash);
  return PW_OK;
}

/* Computes a password hash using the parameters in pwr and the given password.
 * Places the result in out. */
static void pwrecord_compute_hash(const pwrecord *pwr, const uint8_t *password, uint32_t pwlen, uint8_t out[32])
{
  cf_pbkdf2_hmac(password, pwlen,
                 pwr->salt, sizeof pwr->salt,
                 pwr->iters,
                 out, 32,
                 &cf_sha256);
}

/* Fills in the hash field of pwr using the given password */
static void pwrecord_init_hash(pwrecord *pwr, const uint8_t *password, uint32_t pwlen)
{
  pwrecord_compute_hash(pwr, password, pwlen, pwr->hash);
}

/* Encodes the contents of pwr into out.
 * 
 * A pwrecord encoding looks like:
 *   version (big endian 32-bit word) currently 1
 *   iters   (big endian 32-bit word) PKBDF2 iterations used
 *   salt    (16 bytes)
 *   hash    (32 bytes)
 */
static void pwrecord_encode(pwrecord *pwr, uint8_t out[PWRECORD_ENCODING_LEN])
{
  write32_be(pwr->version, out);
  out += 4;
  write32_be(pwr->iters, out);
  out += 4;
  memcpy(out, pwr->salt, sizeof pwr->salt);
  out += sizeof pwr->salt;
  memcpy(out, pwr->hash, sizeof pwr->hash);
}

/* Encodes and encrypts the password record, writing the result into blob_out.
 * The record is encrypted using AES-GCM under the region key.
 *
 * Ciphertext is:
 *   nonce (12 bytes)
 *   tag (16 bytes)
 *   cipher (PWRECORD_ENCODING_LEN bytes)
 */
static uint32_t pwrecord_encrypt(pwrecord *pwr, uint8_t *blob_out, uint32_t bloblen_in, uint32_t *bloblen_out)
{
  uint8_t plain[PWRECORD_ENCODING_LEN] = { 0 };
  uint32_t need_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + PWRECORD_ENCODING_LEN;
  pwrecord_encode(pwr, plain);

  if (bloblen_in < need_len)
    return PW_TOO_SHORT;

  /* choose random nonce */
  if (sgx_read_rand(blob_out, SGX_AESGCM_IV_SIZE))
    return PW_UNEXPECTED_FAILURE;
  
  assert(g_have_region_key);
  if (sgx_rijndael128GCM_encrypt(&g_region_key,
                                 plain, sizeof plain,
                                 blob_out + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE,
                                 blob_out, SGX_AESGCM_IV_SIZE,
                                 NULL, 0,
                                 (sgx_aes_gcm_128bit_tag_t *) (blob_out + SGX_AESGCM_IV_SIZE)))
    return PW_UNEXPECTED_FAILURE;
  *bloblen_out = need_len;

  return PW_OK;
}

/* Decodes a password record encoding in buf, writing the results into
 * pwr. */
static uint32_t pwrecord_decode(pwrecord *pwr, const uint8_t buf[PWRECORD_ENCODING_LEN])
{
  pwr->version = read32_be(buf + 0);
  pwr->iters = read32_be(buf + 4);
  memcpy(pwr->salt, buf + 8, sizeof pwr->salt);
  memcpy(pwr->hash, buf + 8 + sizeof pwr->salt, sizeof pwr->hash);

  if (pwr->version != PWRECORD_VERSION ||
      pwr->iters == 0)
    return PW_BLOB_INVALID;

  return PW_OK;
}

/* Decrypts a password record ciphertext, filling in pwr. */
static uint32_t pwrecord_decrypt(pwrecord *pwr, const uint8_t *blob, uint32_t bloblen)
{
  uint8_t buf[PWRECORD_ENCODING_LEN] = { 0 };
  uint32_t buflen = sizeof buf;
  assert(g_have_region_key);

  if (bloblen != (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + PWRECORD_ENCODING_LEN) ||
      sgx_rijndael128GCM_decrypt(&g_region_key,
                                 blob + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE,           /* cipher */
                                 PWRECORD_ENCODING_LEN,
                                 buf,                                                       /* plain out */
                                 blob, SGX_AESGCM_IV_SIZE,                                  /* nonce */
                                 NULL, 0,                                                   /* aad */
                                 (sgx_aes_gcm_128bit_tag_t *) (blob + SGX_AESGCM_IV_SIZE))) /* tag */
    return PW_BLOB_INVALID;

  return pwrecord_decode(pwr, buf);  
}

/* Test a candidate password by feeding it into PBKDF2 with the parameters in pwr.
 * Then compare it with the stored hash in pwr, and return PW_GUESS_WRONG if the password
 * is wrong. */
static uint32_t pwrecord_test_password(pwrecord *pwr, const uint8_t *password, uint32_t pwlen)
{
  uint8_t purported[32];

  pwrecord_compute_hash(pwr, password, pwlen, purported);

  if (mem_eq(pwr->hash, purported, sizeof pwr->hash))
    return PW_OK;
  else
    return PW_GUESS_WRONG;
}

/* --- ecalls --- */

/* Enroll this enclave, such that it has a copy of the region key
 * available to it.  This means it can decrypt password records and
 * check passwords using that information.
 *
 * This function seals the given key, and then emits the sealed
 * key to the outside world via write_region_data. */
uint32_t pw_region_enroll(const uint8_t *region_key, uint32_t rklen)
{
  int32_t need_len;
  uint8_t buf[1024];
  uint32_t err;

  if (rklen != PWENCLAVE_REGIONKEY_LEN)
    return PW_TOO_SHORT;

  /* Seal region key */
  need_len = sgx_calc_sealed_data_size(0, rklen);
  if (sizeof buf < need_len)
    return PW_UNEXPECTED_FAILURE;
  
  if (sgx_seal_data(0, NULL, rklen, region_key, need_len, (sgx_sealed_data_t *) buf))
    return PW_UNEXPECTED_FAILURE;
  
  /* Emit it */
  if (write_region_data(&err, buf, need_len))
    return PW_UNEXPECTED_FAILURE;
  mem_clean(buf, sizeof buf);
  return err;
}

/* Sets up a password verifier for a new user.  This returns an encrypted password
 * record in blob_out, which should be stored against the user (say, in a database).
 *
 * Then, to check a user's password, pass it to pw_check with the same data. */
uint32_t pw_setup(const uint8_t *password, uint32_t pwlen, uint8_t *blob_out, uint32_t bloblen_in, uint32_t *bloblen_out)
{
  pwrecord pwr = { 0 };
  uint32_t err;

  if (!g_have_region_key)
  {
    err = fetch_region_key();
    if (err) return err;
  }

  err = pwrecord_fresh(&pwr);
  if (err) return err;

  pwrecord_init_hash(&pwr, password, pwlen);
  err = pwrecord_encrypt(&pwr, blob_out, bloblen_in, bloblen_out);
  pwrecord_clean(&pwr);
  return err;
}

/* Check a user's password.  blob should contain data previously output by pw_setup.
 * If the password is correct, PW_OK is returned.  Otherwise, PW_GUESS_WRONG indicates
 * the password is wrong. */
uint32_t pw_check(const uint8_t *password, uint32_t pwlen, const uint8_t *blob, uint32_t bloblen)
{
  pwrecord pwr = { 0 };
  uint32_t err;

  if (!g_have_region_key)
  {
    err = fetch_region_key();
    if (err) return err;
  }

  err = pwrecord_decrypt(&pwr, blob, bloblen);
  if (err) return err;

  err = pwrecord_test_password(&pwr, password, pwlen);
  pwrecord_clean(&pwr);
  return err;
}