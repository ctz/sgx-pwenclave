#include "pwenclave_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "pbkdf2.h"
#include "sha2.h"
#include "bitops.h"
#include "handy.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

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

static void pwrecord_clean(pwrecord *pwr)
{
  mem_clean(pwr, sizeof *pwr);
}

static uint32_t pwrecord_fresh(pwrecord *pwr)
{
  pwr->version = PWRECORD_VERSION;
  pwr->iters = PWRECORD_PBKDF2_ITERS;
  if (sgx_read_rand(pwr->salt, sizeof pwr->salt))
    return PW_UNEXPECTED_FAILURE;
  memset(pwr->hash, 0, sizeof pwr->hash);
  return PW_OK;
}

static void pwrecord_compute_hash(const pwrecord *pwr, const uint8_t *password, uint32_t pwlen, uint8_t out[32])
{
  cf_pbkdf2_hmac(password, pwlen,
                 pwr->salt, sizeof pwr->salt,
                 pwr->iters,
                 out, 32,
                 &cf_sha256);
}

static void pwrecord_init_hash(pwrecord *pwr, const uint8_t *password, uint32_t pwlen)
{
  pwrecord_compute_hash(pwr, password, pwlen, pwr->hash);
}

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

static uint32_t pwrecord_seal_and_write(pwrecord *pwr, uint8_t *blob_out, uint32_t bloblen_in, uint32_t *bloblen_out)
{
  uint8_t buf[PWRECORD_ENCODING_LEN] = { 0 };
  uint32_t need_len;
  pwrecord_encode(pwr, buf);

  need_len = sgx_calc_sealed_data_size(0, sizeof buf);
  if (bloblen_in < need_len)
    return PW_TOO_SHORT;
  
  if (sgx_seal_data(0, NULL, sizeof buf, buf, need_len, (sgx_sealed_data_t *) blob_out))
    return PW_UNEXPECTED_FAILURE;
  *bloblen_out = need_len;

  return PW_OK;
}

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

static uint32_t pwrecord_unseal_and_read(pwrecord *pwr, const uint8_t *blob, uint32_t bloblen)
{
  uint8_t buf[PWRECORD_ENCODING_LEN] = { 0 };
  uint32_t buflen = sizeof buf;

  if (sgx_unseal_data((const sgx_sealed_data_t *) blob, NULL, NULL, buf, &buflen) ||
      buflen != PWRECORD_ENCODING_LEN)
    return PW_BLOB_INVALID;
  
  return pwrecord_decode(pwr, buf);  
}

static uint32_t pwrecord_test_password(pwrecord *pwr, const uint8_t *password, uint32_t pwlen)
{
  uint8_t purported[32];

  pwrecord_compute_hash(pwr, password, pwlen, purported);

  if (mem_eq(pwr->hash, purported, sizeof pwr->hash))
    return PW_OK;
  else
    return PW_GUESS_WRONG;
}

uint32_t pw_setup(const uint8_t *password, uint32_t pwlen, uint8_t *blob_out, uint32_t bloblen_in, uint32_t *bloblen_out)
{
  pwrecord pwr = { 0 };
  uint32_t err;

  err = pwrecord_fresh(&pwr);
  if (err) return err;

  pwrecord_init_hash(&pwr, password, pwlen);
  err = pwrecord_seal_and_write(&pwr, blob_out, bloblen_in, bloblen_out);
  pwrecord_clean(&pwr);
  return err;
}

uint32_t pw_check(const uint8_t *password, uint32_t pwlen, const uint8_t *blob, uint32_t bloblen)
{
  pwrecord pwr = { 0 };
  uint32_t err;

  err = pwrecord_unseal_and_read(&pwr, blob, bloblen);
  if (err) return err;

  err = pwrecord_test_password(&pwr, password, pwlen);
  pwrecord_clean(&pwr);
  return err;
}