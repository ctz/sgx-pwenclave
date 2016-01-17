#include <stdio.h>
#include <tchar.h>

#include "sgx_urts.h"
#include "pwenclave_u.h"

/* This is your region key.  It should be kept offline, and only used
 * when a new CPU needs to do password verification.
 *
 * This is a dummy value for demo purposes! */
static uint8_t region_key_plain[PWENCLAVE_REGIONKEY_LEN] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

/* This data should go in a file.  It is a CPU-specific encryption of the region key. */
static uint8_t sealed_region_key[PWENCLAVE_MAX_BLOB_SIZE];
static uint32_t sealed_region_key_len;

/* --- ocalls --- */

/* This is a debugging ocall */
void emit_debug(const char *buf)
{
  printf("DEBUG: %s\n", buf);
}

uint32_t write_region_data(const uint8_t *buf, uint32_t buflen)
{
  if (buflen > sizeof sealed_region_key)
    return PW_TOO_SHORT;
  memcpy(sealed_region_key, buf, buflen);
  sealed_region_key_len = buflen;
  return PW_OK;
}

uint32_t read_region_data(uint8_t *buf, uint32_t buflen, uint32_t *buflen_out)
{
  if (sealed_region_key_len == 0)
    return PW_NO_REGION_KEY;

  if (buflen < sealed_region_key_len)
    return PW_TOO_SHORT;

  memcpy(buf, sealed_region_key, sealed_region_key_len);
  *buflen_out = sealed_region_key_len;
  return PW_OK;
}

int test(void)
{
  DWORD time;
  uint32_t i, bloblen, pwerr;
  const uint8_t *password = (const uint8_t *) "password123";
  const uint8_t *wrong_password = (const uint8_t *) "spanglypants";

  /* Setup enclave */
  sgx_enclave_id_t eid;
  sgx_status_t ret;
  sgx_launch_token_t token = { 0 };
     
  int token_updated = 0;

  uint8_t blob[PWENCLAVE_MAX_BLOB_SIZE] = { 0 };

  ret = sgx_create_enclave(_T("pwenclave.signed.dll"), SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    return 1;
  }

  /* -- Bring this CPU into the region -- */
  time = GetTickCount();
  ret = pw_region_enroll(eid, &pwerr, region_key_plain, sizeof region_key_plain);
  printf("pw_region_enroll took %ums\n", GetTickCount() - time);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx pw_region_enroll failed: %#x\n", ret);
    sgx_destroy_enclave(eid);
    return 1;
  }

  if (pwerr != PW_OK)
  {
    printf("pw_region_enroll reported failure: %#x\n", pwerr);
    sgx_destroy_enclave(eid);
    return 1;
  }
  
  /* -- Setup password verifier -- */
  time = GetTickCount();
  ret = pw_setup(eid, &pwerr, password, strlen(password), blob, sizeof blob, &bloblen);
  printf("pw_setup took %ums\n", GetTickCount() - time);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx pw_setup failed: %#x\n", ret);
    sgx_destroy_enclave(eid);
    return 1;
  }

  if (pwerr != PW_OK)
  {
    printf("pw_setup reported failure: %#x\n", pwerr);
    sgx_destroy_enclave(eid);
    return 1;
  }

  printf("setup worked, blob is %u bytes\n", bloblen);
  for (i = 0 ; i < bloblen; i++)
    printf("%02x", blob[i]);
  printf("\n");

  /* -- Check it works -- */
  time = GetTickCount();
  ret = pw_check(eid, &pwerr, password, strlen(password), blob, bloblen);
  printf("pw_check+ took %ums\n", GetTickCount() - time);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx pw_check failed: %#x\n", ret);
    sgx_destroy_enclave(eid);
    return 1;
  }

  if (pwerr != PW_OK)
  {
    printf("pw_check reported failure: %#x\n", pwerr);
    sgx_destroy_enclave(eid);
    return 1;
  }

  printf("pw_check worked (positive case)\n");

  /* Check we detect wrong passwords */
  time = GetTickCount();
  ret = pw_check(eid, &pwerr, wrong_password, strlen(wrong_password), blob, bloblen);
  printf("pw_check- took %ums\n", GetTickCount() - time);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx pw_check failed: %#x\n", ret);
    sgx_destroy_enclave(eid);
    return 1;
  }

  if (pwerr != PW_GUESS_WRONG)
  {
    printf("pw_check reported wrong error: %#x\n", pwerr);
    sgx_destroy_enclave(eid);
    return 1;
  }

  printf("pw_check worked (negative case)\n");
  
  /* Destroy enclave */  
  ret = sgx_destroy_enclave(eid);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_destroy_enclave failed: %#x\n", ret);
    return 1;
  }
  
  return 0;
}

int main(void)
{
  int r = test();
  getchar();
  return r;
}
