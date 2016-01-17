#include <stdio.h>
#include <tchar.h>

#include "sgx_urts.h"
#include "pwenclave_u.h"

/* This is a debugging ocall */
void emit_debug(const char *buf)
{
  printf("DEBUG: %s\n", buf);
}

int main(void)
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
  
  /* -- Setup password verified -- */
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

  getchar();
  return 0;
}
