#ifndef PWENCLAVE_U_H__
#define PWENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "pwenclave.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, emit_debug, (const char* str));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, write_region_data, (const uint8_t* blob, uint32_t bloblen));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, read_region_data, (uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out));

sgx_status_t pw_region_enroll(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* region_key, uint32_t rklen);
sgx_status_t pw_setup(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* password, uint32_t pwlen, uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out);
sgx_status_t pw_check(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* password, size_t pwlen, const uint8_t* blob, uint32_t bloblen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
