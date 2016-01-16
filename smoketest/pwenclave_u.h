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

sgx_status_t pw_setup(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* password, uint32_t pwlen, uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out);
sgx_status_t pw_check(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* password, size_t pwlen, const uint8_t* blob, uint32_t bloblen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
