#ifndef PWENCLAVE_T_H__
#define PWENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "pwenclave.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


uint32_t pw_setup(const uint8_t* password, uint32_t pwlen, uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out);
uint32_t pw_check(const uint8_t* password, size_t pwlen, const uint8_t* blob, uint32_t bloblen);

sgx_status_t SGX_CDECL emit_debug(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
