#include "pwenclave_u.h"

typedef struct ms_pw_region_enroll_t {
	uint32_t ms_retval;
	uint8_t* ms_region_key;
	uint32_t ms_rklen;
} ms_pw_region_enroll_t;

typedef struct ms_pw_setup_t {
	uint32_t ms_retval;
	uint8_t* ms_password;
	uint32_t ms_pwlen;
	uint8_t* ms_blob;
	uint32_t ms_bloblen_in;
	uint32_t* ms_bloblen_out;
} ms_pw_setup_t;

typedef struct ms_pw_check_t {
	uint32_t ms_retval;
	uint8_t* ms_password;
	size_t ms_pwlen;
	uint8_t* ms_blob;
	uint32_t ms_bloblen;
} ms_pw_check_t;

typedef struct ms_emit_debug_t {
	char* ms_str;
} ms_emit_debug_t;

typedef struct ms_write_region_data_t {
	uint32_t ms_retval;
	uint8_t* ms_blob;
	uint32_t ms_bloblen;
} ms_write_region_data_t;

typedef struct ms_read_region_data_t {
	uint32_t ms_retval;
	uint8_t* ms_blob;
	uint32_t ms_bloblen_in;
	uint32_t* ms_bloblen_out;
} ms_read_region_data_t;

static sgx_status_t SGX_CDECL pwenclave_emit_debug(void* pms)
{
	ms_emit_debug_t* ms = SGX_CAST(ms_emit_debug_t*, pms);
	emit_debug((const char*)ms->ms_str);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pwenclave_write_region_data(void* pms)
{
	ms_write_region_data_t* ms = SGX_CAST(ms_write_region_data_t*, pms);
	ms->ms_retval = write_region_data((const uint8_t*)ms->ms_blob, ms->ms_bloblen);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pwenclave_read_region_data(void* pms)
{
	ms_read_region_data_t* ms = SGX_CAST(ms_read_region_data_t*, pms);
	ms->ms_retval = read_region_data(ms->ms_blob, ms->ms_bloblen_in, ms->ms_bloblen_out);
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[3];
} ocall_table_pwenclave = {
	3,
	{
		(void*)(uintptr_t)pwenclave_emit_debug,
		(void*)(uintptr_t)pwenclave_write_region_data,
		(void*)(uintptr_t)pwenclave_read_region_data,
	}
};

sgx_status_t pw_region_enroll(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* region_key, uint32_t rklen)
{
	sgx_status_t status;
	ms_pw_region_enroll_t ms;
	ms.ms_region_key = (uint8_t*)region_key;
	ms.ms_rklen = rklen;
	status = sgx_ecall(eid, 0, &ocall_table_pwenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t pw_setup(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* password, uint32_t pwlen, uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out)
{
	sgx_status_t status;
	ms_pw_setup_t ms;
	ms.ms_password = (uint8_t*)password;
	ms.ms_pwlen = pwlen;
	ms.ms_blob = blob;
	ms.ms_bloblen_in = bloblen_in;
	ms.ms_bloblen_out = bloblen_out;
	status = sgx_ecall(eid, 1, &ocall_table_pwenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t pw_check(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* password, size_t pwlen, const uint8_t* blob, uint32_t bloblen)
{
	sgx_status_t status;
	ms_pw_check_t ms;
	ms.ms_password = (uint8_t*)password;
	ms.ms_pwlen = pwlen;
	ms.ms_blob = (uint8_t*)blob;
	ms.ms_bloblen = bloblen;
	status = sgx_ecall(eid, 2, &ocall_table_pwenclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

