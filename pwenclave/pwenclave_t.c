#include "pwenclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

/* sgx_ocfree() just restores the original outside stack pointer. */
#define OCALLOC(val, type, len) do {	\
	void* __tmp = sgx_ocalloc(len);	\
	if (__tmp == NULL) {	\
		sgx_ocfree();	\
		return SGX_ERROR_UNEXPECTED;\
	}			\
	(val) = (type)__tmp;	\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_pw_region_enroll(void* pms)
{
	ms_pw_region_enroll_t* ms = SGX_CAST(ms_pw_region_enroll_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_region_key = ms->ms_region_key;
	uint32_t _tmp_rklen = ms->ms_rklen;
	size_t _len_region_key = _tmp_rklen;
	uint8_t* _in_region_key = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_pw_region_enroll_t));
	CHECK_UNIQUE_POINTER(_tmp_region_key, _len_region_key);

	if (_tmp_region_key != NULL) {
		_in_region_key = (uint8_t*)malloc(_len_region_key);
		if (_in_region_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_region_key, _tmp_region_key, _len_region_key);
	}
	ms->ms_retval = pw_region_enroll((const uint8_t*)_in_region_key, _tmp_rklen);
err:
	if (_in_region_key) free((void*)_in_region_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_pw_setup(void* pms)
{
	ms_pw_setup_t* ms = SGX_CAST(ms_pw_setup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_password = ms->ms_password;
	uint32_t _tmp_pwlen = ms->ms_pwlen;
	size_t _len_password = _tmp_pwlen;
	uint8_t* _in_password = NULL;
	uint8_t* _tmp_blob = ms->ms_blob;
	uint32_t _tmp_bloblen_in = ms->ms_bloblen_in;
	size_t _len_blob = _tmp_bloblen_in;
	uint8_t* _in_blob = NULL;
	uint32_t* _tmp_bloblen_out = ms->ms_bloblen_out;
	size_t _len_bloblen_out = sizeof(*_tmp_bloblen_out);
	uint32_t* _in_bloblen_out = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_pw_setup_t));
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_blob, _len_blob);
	CHECK_UNIQUE_POINTER(_tmp_bloblen_out, _len_bloblen_out);

	if (_tmp_password != NULL) {
		_in_password = (uint8_t*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_password, _tmp_password, _len_password);
	}
	if (_tmp_blob != NULL) {
		if ((_in_blob = (uint8_t*)malloc(_len_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_blob, 0, _len_blob);
	}
	if (_tmp_bloblen_out != NULL) {
		if ((_in_bloblen_out = (uint32_t*)malloc(_len_bloblen_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bloblen_out, 0, _len_bloblen_out);
	}
	ms->ms_retval = pw_setup((const uint8_t*)_in_password, _tmp_pwlen, _in_blob, _tmp_bloblen_in, _in_bloblen_out);
err:
	if (_in_password) free((void*)_in_password);
	if (_in_blob) {
		memcpy(_tmp_blob, _in_blob, _len_blob);
		free(_in_blob);
	}
	if (_in_bloblen_out) {
		memcpy(_tmp_bloblen_out, _in_bloblen_out, _len_bloblen_out);
		free(_in_bloblen_out);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_pw_check(void* pms)
{
	ms_pw_check_t* ms = SGX_CAST(ms_pw_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_password = ms->ms_password;
	size_t _tmp_pwlen = ms->ms_pwlen;
	size_t _len_password = _tmp_pwlen;
	uint8_t* _in_password = NULL;
	uint8_t* _tmp_blob = ms->ms_blob;
	uint32_t _tmp_bloblen = ms->ms_bloblen;
	size_t _len_blob = _tmp_bloblen;
	uint8_t* _in_blob = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_pw_check_t));
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_blob, _len_blob);

	if (_tmp_password != NULL) {
		_in_password = (uint8_t*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_password, _tmp_password, _len_password);
	}
	if (_tmp_blob != NULL) {
		_in_blob = (uint8_t*)malloc(_len_blob);
		if (_in_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_blob, _tmp_blob, _len_blob);
	}
	ms->ms_retval = pw_check((const uint8_t*)_in_password, _tmp_pwlen, (const uint8_t*)_in_blob, _tmp_bloblen);
err:
	if (_in_password) free((void*)_in_password);
	if (_in_blob) free((void*)_in_blob);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_pw_region_enroll, 0},
		{(void*)(uintptr_t)sgx_pw_setup, 0},
		{(void*)(uintptr_t)sgx_pw_check, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][3];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL emit_debug(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_emit_debug_t* ms;
	OCALLOC(ms, ms_emit_debug_t*, sizeof(*ms));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		OCALLOC(ms->ms_str, char*, _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL write_region_data(uint32_t* retval, const uint8_t* blob, uint32_t bloblen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_blob = bloblen;

	ms_write_region_data_t* ms;
	OCALLOC(ms, ms_write_region_data_t*, sizeof(*ms));

	if (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) {
		OCALLOC(ms->ms_blob, uint8_t*, _len_blob);
		memcpy((void*)ms->ms_blob, blob, _len_blob);
	} else if (blob == NULL) {
		ms->ms_blob = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bloblen = bloblen;
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL read_region_data(uint32_t* retval, uint8_t* blob, uint32_t bloblen_in, uint32_t* bloblen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_blob = bloblen_in;
	size_t _len_bloblen_out = sizeof(*bloblen_out);

	ms_read_region_data_t* ms;
	OCALLOC(ms, ms_read_region_data_t*, sizeof(*ms));

	if (blob != NULL && sgx_is_within_enclave(blob, _len_blob)) {
		OCALLOC(ms->ms_blob, uint8_t*, _len_blob);
		memset(ms->ms_blob, 0, _len_blob);
	} else if (blob == NULL) {
		ms->ms_blob = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bloblen_in = bloblen_in;
	if (bloblen_out != NULL && sgx_is_within_enclave(bloblen_out, _len_bloblen_out)) {
		OCALLOC(ms->ms_bloblen_out, uint32_t*, _len_bloblen_out);
		memset(ms->ms_bloblen_out, 0, _len_bloblen_out);
	} else if (bloblen_out == NULL) {
		ms->ms_bloblen_out = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (blob) memcpy((void*)blob, ms->ms_blob, _len_blob);
	if (bloblen_out) memcpy((void*)bloblen_out, ms->ms_bloblen_out, _len_bloblen_out);

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
