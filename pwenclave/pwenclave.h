#ifndef PWENCLAVE_H
#define PWENCLAVE_H

#define PWENCLAVE_MAX_BLOB_SIZE 1024
#define PWENCLAVE_REGIONKEY_LEN 16

/* Error codes */
enum {
  PW_OK = 0,
  PW_TOO_SHORT, // buffer too short to accept full blob
  PW_BLOB_INVALID, // blob did not decrypt or was truncated
  PW_GUESS_WRONG, // password was incorrect
  PW_UNEXPECTED_FAILURE, // enclave code failed (should not happen)
  PW_NO_REGION_KEY // there's no region set up
};

#endif