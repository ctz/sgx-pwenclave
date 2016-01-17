Using SGX to harden password hashing
====================================

SGX is a way of running security-sensitive user-mode code in an 'enclave'.
Code running in an enclave has its memory encrypted and authenticated, and cannot be
observed by code running anywhere else 

This project does simple PBKDF2 password hashing inside an SGX enclave.

Building
--------

You will need:

- The [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk).
- Visual Studio 2012 (a prerequisite of the SGX SDK).
- The Intel SGX Platform Software (comes with SDK) along with SGX-supporting hardware (a Skylake CPU and working BIOS).  The SDK supports a simulator; I haven't tried that.

Once you've got all that sorted, you should merely be able to load the solution and hit run.

I've tested this on a Dell Inspiron 5559 laptop.