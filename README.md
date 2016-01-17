Using SGX to harden password hashing
====================================

SGX is a way of running security-sensitive user-mode code in an 'enclave'.
Code running in an enclave has its memory encrypted and authenticated, and cannot be
observed by code running anywhere else.  It's able to use device-specific
keys to encrypt ('seal') data to future executions of itself or enclaves signed by the
same key.

This project does simple PBKDF2 password hashing inside an SGX enclave.
Password hashes are only available to the enclave, and therefore no amount of
database leakage will jeopardise user passwords.  Your stack of GPUs are useless here.

Warning
-------

This is extremely experimental.  Use at your own risk. There is no warranty.

This repo includes the enclave signing private key and the enclave
runs in debug mode, so this in fact provides no meaningful security.

Building
--------

You will need:

- The [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk).
- Visual Studio 2012 (a prerequisite of the SGX SDK).
- The Intel SGX Platform Software (comes with SDK) along with SGX-supporting hardware (a Skylake CPU and working BIOS).  The SDK supports a simulator; I haven't tried that.

As a fairly obvious result of all this, this is Windows only for the moment.

Once you've got all that sorted, you should merely be able to load the solution and hit run.

I've tested this on a Dell Inspiron 5559 laptop.