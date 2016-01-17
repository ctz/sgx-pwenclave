Using SGX to harden password hashing
====================================

SGX is a way of running security-sensitive user-mode code in an 'enclave'.
Code running in an enclave has its memory encrypted and authenticated, and cannot be
observed by code running anywhere else.  It's able to use device-specific
keys to encrypt ('seal') data to future executions of itself or enclaves signed by the
same key.

This project does PBKDF2 password hashing inside an SGX enclave.
Password hashes are only available to enclaves which have been enrolled in a 'region',
and therefore no amount of database leakage will jeopardise user passwords.  Your
stack of GPUs are useless here.

A region is represented with a AES key, and enclaves in a region have a copy of it
sealed to them.  The key itself can be kept offline and only used when enrolling
new enclaves or doing disaster recovery.

See my corresponding blog post [here](https://jbp.io/2016/01/17/using-sgx-to-hash-passwords/).

Warning
-------

This is extremely experimental.  Use at your own risk. There is no warranty.

This repo includes a trivial region key, the enclave signing private key and the enclave
runs in debug mode, so this in fact provides no meaningful security.

Tour
----

Interesting files:

* **[pwenclave/pwenclave.edl](pwenclave/pwenclave.edl)**: defines the interface surface between user-mode code and the enclave.
  An Intel-provided tool takes this definition and generates stubs for calling these functions in user-mode and converting
  arguments in the enclave (these are [pwenclave/pwenclave_t.c](pwenclave/pwenclave_t.c)
  and [smoketest/pwenclave_u.c](smoketest/pwenclave_u.c)).
* **[pwenclave/pwenclave.c](pwenclave/pwenclave.c)**: implements this interface.  There are bunch of other files alongside providing PBKDF2 etc.
* **[smoketest/smoketest.c](smoketest/smoketest.c)**: starts the enclave and exercises the functions.

Building
--------

You will need:

- The [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk).
- Visual Studio 2012 (a prerequisite of the SGX SDK).
- The Intel SGX Platform Software (comes with SDK) along with SGX-supporting hardware (a Skylake CPU and working BIOS).  The SDK supports a simulator; I haven't tried that.

As a fairly obvious result of all this, this is Windows only for the moment.

Once you've got all that sorted, you should merely be able to load the solution and hit run.

I've tested this on a Dell Inspiron 5559 laptop.
