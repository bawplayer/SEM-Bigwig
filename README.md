# SEM-Bigwig
The goal of this project is to provide the end-user with a set of tools that handles all the necessary steps in order to communicate the code (and data) securely to the destinated Secure Machine, and back.

In the Secure Machine, the process' memory instance outside the trusted zone is encrypted & signed. *A landlord* stands for a unit of meta-data that corresponds with memory quota of single cacheline. Landlord instances allocated predominantly outside the trusted zone, hence, same restrictions apply.

## Landlord

The **Landlord** module is aimed to encrypt & sign the source code of a secret program. Currently, the module generates the required signatures for attestation, merging it into the compiled ELF source code.


To test the module's functionality:
- from the *Landlord* folder, call `make` to compile the module's CPython code,
- either place an executable in *Landlord/tst*, or simply call `make test`, and,
- execute *./sample.py [executable path]*.

#### Notes
- Requirements: Built for 64-bit machine running Linux with Python v3.5
- The Secure Machine doesn't support dynamically linked files, therefore, in order to witness the full functionality of the module, one has to execute the sample code with executables compiled using `--static` flag.
