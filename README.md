# SEM-Bigwig
The goal of this project is to provide the end-user with a set of tools that handles all the necessary steps in order to communicate the code (and data) securely to the destinated Secure Machine, and back.

### Landlord

The **Landlord** module is aimed to parse and encrypt the source code of a secret program. The functionality implemented so far is generating the required meta-data for attestation, merging it into the compiled ELF source code.

To test the module's functionality:
- place an executable in *Landlord/tst*
- call `make` from the *Landlord* folder to compile the C code, and
- execute *./sample.py [executable path]*.

The Secure Machine doesn't support dynamically linked files, therefore, in order to witness the full functionality of the module, one has to execute the sample code with executables compiled using `--static` flag.
