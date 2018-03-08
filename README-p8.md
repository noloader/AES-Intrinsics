# AES-Power8

This is a test implementation of Power 8's in-core crypto using xlC and GCC built-in's.

The test implementation side steps key scheduling by using a pre-expanded "golden" key from FIPS 197, Appendix B. The golden key is the big-endian byte array `2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c`, and it produces the key schedule hard-coded in the program.

The GCC Compile Farm (http://gcc.gnu.org/wiki/CompileFarm) offers two test machines. To test on a Power 8 little-endian machine use GCC112. To test on a big-endian machine use GCC119.

According to data from GCC112, the naive impementation provided by `fips197-p8.c` achieves about 6 cycles-per-byte (cpb). It is mostly dull, but its still better than 20 to 30 cpb for C and C++. Running 4 or 8 blocks in parallel will increase performance to around 1 to 1.5 cpb.

## Compiling

To compile the source file using GCC:

    gcc -std=c99 -mcpu=power8 fips197-p8.c -o fips197-p8.exe

To compile the source file using IBM XL C/C++:

    xlc -qarch=pwr8 -qaltivec fips197-p8.c -o fips197-p8.exe

## Decryption

The decryption rountines are mostly a copy and paste of the encryption routines using the appropriate inverse function. However, you must build the key table using the algorithm discussed in FIPS 197, Sections 5.3.1 through 5.3.4 (pp. 20-23). You cannot use the "Equivalent Inverse Cipher" from Section 5.3.5 (p.23).

If you use the same key table as built for encryption, then you should index the subkey table in reverse order. That is, start with index `rounds`, then `rounds-1`, ..., then index `1`, and finally index `0`. (Remember, there are `N+1` subkeys for `N` rounds of AES).

## Byte Order

The VSX unit only operates on big-endian data. However, the CPU will load the VSX register in little-endian format on a little-endian machine by default. On little-endian machines each 16-byte buffer must be byte reversed before loading. Conversely, the data needs to be stored in little endian format on little endian machines when moving from a VSX register to memory. You have two options when reversing the data to ensure it is properly loaded into a VSX register or saved from a VSX register. First you can reverse the in-memory byte buffer. Second, you can load the byte buffer and then permute the vector.

A derivative of the test program used the first strategy for the subkey table. The subkey table is converted to big endian once so each subkey does not need a permute after loading. It was an optimization that benefited multiple encryptions under the same key. The test program used the second strategy on user data like input and output buffers.

For general reading on byte ordering, see "Targeting your applications - what little endian and big endian IBM XL C/C++ compiler differences mean to you" (http://www.ibm.com/developerworks/library/l-ibm-xl-c-cpp-compiler/index.html).

## Optimizations

There are at least two optimizations available that your program should take. The first optimization is perform the byte reversal on little-endian machines for the subkey table once after it is built. You will still need to perform the endian conversions on user supplied input and output buffers as the data is streamed into the program.

The second optimization your program should take is to run 4 or 8 blocks of encryption or decryption in parallel. The VSX unit has 32 full size registers, so you should be able to raise the number of simultaneous transformations to 12 if desired.

As an example, instead of a single loop operating on a a single block:

```
VectorType s = VectorLoad(input);
VectorType k = VectorLoadKey(subkeys);

s = VectorXor(s, k);
for (size_t i=1; i<rounds-1; i+=2)
{
    s = VectorEncrypt(s, VectorLoadKey(  i*16,   subkeys));
    s = VectorEncrypt(s, VectorLoadKey((i+1)*16, subkeys));
}

s = VectorEncrypt(s, VectorLoadKey((rounds-1)*16, subkeys));
s = VectorEncryptLast(s, VectorLoadKey(rounds*16, subkeys));
```

Run multiple transformations simultaneously:

```
VectorType k = VectorLoadKey(subkeys);
VectorType s0 = VectorLoad( 0, input);
VectorType s1 = VectorLoad(16, input);
VectorType s2 = VectorLoad(32, input);
VectorType s3 = VectorLoad(64, input);

s0 = VectorXor(s0, k);
s1 = VectorXor(s1, k);
s2 = VectorXor(s2, k);
s3 = VectorXor(s3, k);

for (size_t i=1; i<rounds; ++i)
{
     k = VectorLoadKey(i*16, subkeys);
    s0 = VectorEncrypt(s0, k);
    s1 = VectorEncrypt(s1, k);
    s2 = VectorEncrypt(s2, k);
    s3 = VectorEncrypt(s3, k);
}

 k = VectorLoadKey(rounds*16, subkeys);
s0 = VectorEncryptLast(s0, k);
s1 = VectorEncryptLast(s1, k);
s2 = VectorEncryptLast(s2, k);
s3 = VectorEncryptLast(s3, k);
```

## Field Implementations

Both Botan and Crypto++ used `fips197-p8.c` as a proof of concept. You can find the Botan issue to track the cut-in at Issue 1206, Add Power8 AES Encryption (http://github.com/randombit/botan/issues/1206). The issue to track the cut-in for Crypto++ can be found at Issue 497, Add Power8 AES Encryption (http://github.com/weidai11/cryptopp/issues/497).

## Acknowledgements

Thanks to Bill Schmidt, George Wilson, and Michael Strosaker from the IBM Linux Technology Center for help with the implementation.

Many thanks to Andy Polyakov for comments, helpful suggestions and answering questions about his ASM implmentation of Power 8 AES. Andy's implementation is lightening fast and available in the OpenSSL project and the Linux kernel. Andy's code and license terms can be found at http://www.openssl.org/~appro/cryptogams/.
