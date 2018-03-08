# AES-Intrinsics

This GitHub repository contains source code for AES encryption using Intel AES and ARMv8 AES intrinsics, and Power8 built-ins. The source files should be portable across toolchains which support the Intel and ARMv8 AES extensions.

Only the AES encryption function is provided. The function operates on full blocks. Users must set the key, and users must pad the last block. The small sample program included with each source file does both on an empty message.

## Intel AES

The GitHub does not have an Intel AES implementation. Intel has an excellent document at [Intel Advanced Encryption Standard (AES) New Instructions Set](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf).

If you want to test the programs but don't have a capable machine on hand, then you can use the Intel Software Development Emulator. You can find it at http://software.intel.com/en-us/articles/intel-software-development-emulator.

## ARM SHA

To compile the ARM sources on an ARMv8 machine, be sure your CFLAGS include `-march=armv8-a+crc+crypto`. Apple iOS CFLAGS should include `-arch arm64` and a system root like `-isysroot  /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS8.2.sdk`.

The ARM source files are based on code from ARM, and code by Johannes Schneiders, Skip Hovsmith and Barry O'Rourke for the mbedTLS project. You can find the mbedTLS GitHub at http://github.com/ARMmbed/mbedtls. Prior to ARM's implementation, Critical Blue provided the source code and pull request at http://github.com/CriticalBlue/mbedtls.

If you want to test the programs but don't have a capable machine on hand, then you can use the ARM  Fixed Virtual Platforms. You can find it at https://developer.arm.com/products/system-design/fixed-virtual-platforms.

## Power8 SHA

To compile the Power8 sources on an PPC machine with GCC, be sure your CFLAGS include `-mcpu=power8 -maltivec`. If using IBM XL C/C++ then use `-qarch=pwr8 -qaltivec`.

The Power8 source files are written from scratch. IBM's documentation sucks. Namely, there is none.

# Benchmarks

To be determined.