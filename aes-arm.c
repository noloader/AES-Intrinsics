/* aes-arm.c - ARMv8 AES extensions using C intrinsics         */
/*   Written and placed in public domain by Jeffrey Walton     */
/*   Based on code from ARM, and by Johannes Schneiders, Skip  */
/*   Hovsmith and Barry O'Rourke for the mbedTLS project.      */

/* gcc -std=c99 -march=armv8-a+crypto aes-arm.c -o aes-arm.exe */

/* Visual Studio 2017 and above supports ARMv8, but its not clear how to detect */
/* it or use it at the moment. Also see http://stackoverflow.com/q/37244202,    */
/* http://stackoverflow.com/q/41646026, and http://stackoverflow.com/q/41688101 */
#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)
# if defined(__GNUC__)
#  include <stdint.h>
# endif
# if defined(__ARM_NEON) || defined(_MSC_VER)
#  include <arm_neon.h>
# endif
/* GCC and LLVM Clang, but not Apple Clang */
# if defined(__GNUC__) && !defined(__apple_build_version__)
#  if defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO)
#   include <arm_acle.h>
#  endif
# endif
#endif  /* ARM Headers */

void aes_process_arm(const uint8_t key[], const uint8_t subkeys[], uint32_t rounds,
                     const uint8_t input[], uint8_t output[], uint32_t length)
{
	while (length >= 16)
	{
		uint8x16_t block = vld1q_u8(input);

		// AES single round encryption
		block = vaeseq_u8(block, vld1q_u8(key));
		// AES mix columns
		block = vaesmcq_u8(block);

		// AES single round encryption
		block = vaeseq_u8(block, vld1q_u8(subkeys));
		// AES mix columns
		block = vaesmcq_u8(block);

		for (unsigned int i=1; i<rounds-2; ++i)
		{
			// AES single round encryption
			block = vaeseq_u8(block, vld1q_u8(subkeys+i*16));
			// AES mix columns
			block = vaesmcq_u8(block);
		}

		// AES single round encryption
		block = vaeseq_u8(block, vld1q_u8(subkeys+(rounds-2)*16));
		// Final Add (bitwise Xor)
		block = veorq_u8(block, vld1q_u8(subkeys+(rounds-1)*16));

		vst1q_u8(output, block);

		input += 16; output += 16;
		length -= 16;
	}
}

#if defined(TEST_MAIN)

#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	/* FIPS 197, Appendix B input */
	const uint8_t input[16] = { /* user input, unaligned buffer */
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};

	/* FIPS 197, Appendix B key */
	const uint8_t key[16] = { /* user input, unaligned buffer */
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x9 , 0xcf, 0x4f, 0x3c
	};

	/* FIPS 197, Appendix B expanded subkeys */
	__attribute__((aligned(4)))
	const uint8_t subkeys[10][16] = { /* library controlled, aligned buffer */
		{0xA0, 0xFA, 0xFE, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05},
		{0xF2, 0xC2, 0x95, 0xF2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f},
		{0x3D, 0x80, 0x47, 0x7D, 0x47, 0x16, 0xFE, 0x3E, 0x1E, 0x23, 0x7E, 0x44, 0x6D, 0x7A, 0x88, 0x3B},
		{0xEF, 0x44, 0xA5, 0x41, 0xA8, 0x52, 0x5B, 0x7F, 0xB6, 0x71, 0x25, 0x3B, 0xDB, 0x0B, 0xAD, 0x00},
		{0xD4, 0xD1, 0xC6, 0xF8, 0x7C, 0x83, 0x9D, 0x87, 0xCA, 0xF2, 0xB8, 0xBC, 0x11, 0xF9, 0x15, 0xBC},
		{0x6D, 0x88, 0xA3, 0x7A, 0x11, 0x0B, 0x3E, 0xFD, 0xDB, 0xF9, 0x86, 0x41, 0xCA, 0x00, 0x93, 0xFD},
		{0x4E, 0x54, 0xF7, 0x0E, 0x5F, 0x5F, 0xC9, 0xF3, 0x84, 0xA6, 0x4F, 0xB2, 0x4E, 0xA6, 0xDC, 0x4F},
		{0xEA, 0xD2, 0x73, 0x21, 0xB5, 0x8D, 0xBA, 0xD2, 0x31, 0x2B, 0xF5, 0x60, 0x7F, 0x8D, 0x29, 0x2F},
		{0xAC, 0x77, 0x66, 0xF3, 0x19, 0xFA, 0xDC, 0x21, 0x28, 0xD1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6E},
		{0xD0, 0x14, 0xF9, 0xA8, 0xC9, 0xEE, 0x25, 0x89, 0xE1, 0x3F, 0x0c, 0xC8, 0xB6, 0x63, 0x0C, 0xA6}
	};

	/* Result */
	uint8_t result[19] = { 0 };

	aes_process_arm((const uint8_t*)key, (const uint8_t*)subkeys, 10, input, result+3, 16);

	printf("Input: ");
	for (unsigned int i=0; i<16; ++i)
		printf("%02X ", input[i]);
	printf("\n");

	printf("Key: ");
	for (unsigned int i=0; i<16; ++i)
		printf("%02X ", key[i]);
	printf("\n");

	printf("Output: ");
	for (unsigned int i=3; i<19; ++i)
		printf("%02X ", result[i]);
	printf("\n");

	/* FIPS 197, Appendix B output */
	const uint8_t exp[16] = {
		0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32
	};

	if (0 == memcmp(result+3, exp, 16))
		printf("SUCCESS!!!\n");
	else
		printf("FAILURE!!!\n");

	return 0;
}

#endif
