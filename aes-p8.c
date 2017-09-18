/* Written and placed in public domain by Jeffrey Walton         */
/*  aes-p8.c tests Power 8 AES using GCC and XL C/C++ built-ins. */

/* xlc -qarch=pwr8 -qaltivec aes-p8.c -o aes-p8.exe              */
/* gcc -std=c99 -mcpu=power8 aes-p8.c -o aes-p8.exe              */

/* To test on an AltiVec/Power 8 little-endian machine use       */
/* GCC112. To test on a big-endian machine use GCC119.           */

/* Many thanks to Andy Polyakov for comments, helpful            */
/* suggestions and answering questions about his ASM             */
/* implmentation of Power 8 AES.                                 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(__ALTIVEC__)
# include <altivec.h>
#endif

#if defined(__xlc__) || defined(__xlC__)
# define TEST_AES_XLC 1
#elif defined(__clang__)
# define TEST_AES_CLANG 1
#elif defined(__GNUC__)
# define TEST_AES_GCC 1
#endif

#if defined(__LITTLE_ENDIAN__)
# define TEST_AES_LITTLE_ENDIAN 1
#endif

typedef vector unsigned char uint8x16_p8;
typedef vector unsigned long long uint64x2_p8;

uint8x16_p8 Reverse8x16(const uint8x16_p8 src)
{
	const uint8x16_p8 mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
	const uint8x16_p8 zero = {0};
	return vec_perm(src, zero, mask);
}

uint64x2_p8 Reverse64x2(const uint64x2_p8 src)
{
	const uint8x16_p8 mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
	const uint8x16_p8 zero = {0};
	return (uint64x2_p8)vec_perm((uint8x16_p8)src, zero, mask);
}

/* Load from big-endian format. Perform endian conversion as necessary */
uint8x16_p8 Load8x16(const uint8_t src[16])
{
#if defined(TEST_AES_XLC)
	/* http://stackoverflow.com/q/46124383/608639 */
	return vec_xl_be(0, (uint8_t*)src);
#else
	/* GCC, Clang, etc */
# if defined(TEST_AES_LITTLE_ENDIAN)
	return Reverse8x16(vec_vsx_ld(0, src));
# else
	return vec_vsx_ld(0, src);
# endif
#endif
}

/* Store in big-endian format. Perform endian conversion as necessary */
void Store8x16(const uint8x16_p8 src, uint8_t dest[16])
{
#if defined(TEST_AES_XLC)
	/* http://stackoverflow.com/q/46124383/608639 */
	vec_xst_be(src, 0, (uint8_t*)dest);
#else
	/* GCC, Clang, etc */
# if defined(TEST_AES_LITTLE_ENDIAN)
	vec_vsx_st(Reverse8x16(src), 0, dest);
# else
	vec_vsx_st(src, 0, dest);
# endif
#endif
}

/* Load from big-endian format. Perform endian conversion as necessary */
uint64x2_p8 Load64x2(const uint8_t src[16])
{
#if defined(TEST_AES_XLC)
	/* http://stackoverflow.com/q/46124383/608639 */
	return (uint64x2_p8)vec_xl_be(0, (uint8_t*)src);
#else
	/* GCC, Clang, etc */
# if defined(TEST_AES_LITTLE_ENDIAN)
	return (uint64x2_p8)Reverse8x16(vec_vsx_ld(0, src));
# else
	return (uint64x2_p8)vec_vsx_ld(0, src);
# endif
#endif
}

/* Store in big-endian format. Perform endian conversion as necessary */
void Store64x2(const uint64x2_p8 src, uint8_t dest[16])
{
#if defined(TEST_AES_XLC)
	/* http://stackoverflow.com/q/46124383/608639 */
	vec_xst_be((uint8x16_p8)src, 0, (uint8_t*)dest);
#else
	/* GCC, Clang, etc */
# if defined(TEST_AES_LITTLE_ENDIAN)
	vec_vsx_st(Reverse8x16((uint8x16_p8)src), 0, dest);
# else
	vec_vsx_st((uint8x16_p8)src, 0, dest);
# endif
#endif
}

int main(int argc, char* argv[])
{
	/* FIPS 197, Appendix B input */
	const uint8_t input[17] = { /* user input, unaligned buffer */
		-1, 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};

	/* FIPS 197, Appendix B key */
	const uint8_t key[18] = { /* user input, unaligned buffer */
		-1, -1, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x9 , 0xcf, 0x4f, 0x3c
	};

	/* FIPS 197, Appendix B expanded subkeys */
	__attribute__((aligned(16)))
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
	uint8_t result[19] = { /* user output, unaligned buffer */
		-1, -1, -1
	};

#if defined(TEST_AES_XLC)

	/* Ensure we are exercising unaligned user buffers */
	uint8x16_p8 s = Load8x16(input+1);
	uint8x16_p8 k = Load8x16(key+2);
	s = vec_xor(s, k);

	k = Load8x16(subkeys[0]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[1]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[2]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[3]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[4]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[5]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[6]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[7]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[8]);
	s = __vcipher(s, k);

	k = Load8x16(subkeys[9]);
	s = __vcipherlast(s, k);

	/* Ensure we are exercising unaligned user buffers */
	Store8x16(s, result+3);

#elif defined(TEST_AES_GCC)

	/* Ensure we are exercising unaligned user buffers */
	uint64x2_p8 s = Load64x2(input+1);
	uint64x2_p8 k = Load64x2(key+2);
	s = vec_xor(s, k);

	k = Load64x2(subkeys[0]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[1]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[2]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[3]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[4]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[5]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[6]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[7]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[8]);
	s = __builtin_crypto_vcipher(s, k);

	k = Load64x2(subkeys[9]);
	s = __builtin_crypto_vcipherlast(s, k);

	/* Ensure we are exercising unaligned user buffers */
	Store64x2(s, result+3);

#endif

	printf("Input: ");
	for (unsigned int i=1; i<17; ++i)
		printf("%02X ", input[i]);
	printf("\n");

	printf("Key: ");
	for (unsigned int i=2; i<18; ++i)
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
