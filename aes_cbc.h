#ifndef AES_CBC
#define AES_CBC
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/cmac.h>
#include <stdint.h>
#define KEYSIZE 60 
#define MACSIZE 16
#define KEY_BIT 128

//typedef uint8_t U8;
typedef unsigned char U8;

// Cipher Key
static U8 cipher_key[] = 
						{0x00,0x01, 
						 0x00,0x10, 
						 0xAA,0xAA,0xAA,0xAA,
						 0xAA,0xAA,0xAA,0xAA,
						 0xAA,0xAA,0xAA,0xAA,
						 0xAA,0xAA,0xAA,0xAA,
						 0x00,0x02,
						 0x00,0x10,
						 0xBB,0xBB,0xBB,0xBB,
						 0xBB,0xBB,0xBB,0xBB,
						 0xBB,0xBB,0xBB,0xBB,
						 0xBB,0xBB,0xBB,0xBB,
						 0x00,0x03,
						 0x00,0x10,
						 0xCC,0xCC,0xCC,0xCC,
						 0xCC,0xCC,0xCC,0xCC,
						 0xCC,0xCC,0xCC,0xCC,
						 0xCC,0xCC,0xCC,0xCC};


// Mac Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
static const U8 mac_key[] = {  0x2b,0x7e,0x15,0x16, 
						0x28,0xae,0xd2,0xa6,
						0xab,0xf7,0x15,0x88,
						0x09,0xcf,0x4f,0x3c};
	

// AES_CBC Encrypt
int aes_encrypt( U8 *p_in, U8 *p_out, int size)
{
	AES_KEY enc_aes_key;            // aes_key structure 
	U8 iv_aes[AES_BLOCK_SIZE];      // initialize vectore
	bzero(iv_aes, sizeof(iv_aes));  // insert 0 to iv_array
 
    AES_set_encrypt_key(cipher_key, KEY_BIT, &enc_aes_key);                  // set cipher key
	AES_cbc_encrypt( p_in, p_out, size, &enc_aes_key , iv_aes, AES_ENCRYPT); // encrypting
	//AES_cbc_encrypt( p_in, p_out, sizeof(p_in), &enc_aes_key , iv_aes, AES_ENCRYPT);

	return 0;
}


// AES_CBC Decrypt
int aes_decrypt( U8 *p_in, U8 *p_out, int size)
{
	AES_KEY dec_aes_key;
	U8 iv_aes[AES_BLOCK_SIZE];
	bzero(iv_aes, sizeof(iv_aes));

	AES_set_decrypt_key(cipher_key, KEY_BIT, &dec_aes_key);
	AES_cbc_encrypt( p_in, p_out, size, &dec_aes_key , iv_aes, AES_DECRYPT);

	return 0;
}


// Print Array
void printBytes(U8 *arr, size_t len){
	for (int i=0;i<len;i++){
		printf("0x%02x ", arr[i]);
	}
	printf("\n");
}

#endif
