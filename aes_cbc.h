#ifndef AES_CBC
#define AES_CBC
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <stdint.h>

//typedef unsigned char U8;
//static const U8 cipher_key[] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};

typedef uint8_t U8;
static const uint8_t cipher_key[20] = 
						{0x01,0x0F,0x10,0x10,0x10,
			 		     0x10,0x10,0x10,0x10,0x10,
			 		     0x10,0x10,0x10,0x10,0x10,	
			 		     0x10,0x10,0x10,0x10,0x10};

/*
						{0x02,0x0F,0x11,0x11,0x11,
						 0x11,0x11,0x11,0x11,0x11,
						 0x11,0x11,0x11,0x11,0x11,	
						 0x11,0x11,0x11,0x11,0x11},
						{0x03,0x0F,0x12,0x12,0x12,
						 0x12,0x12,0x12,0x12,0x12,
						 0x12,0x12,0x12,0x12,0x12,	
						 0x12,0x12,0x12,0x12,0x12}};
*/


#define KEY_BIT 128

int aes_decrypt( U8 *p_in, U8 *p_out, int size)
{
	AES_KEY aes_key;
	U8 iv_aes[AES_BLOCK_SIZE];
	bzero(iv_aes, sizeof(iv_aes));

	AES_set_decrypt_key( cipher_key, KEY_BIT, &aes_key);
	AES_cbc_encrypt( p_in, p_out, size, &aes_key , iv_aes, AES_DECRYPT);
	return 0;
}

  
int aes_encrypt( U8 *p_in, U8 *p_out, int size)
{
	AES_KEY aes_key;                // aes_key structure declare
	U8 iv_aes[AES_BLOCK_SIZE];      // initialize vector array declare
	bzero(iv_aes, sizeof(iv_aes));  // insert 0 to iv_array
 
    AES_set_encrypt_key(cipher_key, KEY_BIT, &aes_key);                  // set cipher key
	AES_cbc_encrypt( p_in, p_out, size, &aes_key , iv_aes, AES_ENCRYPT); // encrypting plain_text

	return 0;
}

#endif
