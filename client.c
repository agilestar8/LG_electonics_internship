#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <mqueue.h>
#include <time.h>
#include <stdint.h>
#include <openssl/cmac.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#define KEY_BIT 128
#define KEYSIZE 64
#define MACSIZE 16
#define PSKSIZE 16

//typedef uint8_t U8;
typedef unsigned char U8;

// AES_CBC Encrypt
int aes_encrypt( U8 *p_in, U8 *p_out, int size, U8 *key)
{
	AES_KEY aes_key;            // aes_key structure 
	U8 iv_aes[AES_BLOCK_SIZE];      // initialize vectore
	bzero(iv_aes, sizeof(iv_aes));  // insert 0 to iv_array
 
    AES_set_encrypt_key(key, KEY_BIT, &aes_key);                  // set cipher key
	AES_cbc_encrypt( p_in, p_out, size, &aes_key , iv_aes, AES_ENCRYPT); // encrypting

	return 0;
}

// AES_CBC Decrypt
int aes_decrypt( U8 *p_in, U8 *p_out, int size, U8 *key)
{
	AES_KEY dec_key;
	U8 iv_aes[AES_BLOCK_SIZE];
	bzero(iv_aes, sizeof(iv_aes));

	AES_set_decrypt_key(key, KEY_BIT, &dec_key);
	AES_cbc_encrypt( p_in, p_out, size, &dec_key , iv_aes, AES_DECRYPT);

	return 0;
}

// Print Array
void printBytes(U8 *arr, size_t len){
	for (int i=0;i<len;i++){
		printf("0x%02x ", arr[i]);
	}
	printf("\n");
}


// clinet.c
int main(int argc, char **argv)
{
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


	// Mac Key
	static const U8 mac_key[] = {   0x2b,0x7e,0x15,0x16, 
									0x28,0xae,0xd2,0xa6,
									0xab,0xf7,0x15,0x88,
									0x09,0xcf,0x4f,0x3c};
	printf("---------------------------------------------------------------------------------------------\n");

	// PSS KEY
	U8 PSS_KEY[PSKSIZE];
	for(int i=4;i<20;i++){
		PSS_KEY[i-4] = cipher_key[i];
	}
	printBytes(cipher_key, 20);
	printBytes(PSS_KEY,sizeof(PSS_KEY));


	U8 p_encrypt[KEYSIZE];         
	U8 p_decrypt[KEYSIZE];         
	U8 p_temp[1024];
	int encrypt_size = ((sizeof(cipher_key) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;


	// Encrypt by PSS_KEY
	aes_encrypt(cipher_key, p_encrypt, sizeof(cipher_key), PSS_KEY);

	// Decrypt
	memcpy(p_temp, p_encrypt, encrypt_size);    
	aes_decrypt(p_temp, p_decrypt, encrypt_size, PSS_KEY);   
	int padding_gap = encrypt_size - sizeof(cipher_key);

	printf("[CLIENT] Cipher KEY(hex) : \n");
	printBytes(cipher_key, KEYSIZE-padding_gap);

	printf("\n[CLIENT] KEY Encrypt : \n");
	printBytes(p_encrypt, KEYSIZE);

	printf("\n[CLIENT] KEY Decrypt : \n");
	printBytes(p_decrypt, KEYSIZE-padding_gap);


	// Crate MAC 
	U8 mact[MACSIZE] = {0};	// MAC 
	size_t mactlen;

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, mac_key, MACSIZE, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, p_encrypt, sizeof(p_encrypt));
	CMAC_Final(ctx, mact, &mactlen);
	printf("\n[CLIENT] Generated CMAC : \n");
	printBytes(mact, mactlen);
	CMAC_CTX_free(ctx);


	// Concat KEY+CMAC
	U8 AEAD[KEYSIZE+MACSIZE] = {};

	for(int i=0;i<KEYSIZE;i++){
		AEAD[i] = p_encrypt[i];
	}
	for(int i=KEYSIZE;i<KEYSIZE+MACSIZE;i++){
		AEAD[i] = mact[i-KEYSIZE];
	}

	printf("\n[CLIENT] AEAD : \n");
	printBytes(AEAD,KEYSIZE+MACSIZE);


	// MQ Send
    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    mqd_t mq;
    U8 buf[KEYSIZE+MACSIZE];

    mq = mq_open("/mq_buf", O_WRONLY, 0666, &attr);
    if(mq == -1){
        perror("open error");
        exit(0);
    }

	if((mq_send(mq, AEAD, sizeof(AEAD), 1)) == -1){
		perror("MQ_send error");
        exit(-1);
    }
    mq_close(mq);
	
	printf("\n[CLIENT CLOSED]\n");
	return 0;
}



