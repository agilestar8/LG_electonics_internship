#include <stdlib.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <openssl/cmac.h>
#include "aes_cbc.h"

// clinet.c
int main(int argc, char **argv)
{
	printf("---------------------------------------------------------------------------------------------\n");
	// Encrypt
	U8 p_encrypt[KEYSIZE];         
	U8 p_decrypt[KEYSIZE];         
	U8 p_temp[KEYSIZE];
	int encrypt_size;

	aes_encrypt(cipher_key, p_encrypt, sizeof(cipher_key));
	
	// Decrypt
	encrypt_size = ((sizeof(cipher_key) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * 16;
	memcpy(p_temp, p_encrypt, encrypt_size);    
	aes_decrypt(p_temp, p_decrypt, encrypt_size);   

	
	printf("[CLIENT] Cipher KEY(hex) : ");
	printBytes(cipher_key, KEYSIZE);

	printf("\n[CLIENT] KEY Encrypt : ");
	printBytes(p_encrypt, KEYSIZE);
	
	printf("\n[CLIENT] KEY Decrypt : ");
	printBytes(p_decrypt, KEYSIZE);


	// Crate CMAC 
	U8 mact[MACSIZE] = {0};	// CMAC 
	size_t mactlen;

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, mac_key, MACSIZE, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, p_encrypt, sizeof(p_encrypt));
	CMAC_Final(ctx, mact, &mactlen);
	printf("\n[CLIENT] Generated CMAC : ");
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

	printf("\n[CLIENT] AEAD : ");
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
//	if((mq_send(mq, p_encrypt, strlen(p_encrypt), 1)) == -1){
            perror("MQ_send error");
            exit(-1);
    }
    mq_close(mq);
	
	printf("\n[CLIENT CLOSED]\n");
	printf("---------------------------------------------------------------------------------------------\n");

	return 0;
}



