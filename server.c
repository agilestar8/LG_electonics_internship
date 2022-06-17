#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_cbc.h"
#include <fcntl.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>

// server.c
int main(int argc, char *args[])
{
	printf("Run Server\n");

    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    U8 buf[KEYSIZE+MACSIZE] = {};
 
    mqd_t mq; 
 
	// MQ open
    mq = mq_open("/mq_buf", O_RDWR | O_CREAT, 0666, &attr);
    if (mq == -1){
		perror("message queue open error");
        exit(1);
     }
	
	// MQ receive
    if(mq_receive(mq, buf, attr.mq_msgsize,NULL) == -1){
        perror("mq_receive error");
		exit(-1);
    }

	printf("\n[SERVER] Received buffer length : %ld\n", sizeof(buf));
	printf("[SERVER] Received buffer : \n");
	printBytes(buf,sizeof(buf));
	printf("\n");


	// Decryption
	U8 s_encrypt[KEYSIZE];
	U8 s_decrypt[KEYSIZE];		
	U8 temp[1024];	
	int encrypt_size;	

	// Devide buffer to encrypted_key and CMAC
	U8 r_encrypt[KEYSIZE+MACSIZE];
	U8 r_mac[MACSIZE];	
	for(int i=0; i<KEYSIZE; i++){
		r_encrypt[i] = buf[i];
	}
	for(int i=KEYSIZE;i<KEYSIZE+MACSIZE;i++){
		r_mac[i-KEYSIZE] = buf[i];
	}
	
	encrypt_size = ((sizeof(r_encrypt) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	memcpy(temp, r_encrypt, encrypt_size);		
	aes_decrypt(temp, s_decrypt, encrypt_size);
	int padding_gap = encrypt_size - sizeof(cipher_key);

	printf("[SERVER] Received Key: \n");
	printBytes(r_encrypt,KEYSIZE);
	printf("\n");	 
	printf("[SERVER] Decrypted Key : \n");
	printBytes(s_decrypt,KEYSIZE-padding_gap);
	printf("\n");	

	// Re Encrpyt
	aes_encrypt(s_decrypt, s_encrypt, sizeof(cipher_key));
	printf("[SERVER] Re Encrpyt : \n");
	printBytes(s_encrypt,KEYSIZE);
	printf("\n");


	// Crate CMAC 
	U8 server_mac[MACSIZE] = {0}; 
	size_t mactlen;

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, mac_key, MACSIZE, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, r_encrypt, KEYSIZE);
	CMAC_Final(ctx, server_mac, &mactlen);
	CMAC_CTX_free(ctx);

	printf("[SERVER] CLIENT MAC: \n");
	printBytes(r_mac,MACSIZE);
	printf("\n");	 

	printf("[SERVER] SERVER MAC : \n");
	printBytes(server_mac, mactlen);	
	printf("\n");

	/*
	if (strcmp(r_mac,server_mac)==1){
		printf("MAC Verified\n");
	}
	else{
		printf("MAC don't Verified\n");
	}*/


	FILE* fp = fopen("stored_key.txt", "w");
	fputs(s_encrypt,fp);
	if(fp == NULL){
		printf("\nno file\n");
		return 0;
	}

	fclose(fp);

	printf("[SERVER CLOSED]\n");

	return 0;
}
