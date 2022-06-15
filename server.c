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

	printf("\nbuffer length : %ld\n", sizeof(buf));


	// Key Decryption
	U8 p_decrypt[KEYSIZE];		
	U8 p_temp[1024];	
	int encrypt_size;
	
	U8 r_encrypt[KEYSIZE];
	for(int i=0; i<KEYSIZE; i++){
		r_encrypt[i] = buf[i];
	}

	U8 r_mac[MACSIZE];
	for(int i=KEYSIZE;i<KEYSIZE+MACSIZE;i++){
		r_mac[i-KEYSIZE] = buf[i];
	}

	//aes_encrypt(cipher_key,p_encrypt,sizeof(cipher_key));
	encrypt_size = ((sizeof(cipher_key) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	memcpy(p_temp, r_encrypt, encrypt_size);		
	aes_decrypt(p_temp, p_decrypt, encrypt_size);

	printf("\n[SERVER] Received AEAD : ");
	printBytes(buf,sizeof(buf));
	printf("\n");

	printf("[SERVER] Received Key: ");
	printBytes(r_encrypt,KEYSIZE);
	printf("\n");	 

	printf("[SERVER] Received MAC: ");
	printBytes(r_mac,MACSIZE);
	printf("\n");	 

	printf("[SERVER] Decrypted Key : ");
	printBytes(p_decrypt,KEYSIZE);
	printf("\n");
	

	// Crate CMAC 
	U8 server_mac[MACSIZE] = {0}; 
	size_t mactlen;

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, mac_key, MACSIZE, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, r_encrypt, sizeof(r_encrypt));
	CMAC_Final(ctx, server_mac, &mactlen);
	CMAC_CTX_free(ctx);
	printf("[SERVER] Generated CMAC : ");
	printBytes(server_mac, mactlen);	

	printf("\n[SERVER CLOSED]\n");

	return 0;
}
