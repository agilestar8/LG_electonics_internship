#include <stdlib.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "aes_cbc.h"
//#include<openssl/aes.h>
//#include<openssl/des.h>

typedef uint8_t U8; 

int main(int argc, char **argv)
{

	// Encrypt

	U8 p_encrypt[1024];         
	U8 p_decrypt[1024];         
	U8 p_temp[1024];
	int encrypt_size;

	aes_encrypt(cipher_key, p_encrypt, sizeof(cipher_key)); // (plaintext, encrypted, size)
	encrypt_size = (sizeof(cipher_key) + AES_BLOCK_SIZE) /16 * 16;
  
	// Decrypt
	memcpy(p_temp, p_encrypt, encrypt_size);        // for padding
	aes_decrypt(p_temp, p_decrypt, encrypt_size);   // decrypt

	int i;
	printf("[CLIENT] Cipher key(hex) : ");
	for (i=0; i<sizeof(cipher_key); i++){
		printf("0x%02x ", cipher_key[i]);
	}

	printf("\n\n[CLIENT] encrypt : ");
	for (i=0; i<sizeof(cipher_key); i++){
		printf("0x%02x ", p_encrypt[i]);
	}
	
	printf("\n\n");
	printf("[CLIENT] decrypt : ");
	for (i=0; i<KEYSIZE; i++){
		printf("0x%02x ", p_decrypt[i]);
	}


	// MQ Send
	
    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    mqd_t mq;
    U8 buf[128];

	printf("\n");

    mq = mq_open("/mq_buf", O_WRONLY, 0666, &attr);
    if(mq == -1){
        perror("open error");
        exit(0);
    }

	if((mq_send(mq, p_encrypt, strlen(p_encrypt), 1)) == -1){
            perror("mq_send error");
            exit(-1);
    }
    mq_close(mq);
	


	return 0;
}

