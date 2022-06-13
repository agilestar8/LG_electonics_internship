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

#define KEYSIZE 60
typedef uint8_t U8; 

int main(int argc, char **argv)
{

	// key setting

/*	
	uint8_t key[3][20] = {{0x01,0x0F,0x10,0x10,0x10, //01 0F AAAA...
						  0x10,0x10,0x10,0x10,0x10,
						  0x10,0x10,0x10,0x10,0x10,	
						  0x10,0x10,0x10,0x10,0x10}, 
						{0x02,0x0F,0x11,0x11,0x11,
						  0x11,0x11,0x11,0x11,0x11,
						  0x11,0x11,0x11,0x11,0x11,	
						  0x11,0x11,0x11,0x11,0x11},
						{0x03,0x0F,0x12,0x12,0x12,
						  0x12,0x12,0x12,0x12,0x12,
						  0x12,0x12,0x12,0x12,0x12,	
						  0x12,0x12,0x12,0x12,0x12}};
*/	


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
	printf("[CLIENT] client key(hex) : ");
	for (i=0; i<sizeof(cipher_key); i++){
		printf("0x%02x ", cipher_key[i]);
	}
	printf("\n");

	printf("\n[CLIENT] encrypt : ");
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

	//memcpy(buf,key[0],sizeof(key[0]));


	printf("\n");
	//for (i=0;i<sizeof(buf);i++){
	//printf("%c ",buf);}
	

    mq = mq_open("/mq_buf", O_WRONLY, 0666, &attr);
    if(mq == -1){
        perror("open error");
        exit(0);
    }

    //scanf("%s", buf);
    if((mq_send(mq, p_encrypt, strlen(p_encrypt), 1)) == -1){
            perror("mq_send error");
            exit(-1);
    }
    mq_close(mq);
	


	return 0;
}

