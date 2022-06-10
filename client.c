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

	// key setting

	
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
	


	// Encrypt

	U8 p_encrypt[1024];         
	U8 p_decrypt[1024];         
	U8 p_temp[1024];
	int encrypt_size;

	aes_encrypt(key[0], p_encrypt, sizeof(key[0]));   // (plaintext, encrypted text array, text size)
	encrypt_size = (sizeof(key[0]) + AES_BLOCK_SIZE) /16 * 16;
  
	// Decrypt
	memcpy(p_temp, p_encrypt, encrypt_size);        // for padding
	aes_decrypt(p_temp, p_decrypt, encrypt_size);   // decrypt

	int i;
	printf("client key data(hex) : ");
	for (i=0; i<sizeof(key[0]); i++){
		printf("0x%02x ", key[0][i]);
	}

	printf("\nclient encrypt : ");
	for (i=0; i<sizeof(key[0]); i++){
		printf("0x%02x ", p_encrypt[i]);
	}
	
	printf("\n");
	printf("client decrypt : ");
	for (i=0; i<sizeof(key[0]); i++){
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

