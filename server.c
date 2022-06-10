#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <openssl/aes.h>
//#include <openssl/des.h>
#include "aes_cbc.h"
#include <fcntl.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>

int main(int argc, char *args[])
{

    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    U8 buf[128] = {0,};
 
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


	// Key Decryptio
	
	//U8 p_encrypt[1024];         // encrypted text
	U8 p_decrypt[128];         // decrypted text
	U8 p_temp[128];            // to fill 128 bit
	int encrypt_size;

	encrypt_size = (sizeof(buf) + AES_BLOCK_SIZE) / 16 * 16;
	memcpy(p_temp, buf, encrypt_size);        // for padding
	aes_decrypt(p_temp, p_decrypt, encrypt_size);   // for padding

	printf("received key : %s \n", buf);

	int i;
	printf("decrypted : ");
	for ( i = 0; i < sizeof(buf); i++){
		printf( "0x%02x ", p_decrypt[i]);
	}
	 printf("\n");	 


	return 0;
}
