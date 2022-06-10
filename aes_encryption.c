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


//typedef uint8_t U8;
//static const U8 cipher_key[] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
//#define KEY_BIT 128

/*
int aes_encrypt( U8 *p_in, U8 *p_out, int size)
{
          AES_KEY aes_key;                // aes_key structure declare
          U8 iv_aes[AES_BLOCK_SIZE];      // initialize vector array declare
          bzero(iv_aes, sizeof(iv_aes));  // insert 0 to iv_array
 
          AES_set_encrypt_key(cipher_key, KEY_BIT, &aes_key);                  // set cipher key
          AES_cbc_encrypt( p_in, p_out, size, &aes_key , iv_aes, AES_ENCRYPT); // encrypting plain_text
 
          return 0;
}


int aes_decrypt( U8 *p_in, U8 *p_out, int size)
{
         AES_KEY aes_key;
         U8 iv_aes[AES_BLOCK_SIZE];
         bzero(iv_aes, sizeof(iv_aes));
 
          AES_set_decrypt_key( cipher_key, KEY_BIT, &aes_key);
          AES_cbc_encrypt( p_in, p_out, size, &aes_key , iv_aes, AES_DECRYPT);
          return 0;
}
*/


int main(int argc, char *args[])
{
	// key setting

	/*
	uint8_t key[3][20] = {{0x01,0x0F,0x10,0x10,0x10,
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
						  0x12,0x12,0x12,0x12,0x12}
	};
	*/


	// Encrypt part
	
	//U8 plaintext[] = {0x01, 0x02, 0x03, 0x04, 0x05};	//test1
	//U8 *plaintext = "abcedf";	// test2
	//U8 plaintext[17];
	
	U8 p_encrypt[1024];         // encrypted text
	U8 p_decrypt[1024];         // decrypted text
	U8 p_temp[1024];            // to fill 128 bit
	int encrypt_size;
	aes_encrypt(plaintext, p_encrypt, sizeof(plaintext));   // (plaintext, encrypted text array, text size)
	encrypt_size = (sizeof(plaintext) + AES_BLOCK_SIZE) /16 * 16;
  
	memcpy(p_temp, p_encrypt, encrypt_size);        // for padding
	aes_decrypt(p_temp, p_decrypt, encrypt_size);   // for padding

	printf("key data : %s \n", plaintext);
	printf("aes-cbc encrypt : ");
	int i;
	for (i=0; i<sizeof(plaintext); i++){
		printf("0x%02x ", p_encrypt[i]);
	}
	
	printf("\n");
	printf("aes-cbc decrypt : ");
	int ndx;
	for ( ndx = 0; ndx < sizeof(plaintext); ndx++){
		printf( "0x%02x ", p_decrypt[ndx]);
	}
	 printf("\n");	 
	 printf("decrypted : %s\n", p_decrypt);


	// server part

    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    char buf[128] = {0,};
 
    mqd_t mq; 
 
    mq = mq_open("/mq_buf", O_RDWR | O_CREAT, 0666, &attr);
    if (mq == -1){
		perror("message queue open error");
        exit(1);
     }
 
    if(mq_receive(mq, buf, attr.mq_msgsize,NULL) == -1){
        perror("mq_receive error");
		exit(-1);
    }
 
    printf("received MQ : %s\n", buf);
	
	return 0;
}


