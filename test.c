#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<mqueue.h>
#include<openssl/aes.h>
#include<openssl/des.h>
#include<openssl/cmac.h>
#include<errno.h>
#define KEY_BIT 128
#define KEYSIZE 64
#define MACSIZE 16
// TEST.c

typedef uint8_t U8;
//typedef unsigned char U8;
#define ENC_ERR_NONE 0
#define ENC_ERR_FAIL 1
// AES_CBC Encrypt
int aes_encrypt( U8 *p_in, U8 *p_out, int size, U8 *key)
{
	AES_KEY aes_key;            // aes_key structure 
	U8 iv_aes[AES_BLOCK_SIZE];      // initialize vectore
	bzero(iv_aes, sizeof(iv_aes));  // insert 0 to iv_array
 
    int ret=0;
	ret = AES_set_encrypt_key(key, KEY_BIT, &aes_key);                  // set cipher key
	if(ret){
		return ENC_ERR_FAIL;
	}
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

typedef struct message{
	int cmd;
	char buffer[80];
	int ret;
}msg;

int main(){
	
	struct mq_attr attr;
	attr.mq_maxmsg = 10;
	attr.mq_msgsize = 128;
	mqd_t mq;

	msg m;
	m.cmd = 1;
	strcpy(m.buffer, "Hello");
	m.ret = 0;

	printf("[TEST] m %d\n", m.cmd);
	printf("[TEST] %s\n", m.buffer);
	printf("[TEST] %d\n", m.ret);
	
	mq = mq_open("/mq_buf", O_RDWR|O_CREAT, 0666, &attr);
	if (mq == -1){
		perror("[TEST] send error");
		return 0;
	}
	mq_send(mq, (const char *) &m, sizeof(m)+1,1);


	msg m2;
	if(mq_receive(mq, (char *) &m2, sizeof(m2)+128, NULL) == -1){
		perror("[TEST] receive error : ");
	}
	mq_close(mq);
	
	printf("[TEST] m2 %d\n", m2.cmd);
	printf("[TEST] %s\n", m2.buffer);
	printf("[TEST] %d\n", m2.ret);
	



/*
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
	static const U8 mac_key[] = {0x2b,0x7e,0x15,0x16, 
							 	 0x28,0xae,0xd2,0xa6,
								 0xab,0xf7,0x15,0x88,
								 0x09,0xcf,0x4f,0x3c};

	
	U8 PSS_KEY[16];
	for(int i=4;i<20;i++){
		PSS_KEY[i-4] = cipher_key[i];
	}
	//printBytes(cipher_key, KEYSIZE);
	//printBytes(PSS_KEY,sizeof(PSS_KEY));
	printf("\n");

	int encrypt_size = ((sizeof(cipher_key) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;


	U8 p_encrypt[KEYSIZE] = {0,};         
	U8 p_decrypt[KEYSIZE];         
	U8 p_temp[1024];

	// Encrypt
	aes_encrypt(cipher_key, p_encrypt, sizeof(cipher_key), PSS_KEY);

	// Decrypt
	memcpy(p_temp, p_encrypt, encrypt_size);    
	aes_decrypt(p_temp, p_decrypt, encrypt_size, PSS_KEY );   


	// key save and load	
	int fd;
	U8 key_buf[KEYSIZE]={0,};
	umask(0);

	if (open("file.dlc",O_RDONLY,0666)== -1){
		
		fd = open("file.dlc",O_WRONLY,0666);
		write(fd, p_decrypt, KEYSIZE);
		printf("[SERVER] don't have key, create key file :\n");	
		close(fd);
		return 0;
	}

	fd = open("file.dlc",O_RDONLY,0666);	
	read(fd,key_buf,KEYSIZE);
	for(int i=0;i<KEYSIZE;i++)
		printf("%02x ",key_buf[i]);
//	printBytes(key_buf,KEYSIZE);
	printf("\n");
	close(fd);

*/




//	printBytes(p_encrypt, sizeof(p_encrypt));




	

	return 0;
}
