#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<mqueue.h>
#include<stdint.h>
#define KEY_BIT 128
#define KEYSIZE 64
#define MACSIZE 16
#define PSKSIZE 16
typedef uint8_t U8;
// APP.c

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
typedef struct messeage{
	int cmd;
	U8 buffer[80];
	int ret;
}msg;


int main(int argc, char *argv[]){
// interface : ./app [num] plaintext	

//[num]
// 1.Encryption
// 2.Decryption	
// 3.CMAC Generation	
// 4.HMAC Generation


if (argc!=3){
		printf("usege : ./app [mode] [text]\n");
		return 0;
	}
	int argv1=0;
	char argv2[80];
	argv1 = atoi(argv[1]);
	strcpy(argv2,argv[2]);


 	// MQ
    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    mqd_t mq; 
 
	msg m;
	m.cmd = argv1;
	strcpy(m.buffer, argv2);
	m.ret = 0;

    mq = mq_open("/mq_buf", O_RDWR | O_CREAT, 0666, &attr);
    if (mq == -1){
		perror("message queue open error");
        exit(1);
     }
	
	// MQ send
	if((mq_send(mq, &m, sizeof(m), 1)) == -1){
		perror("[APP] MQ Send Error");
		exit(-1);
	}
	mq_close(mq);
	


	/* 서버에서 결과 보내준 거 받기
	// MQ receive
	mq = mq_open("/receive", O_RDWR | O_CREAT, 0666, &attr);
    if (mq == -1){
		perror("message queue open error");
        exit(1);
     }
    if(mq_receive(mq, response, attr.mq_msgsize,NULL) == -1){
        perror("mq_receive error");
		exit(-1);
    }
	mq_close(mq);

	printf(buf);


	// Create HMAC
	int hlen = sizeof(hmac_key);
	U8 hmac[1024];
	HMAC_CTX *ctx2 = HMAC_CTX_new();
	HMAC_CTX_reset(ctx2);
	HMAC_Init_ex(ctx2, hmac_key, MACSIZE, EVP_sha256(), NULL);
	HMAC_Update(ctx2, m.buffer, strlen(m.buffer));
	HMAC_Final(ctx2, hmac, &hlen);
	printf("[SERVER] HMAC Digest : \n");
	printBytes(hmac,strlen(hmac));
	HMAC_CTX_free(ctx2);

	*/

	return 0;
}


