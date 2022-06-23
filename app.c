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
*/


	return 0;
}


