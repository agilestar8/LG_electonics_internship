#include<stdio.h>
#include<stdlib.h>
#include<string.h> 
#include<sys/msg.h>
#include<sys/ipc.h>
#include<sys/types.h>
#include<fcntl.h>
#include<mqueue.h>
#include<sys/stat.h>
#include<time.h>
 
int main(){
 
     struct mq_attr attr;
     attr.mq_maxmsg = 10;
     attr.mq_msgsize = 128;
      char buf[128] = {0,};
 
      mqd_t mq;
 
      mq = mq_open("/message", O_RDWR | O_CREAT, 0666, &attr);
      if (mq == -1){
          perror("message queue open error");
         exit(1);
     }
 
      if(mq_receive(mq, buf, attr.mq_msgsize,NULL) == -1){
          perror("mq_receive error");
          exit(-1);
      }
 
      printf("mq received : %s\n", buf);
 
      return 0;
  }

