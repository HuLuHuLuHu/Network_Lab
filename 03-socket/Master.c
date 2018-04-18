/* Master application */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

char location[19] = "./war_and_peace.txt";

int main (int argc,char *argv[])
{

	int sock1,sock2;
	FILE *war = fopen(location,"r");
	fseek(war,0L,SEEK_END);
	int len = ftell(war);
	int offset = len/2;
	uint32_t off_n = htonl(offset);
	uint32_t len_n = htonl(len);
printf("%d,%d,%d,%d\n",offset,len,off_n,len_n);
	fclose(war);
	struct sockaddr_in worker1,worker2;
	uint32_t reply1[26] = {0}, reply2[26] = {0};
	
	//create socket
	sock1 = socket(AF_INET,SOCK_STREAM,0);
	if(sock1 == -1)
	printf("Could not create socket1!\n");
	else 
	printf("Socket1 created!\n");

	sock2 = socket(AF_INET,SOCK_STREAM,0);
	if(sock2 == -1)
	printf("Could not create socket2!\n");
	else 
	printf("Socket2 created!\n");

	worker1.sin_addr.s_addr = inet_addr("10.0.0.2");
	worker1.sin_family = AF_INET;
	worker1.sin_port = htons( 9999 );
	worker2.sin_addr.s_addr = inet_addr("10.0.0.3");
	worker2.sin_family = AF_INET;
	worker2.sin_port = htons( 9999 );	

	if(connect(sock1,(struct sockaddr *)&worker1,sizeof(worker1)) < 0){
	printf("worker1 connect failed!!\n");
	return -1;
	}
	printf("Worker1 Connected!!\n");


	if(connect(sock2,(struct sockaddr *)&worker2,sizeof(worker2)) < 0){
	printf("worker2 connect failed!!\n");
	return -1;
	}
	printf("worker2 Connected!!\n");
	if(send(sock1,location,20,0)<0){
	printf("Send failed!\n");
	return -1;
	}
	uint32_t zero = htonl(0);
	if(send(sock1, &zero, sizeof(int),0)<0){
	printf("Send failed!\n");
	return -1;
	}
	
	if(send(sock1, &off_n, sizeof(int),0)<0){
	printf("Send failed!\n");
	return -1;
	}


	if(send(sock2,location,20,0)<0){
	printf("Send failed!\n");
	return -1;
	}

	if(send(sock2,&off_n,sizeof(int),0)<0){
	printf("Send failed!\n");
	return -1;
	}

	if(send(sock2,&len_n,sizeof(int),0)<0){
	printf("Send failed!\n");
	return -1;
	}

	
	if(recv(sock1,(char*)reply1, 26*sizeof(uint32_t), 0) <0)
	printf("rsv failed!\n");
	if(recv(sock2,(char*)reply2, 26*sizeof(uint32_t), 0) <0)
	printf("rsv failed!\n");

	uint32_t result1[26] = {0}, result2[26] = {0};
	for(int j=0;j<26;j++){
	result1[j] = ntohl(reply1[j]);
	result2[j] = ntohl(reply2[j]);	
	}

	for(int i=0; i<26; i++)
	result1[i] += result2[i];
	
	for(int j=0; j<26; j++)
	printf("%c : %d\n",'a'+j, result1[j]);
	close(sock1);
	close(sock2);
	return 0;
}
