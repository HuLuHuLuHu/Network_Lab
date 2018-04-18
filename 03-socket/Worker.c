/* Worker appication */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc,const char*argv[])
{
	int sock,c_sock;
	struct sockaddr_in worker;
	char message[2000];
	int count[26] = {0};
	if((sock = socket(AF_INET, SOCK_STREAM,0)) < 0){
	        perror("Could not create socket");
		return -1;	
	}
	printf("Socket Created!\n");

	worker.sin_family = AF_INET;
	worker.sin_addr.s_addr = INADDR_ANY;
	worker.sin_port = htons(9999);

	if(bind(sock,(struct sockaddr *)&worker,sizeof(worker)) < 0) 	{
	perror("bind failded. Error!\n");
	return -1;
	}
	printf("bind done !\n");

	listen(sock,1);

	printf("waiting for incoming connections ...");

	int c = sizeof(struct sockaddr_in);
    if ((c_sock = accept(sock, (struct sockaddr *)&worker, (socklen_t *)&c)) < 0) {
        perror("accept failed");
        return 1;
    }
	printf("Connection accepted");
     
	int msg_len = 0;
    // Receive a message from client
char location[100];
uint32_t start_n,end_n,start,end;
   if ((recv(c_sock, location, 20, 0)) < 0)
	printf("error!\n");
   if ((recv(c_sock, &start_n, sizeof(int), 0)) < 0)
	printf("error!\n");
   if ((recv(c_sock, &end_n, sizeof(int), 0)) < 0)
	printf("error!\n");
start = ntohl(start_n);
end = ntohl(end_n);
printf("%d,%d\n",start,end);
	FILE *file = fopen(location,"r");
	fseek(file,start,SEEK_SET);
	char temp;
	for(int i=start; i< end;i++){
	temp = fgetc(file);
	if(temp <= 'Z' && temp >= 'A')
	count[(int)temp-'A']++;
	if(temp <= 'z' && temp >= 'a')
	count[(int)temp-'a']++;
	}
	fclose(file);
	uint32_t send_n[26];
   	for(int j=0; j<26; j++)
	send_n[j] = htonl(count[j]);
   	for(int j=0; j<26; j++)
printf("%d\n",count[j]);
	if(send(c_sock,(char*)send_n,26*sizeof(uint32_t),0)<0){
	printf("Send failed!\n");
	return -1;
	}
    return 0;

}
