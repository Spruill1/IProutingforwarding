#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "ipsum.h"
#include <netinet/ip.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <string.h>
#include <fstream>
#include <sstream>

#define IP_LENGTH 16
#define TTL_MAX 16
#define MTU 1400
#define IN_BUFFER_SIZE (1024 * 64)
#define UPDATE_TIMER 5000 //(5000ms = 5seconds)
#define EXPIRE_TIMER 12000
#define ROUTING_ENTRIES_MAX 64
#define RIP_DATA 200



int main(int argv, char* argc[]){
	int nodeSocket;
	if((nodeSocket=socket(AF_INET, SOCK_DGRAM, 0))==-1) {
		perror("create socket failed:");
		exit(1);
	}
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(17003);

	struct sockaddr_in c_addr;
	c_addr.sin_family = AF_INET;
	inet_aton("127.0.0.1",&c_addr.sin_addr);
	c_addr.sin_port = htons(17001);

	socklen_t slen = sizeof(struct sockaddr_in);

	if((bind(nodeSocket,(struct sockaddr *)&addr, slen))==-1){
		perror("bind failed:");
		exit(1);
	}
	
	char buf[20] = "David says hi!";	

	while(1){
		if((sendto(nodeSocket, buf, 20, 0, (struct sockaddr *)&c_addr, sizeof(c_addr)))==-1){
			perror("sendto died painfully:");
			exit(1);
		}
		printf("Packet Sent\n");
		sleep(5);
	}
}
