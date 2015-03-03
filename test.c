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
	addr.sin_port = htons(atoi(argc[1]));

	struct sockaddr_in c_addr;
	c_addr.sin_family = AF_INET;
	inet_aton("127.0.0.1",&c_addr.sin_addr);
	c_addr.sin_port = htons(atoi(argc[2]));

	socklen_t slen = sizeof(struct sockaddr_in);

	if((bind(nodeSocket,(struct sockaddr *)&addr, slen))==-1){
		perror("bind failed:");
		exit(1);
	}
	
	char buf[128]="";
	struct ip * ip = (struct ip *)&buf[0];

	    //process package
	    // Must fill this up
	    ip->ip_hl = 5; //header length
	    ip->ip_v = 0; //version
	    ip->ip_tos = 0; //Type of service
	    ip->ip_len = htons(ip->ip_hl + 10); //Total length
	    ip->ip_id = 0; //id
	    ip->ip_off= 0; //offset
	    ip->ip_ttl = 0; //time to live
	    ip->ip_p = 200;
	    ip->ip_sum = 0; //checksum
	    ip->ip_src.s_addr = 0;
	    ip->ip_dst.s_addr = 0;

	char *payload = buf+ip->ip_hl*4;
	int pkt_id=0;

	while(1){
		ip->ip_p = 0;//pkt_id%3==0 ? 0:200;
		sprintf(payload,"pkt: %d",++pkt_id);
		if((sendto(nodeSocket, buf, 128, 0, (struct sockaddr *)&c_addr, sizeof(c_addr)))==-1){
			perror("sendto died painfully:");
			exit(1);
		}
		printf("Packet Sent\n");
		sleep(5);
	}
}
