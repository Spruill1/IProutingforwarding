#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "ipsum.h"
#include <netinet/ip.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <string.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

#include <future>//libraries for dealing with async input and time
#include <thread>
#include <chrono>

//using namespace std;

#define IP_LENGTH 16
#define TTL_MAX 16
#define MTU 1400
#define IN_BUFFER_SIZE (1024 * 64)
#define UPDATE_TIMER 5000 //(5000ms = 5seconds)
#define EXPIRE_TIMER 12000
#define ROUTING_ENTRIES_MAX 64
#define RIP_DATA 200

typedef struct node{
	uint32_t IP_me;
	int port_me;

	int fd;

	node(){port_me = 0; IP_me = 0; fd = -1;}
	void print(){printf("node:\t%x:%d\n",IP_me,port_me);}
} node;

typedef struct net_interface{
	int id;

	uint32_t IP_remote;
	uint16_t port_remote;
	uint32_t vip_me;
	uint32_t vip_remote;

	int sock;
	struct sockaddr_in addr;
	bool up;

	net_interface(int id_in){
			id = id_in;
			IP_remote = 0;
			port_remote = 0;
			vip_me = 0;
			vip_remote = 0;
			up = false;
    	}
	void print(){
		struct in_addr temp;
		temp.s_addr = vip_me;
		printf("%d\t%s\t%s\n",id,inet_ntoa(temp),up ? "up" : "down");
	}
	void initSocket(){
		if ((sock = socket(AF_INET, SOCK_DGRAM/*use UDP*/, IPPROTO_IP)) < 0 ){
			perror("Create socket failed:");
			exit(1);
		}
		up = true;
	}
	int sendPacket(char *data_with_header){
		if(!up) return -1; //the connection isn't up
		//TODO: write out the sendpacket routine
		//	create socket on the fly?

		return 0; //finished
	}

} net_interface;

typedef struct forwarding_table_entry {
	char dest[IP_LENGTH];
	uint16_t cost;
	int int_id;

	forwarding_table_entry() {memset(&dest[0], 0, IP_LENGTH);
				  cost=TTL_MAX;
				  int_id = -1;}
} forwarding_table_entry;

typedef struct forwarding_table {
	uint16_t num_entries;
	forwarding_table_entry entries[ROUTING_ENTRIES_MAX];
} forwarding_table;

typedef struct RIP {
	uint16_t command;
	uint16_t num_entries;
	struct {
		uint32_t cost;
		uint32_t address;
	} entries[ROUTING_ENTRIES_MAX];
} RIP;

node Node; //global for this node's information
std::vector<net_interface> myInterfaces; //the interfaces for this node
forwarding_table forwardingTable;

uint32_t IPStringToInt(std::string ip){
    if(ip=="localhost") {ip = "127.0.0.1";}
	uint32_t res=0;
	std::string nIP = std::string(ip.data());
	uint8_t B0 = atoi(nIP.substr(0,nIP.find(".")).c_str());
	nIP.erase(0,nIP.find(".")+1);
	uint8_t B1 = atoi(nIP.substr(0,nIP.find(".")).c_str());
	nIP.erase(0,nIP.find(".")+1);
	uint8_t B2 = atoi(nIP.substr(0,nIP.find(".")).c_str());
	nIP.erase(0,nIP.find(".")+1);
	uint8_t B3 = atoi(nIP.substr(0,nIP.length()).c_str());
	res+=B0; res=res<<8;
	res+=B1; res=res<<8;
	res+=B2; res=res<<8;
	res+=B3;
	return res;
}

int readFile(char* path, node *Node, std::vector<net_interface> * myInterfaces) {
	std::ifstream fin(path);

	std::string myInfo;
	getline(fin,myInfo);

	//get the IP & Port for this node
	Node->IP_me = IPStringToInt(myInfo.substr(0,myInfo.find(":")));
	Node->port_me = atoi(myInfo.substr(myInfo.find(":")+1,myInfo.npos).c_str());

	Node->print();

	//get the information for the interfaces
	while(!fin.eof()){
		myInfo.erase(0,myInfo.length());
		getline(fin,myInfo);
		net_interface myInt = net_interface(myInterfaces->size()+1);
		myInt.IP_remote = IPStringToInt(myInfo.substr(0,myInfo.find(":")));
			myInfo.erase(0,myInfo.find(":")+1);
		myInt.port_remote = atoi(myInfo.substr(0,myInfo.find(" ")).c_str());
			myInfo.erase(0,myInfo.find(" ")+1);
		myInt.vip_me = IPStringToInt(myInfo.substr(0,myInfo.find(" ")));
		IPStringToInt(myInfo.substr(0,myInfo.find(" ")));
			myInfo.erase(0,myInfo.find(" ")+1);
		myInt.vip_remote = IPStringToInt(myInfo);

		if(myInt.IP_remote!=0){
			myInt.initSocket();
			myInterfaces->push_back(myInt);
		}
	}

}

void createReadSocket(){
	int nodeSocket;
	if((nodeSocket=socket(AF_INET, SOCK_DGRAM, 0))==0) {
		perror("create socket failed:");
		exit(1);
	}
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(Node.port_me);

	if((bind(nodeSocket,(struct sockaddr *)&addr, sizeof(struct sockaddr)))==-1){
		perror("bind failed:");
		exit(1);
	}

	Node.fd = nodeSocket;
}

void cmd_ifconfig(){
	for(std::vector<net_interface>::iterator iter = myInterfaces.begin(); iter != myInterfaces.end(); ++iter)
	{
		iter->print();
	}
}

void cmd_routes(){}
void cmd_down(int id){
	if(id > myInterfaces myInterfaces[id-1].up = false;}
void cmd_up(int id){myInterfaces[id-1].up = true;}
void cmd_send(struct in_addr vip, char* msg){}

void processCommand(char* cmmd){
	char arg0[10], arg1[20], arg2[MTU]; //TODO: go back and give a better size for arg2
	sscanf(cmmd,"%s %s %s",arg0,arg1,arg2);
	if(strncmp(cmmd,"ifconfig",8)==0){
		cmd_ifconfig();
		return;
	}
	if(strncmp(cmmd,"routes",6)==0){
		cmd_routes();
		return;
	}
	if(strncmp(cmmd,"down",4)==0){
		cmd_down(atoi(arg1));
		return;
	}
	if(strncmp(cmmd,"up",2)==0){
		cmd_up(atoi(arg1));
		return;
	}
	if(strncmp(cmmd,"send",4)==0){
		struct in_addr vip;
		inet_aton(arg1,&vip);
		cmd_send(vip,arg2);
		return;
	}
}

bool isRIP(char* buff) { //is the packet a RIP packet?
	return false;
}

bool isIP(char* buff) { //is the packet an IP packet?
	return false;
}

void processIncomingPacket(char* buff) {

}

int main(int argv, char* argc[]){

	//if there is no arguments, then exit
	if (argv < 2) {
			perror("No input file:");
			exit(1);
	}

	if(int err = readFile(argc[1],&Node,&myInterfaces) < 0) {return err;} //get the file's information

	createReadSocket();

	fd_set rfds, fullrfds;
    	struct timeval tv;
    	tv.tv_sec = 5;
    	tv.tv_usec = 0;
	int activity;
	FD_ZERO(&fullrfds);
	FD_SET(Node.fd, &fullrfds);
	FD_SET(STDIN_FILENO, &fullrfds);
	while(1){
		rfds = fullrfds;
		select(Node.fd+1,&rfds,NULL,NULL,&tv);
			
		if(FD_ISSET(STDIN_FILENO, &rfds)) {
			char buf[128];
			fgets(buf,128,stdin);
			processCommand(buf);
		}
		if(FD_ISSET(Node.fd, &rfds)) {
			//yay! we got a packet, I wonder what it is?
			
			char buf[128];

			if((recv(Node.fd,buf,128,0))==-1){
				perror("recv failed:");
				exit(1);
			}
			printf("Got Packet: %s\n",buf);
			
		}
	}
}























