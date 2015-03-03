#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "ipsum.h"
#include <netinet/ip.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <string.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

#include <future>//libraries for dealing with async input and time
#include <thread>
#include <chrono>

using namespace std;

#define IP_LENGTH 16
#define TTL_MAX 16
#define MTU 1400
#define IN_BUFFER_SIZE (1024 * 64)
#define UPDATE_TIMER 5000 //(5000ms = 5seconds)
#define EXPIRE_TIMER 12000
#define ROUTING_ENTRIES_MAX 64
#define RIP_DATA 200

uint32_t IPStringToInt(string ip){
    if(ip=="localhost") {ip = "127.0.0.1";}
	uint32_t res=0;
	string nIP = string(ip.data());
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

typedef struct node{
	uint32_t IP_me;
	int port_me;

	node(){port_me = 0; IP_me = 0;}
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
		printf("net_interface:\n\tid: %d\n\t%x:%d\n\t%x\n\t%x\n",
			id,IP_remote,port_remote,vip_me,vip_remote);
	}
	void initSocket(){
		if (sock = socket(AF_INET, SOCK_DGRAM/*use UDP*/, 0) < 0 ){
			perror("Create socket failed:");
			exit(1);
		}
		up = true;
	}
	int sendPacket(char *data_with_header){
		if(!up) return -1; //the connection isn't up
		//TODO: write out the sendpacket routine

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
forwarding_table forwardingTable;


int readFile(char* path, node *Node, vector<net_interface> * myInterfaces) {
	ifstream fin(path);

	string myInfo;
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
	for(vector<net_interface>::iterator iter = myInterfaces->begin(); iter != myInterfaces->end(); ++iter)
	{
		iter->print();
	}
}

int main(int argv, char* argc[]){

	//if there is no arguments, then exit
	if (argv < 2) {
			perror("No input file:");
			exit(1);
	}

	vector<net_interface> myInterfaces;
	if(int err = readFile(argc[1],&Node,&myInterfaces) < 0) {return err;} //get the file's information

}


