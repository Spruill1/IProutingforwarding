#include <stdio.h>
#include <stdlib.h>

#include "ipsum.h"
#include "/usr/include/netinet/ip.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

using namespace std;

#define IP_LENGTH = 16
#define TTL_MAX = 16
#define MTU_MAX = 1400
#define IN_BUFFER_SIZE = (1024 * 64)
#define UPDATE_TIMER = 5000 //(5000ms = 5seconds)
#define EXPIRE_TIMER = 12000
#define ROUTING_ENTRIES_MAX = 64


typedef struct node{
	string myAddr;
	int myPort;

	void print(){printf("node:\t%s:%d\n",myAddr.c_str(),myPort);}
} node;

typedef struct net_interface{
	char IPofRemote;
	int PortofRemote;
	string VIPofMyInterface;
	string VIPofRemoteInterface;


	int sock;	

	void print(){
		printf("net_interface:\n\t%s:%d\n\t%s\n\t%s\n",
			IPofRemote.c_str(),PortofRemote,
			VIPofMyInterface.c_str(),VIPofRemoteInterface.c_str());
	}

} net_interface;

int readFile(char* path, node *myNode, vector<net_interface> * myInterfaces);

int main(int argv, char* argc[]){

	//if there is no arguments, then exit
	if (argv < 2) {
			perror("No input file:");
			return -1;
	}

	node myNode;
	vector<net_interface> myInterfaces;
	if(int err = readFile(argc[1],&myNode,&myInterfaces) < 0) {return err;} //get the file's information


}

int readFile(char* path, node *myNode, vector<net_interface> * myInterfaces) {
	ifstream fin(path);

	string myInfo;
	getline(fin,myInfo);
	
	//get the IP & Port for this node
	myNode->myAddr = myInfo.substr(0,myInfo.find(":"));
	myNode->myPort = atoi(myInfo.substr(myInfo.find(":")+1,myInfo.npos).c_str());

	myNode->print();

	//get the information for the interfaces
	while(!fin.eof()){
		myInfo.erase(0,myInfo.length());
		getline(fin,myInfo);
		net_interface myInt;
		myInt.IPofRemote = myInfo.substr(0,myInfo.find(":"));
			myInfo.erase(0,myInfo.find(":")+1);
		myInt.PortofRemote = atoi(myInfo.substr(0,myInfo.find(" ")).c_str());
			myInfo.erase(0,myInfo.find(" ")+1);
		myInt.VIPofMyInterface = myInfo.substr(0,myInfo.find(" "));
			myInfo.erase(0,myInfo.find(" ")+1);
		myInt.VIPofRemoteInterface = myInfo;
		
		if(myInt.IPofRemote.length()>0){
		myInterfaces->push_back(myInt);}
	}
	for(vector<net_interface>::iterator iter = myInterfaces->begin(); iter != myInterfaces->end(); ++iter)
	{ 
		iter->print(); 
		if (iter->sock = socket(AF_INET, SOCK_DGRAM/*use UDP*/, 0) < 0 ){
			perror("Create socket failed:");
			return -1;
		}
	}
}
