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

typedef struct node{
	std::string myAddr;
	int myPort;

	void print(){printf("node:\t%s:%d\n",myAddr.c_str(),myPort);}
} node;

typedef struct interface{
	std::string IPofRemote;
	int PortofRemote;
	std::string VIPofMyInterface;
	std::string VIPofRemoteInterface;

	void print(){
		printf("interface:\n\t%s:%d\n\t%s\n\t%s\n",
			IPofRemote.c_str(),PortofRemote,
			VIPofMyInterface.c_str(),VIPofRemoteInterface.c_str());
	}

} interface;

int main(int argv, char* argc[]){

	//if there is no arguments, then exit
	if (argv < 2) {
			perror("No input file:");
			return -1;
	}


	node myNode;
	std::vector<interface> myInterfaces;

	std::ifstream fin(argc[1]);

	std::string myInfo;
	std::getline(fin,myInfo);
	
	//get the IP & Port for this node
	myNode.myAddr = myInfo.substr(0,myInfo.find(":"));
	myNode.myPort = atoi(myInfo.substr(myInfo.find(":")+1,myInfo.npos).c_str());

	myNode.print();

	//get the information for the interfaces
	while(!fin.eof()){
		myInfo.erase(0,myInfo.length());
		std::getline(fin,myInfo);
		interface myInt;
		myInt.IPofRemote = myInfo.substr(0,myInfo.find(":"));
			myInfo.erase(0,myInfo.find(":")+1);
		myInt.PortofRemote = atoi(myInfo.substr(0,myInfo.find(" ")).c_str());
			myInfo.erase(0,myInfo.find(" ")+1);
		myInt.VIPofMyInterface = myInfo.substr(0,myInfo.find(" "));
			myInfo.erase(0,myInfo.find(" ")+1);
		myInt.VIPofRemoteInterface = myInfo;
		
		if(myInt.IPofRemote.length()>0){
		myInterfaces.push_back(myInt);}
	}
	for(std::vector<interface>::iterator iter = myInterfaces.begin(); iter != myInterfaces.end(); ++iter)
	{ 
		iter->print(); 
	}
}
