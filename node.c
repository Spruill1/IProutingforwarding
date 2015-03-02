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

typedef struct node{
	std::string myAddr;
	int myPort;

	void print(){printf("node:\t%s:%d\n",myAddr.c_str(),myPort);}
} node;

int main(int argv, char* argc[]){

//if there is no arguments, then exit
if (argv < 2) {
		perror("No input file:");
		return -1;
	}

std::ifstream fin(argc[1]);

std::string myInfo;
std::getline(fin,myInfo);

node myNode;
myNode.myAddr = myInfo.substr(0,myInfo.find(":"));
myNode.myPort = atoi(myInfo.substr(myInfo.find(":")+1,myInfo.npos).c_str());

myNode.print();
}
