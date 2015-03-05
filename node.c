#include <stdio.h>
#include <stdlib.h>
#include <iostream>

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
#include <map>
#include <algorithm>

#include <future>//libraries for dealing with async input and time
#include <thread>
#include <chrono>

#include <time.h>

#include "ipsum.h"

//using namespace std;

#define IP_LENGTH 16
#define TTL_MAX 16
#define MTU 1400
#define IN_BUFFER_SIZE (1024 * 64)
#define UPDATE_TIMER 5000 //(5000ms = 5seconds)
#define EXPIRE_TIMER 12000
#define ROUTING_ENTRIES_MAX 64
#define RIP_PROTOCOL 200
#define SENT_PROTOCOL 0
#define is_ip false
#define is_rip true
#define RIP_REQUEST     1
#define RIP_RESPONSE    2
#define RIP_TRIGREQ     6
#define RIP_TRIGRESP    7
#define RIP_TRIGACK     8
#define RIP_UPREQ       9
#define RIP_UPRESP      10
#define RIP_UPACK       11

#define routingTimeout 12
#define ripTimer 5


typedef struct node{
	struct in_addr IP_me;
	int port_me;
	
	int fd;
	
	node(){port_me = 0; IP_me.s_addr = 0; fd = -1;}
	void print(){printf("node:\t%x:%d\n",(int)IP_me.s_addr,port_me);}
} node;


node Node; //global for this node's information

typedef struct net_interface{
	int id;
	
	struct in_addr IP_remote;
	uint16_t port_remote;
	uint32_t vip_me;
	uint32_t vip_remote;
	
	//buffered payload
	
	char buffer[IN_BUFFER_SIZE+1];
	int packet_index = 0;
	
	
	int sock;
	
	struct sockaddr_in addr;
	bool up;
	
	net_interface(int id_in){
		id = id_in;
		IP_remote.s_addr = 0;
		port_remote = 0;
		vip_me = 0;
		vip_remote = 0;
		up = false;
	}
	void print(){
		uint8_t c0 = (uint8_t)((vip_remote & 0xFF000000)>>24);
		uint8_t c1 = (uint8_t)((vip_remote & 0x00FF0000)>>16);
		uint8_t c2 = (uint8_t)((vip_remote & 0x0000FF00)>>8);
		uint8_t c3 = (uint8_t)(vip_remote & 0x000000FF);
		printf("%d\t%d.%d.%d.%d\t%s\n",id,c0,c1,c2,c3,up ? "up" : "down");
	}
	void initSocket(){  //right now I'm thinking this method is pointless, I don't think we need a special socket for each interface
		if ((sock = socket(AF_INET, SOCK_DGRAM/*use UDP*/, IPPROTO_IP)) < 0 ){
			perror("Create socket failed:");
			exit(1);
		}
		up = true;
	}
	int sendPacket(char *data_with_header, int len){
		if(!up) return -1; //the connection isn't up
		//TODO: write out the sendpacket routine
		
		struct sockaddr_in dst_addr;
		dst_addr.sin_family = AF_INET;
		dst_addr.sin_addr = IP_remote;
		dst_addr.sin_port = htons(port_remote);
		
		if((sendto(Node.fd,data_with_header,len,0,(struct sockaddr *)&dst_addr, sizeof(dst_addr)))==-1){
			perror("sendto failed:");
			exit(1);
		}
		return 0; //finished
	}
	
} net_interface;

typedef struct forwarding_table_entry {
	uint32_t hop_ip;
	uint16_t cost;
	int int_id;
	
	time_t init;
	
	forwarding_table_entry() {
		hop_ip = 0;
		cost=TTL_MAX;
		int_id = -1;
	}
} forwarding_table_entry;


typedef struct RIP {
	uint16_t command;
	uint16_t num_entries;
	struct {
		uint32_t cost;
		uint32_t address;
	} entries[ROUTING_ENTRIES_MAX];
	
	
}RIP;

std::vector<net_interface> myInterfaces; //the interfaces for this node
std::map<uint32_t, forwarding_table_entry> forwardingTable;

uint32_t IPStringToInt(std::string ip){
	if(ip=="localhost") {ip = "127.0.0.1";}
	uint32_t res=0;
	std::string nIP = std::string(ip.data());
	uint8_t B0 = atoi(nIP.substr(0,nIP.find(".")).c_str()); printf("B0:%d\t",B0);
	nIP.erase(0,nIP.find(".")+1);
	uint8_t B1 = atoi(nIP.substr(0,nIP.find(".")).c_str()); printf("B1:%d\t",B1);
	nIP.erase(0,nIP.find(".")+1);
	uint8_t B2 = atoi(nIP.substr(0,nIP.find(".")).c_str()); printf("B2:%d\t",B2);
	nIP.erase(0,nIP.find(".")+1);
	uint8_t B3 = atoi(nIP.substr(0,nIP.length()).c_str()); printf("B3:%d\t",B3);
	res+=B0; res=res<<8;
	res+=B1; res=res<<8;
	res+=B2; res=res<<8;
	res+=B3;
	printf("res: %x\n",res);
	return res;
}

void checkLocal(std::string ip, struct in_addr *addr){
	if(ip=="localhost") {ip = "127.0.0.1";}
	inet_aton(ip.c_str(),addr);
}

int readFile(char* path, node *Node, std::vector<net_interface> * myInterfaces) {
	std::ifstream fin(path);
	
	std::string myInfo;
	getline(fin,myInfo);
	
	//get the IP & Port for this node
	//Node->IP_me = IPStringToInt(myInfo.substr(0,myInfo.find(":")));
	//inet_aton(myInfo.substr(0,myInfo.find(":")).c_str(),&Node->IP_me);
	checkLocal(myInfo.substr(0,myInfo.find(":")),&Node->IP_me);
	Node->port_me = atoi(myInfo.substr(myInfo.find(":")+1,myInfo.npos).c_str());
	
	//Node->print();
	
	//get the information for the interfaces
	while(!fin.eof()){
		myInfo.erase(0,myInfo.length());
		getline(fin,myInfo);
		net_interface myInt = net_interface(myInterfaces->size()+1);
		//myInt.IP_remote = IPStringToInt(myInfo.substr(0,myInfo.find(":")));
		//inet_aton(myInfo.substr(0,myInfo.find(":")).c_str(),&myInt.IP_remote);
		checkLocal(myInfo.substr(0,myInfo.find(":")),&myInt.IP_remote);
		myInfo.erase(0,myInfo.find(":")+1);
		myInt.port_remote = atoi(myInfo.substr(0,myInfo.find(" ")).c_str());
		myInfo.erase(0,myInfo.find(" ")+1);
		myInt.vip_me = IPStringToInt(myInfo.substr(0,myInfo.find(" ")));
		IPStringToInt(myInfo.substr(0,myInfo.find(" ")));
		myInfo.erase(0,myInfo.find(" ")+1);
		myInt.vip_remote = IPStringToInt(myInfo);
		
		if(myInt.IP_remote.s_addr!=0){
			myInt.initSocket();
			myInterfaces->push_back(myInt);
			forwarding_table_entry entry;
			entry.cost = 1;
			entry.hop_ip = myInt.vip_remote;
			forwardingTable[myInt.vip_remote] = entry;
		}
	}
	//return something?
	
	
	return 0;
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
		printf("port %d", Node.port_me);
		perror("bind failed:");
		exit(1);
	}
	
	Node.fd = nodeSocket;
}


int ripMessageSize(RIP *packet){
	//gets the actual message size
	return sizeof(uint16_t)*2+sizeof(uint32_t)*2*packet->num_entries;
}

void ip_sendPacket(bool isRIP, char* payload, int payload_size, int interface_id, uint32_t src_ip, uint32_t dest_ip, u_char timeToLive){
	char bufferd[MTU] = "";
	struct ip *_ip;
	_ip = (struct ip *) bufferd;
	
	if(interface_id < 0){
		perror("no matching vip:");
		return;
	}
	
	//Don't send if interface is down
	if(!myInterfaces[interface_id].up){
		printf("\n\nWTFFFF\n\n");
		return;
	}
	
	//if the packet is bigger than mtu then split the packet
	
	
	//process packet
	// Must fill this up
	_ip->ip_hl = 5; //header length  5 is the minimum length, counts # of 32-bit words in the header
	_ip->ip_v = 4; //version
	_ip->ip_tos = 0; //Type of service
	_ip->ip_len = htons(_ip->ip_hl*4 + payload_size); //Total length, ip_hl is in 32-bit words, need bytes
	_ip->ip_id = 0; //id
	_ip->ip_off= 0x4000; //offset
	_ip->ip_ttl = (isRIP)? TTL_MAX: timeToLive; //time to live
	_ip->ip_p = isRIP ? RIP_PROTOCOL:SENT_PROTOCOL; //set the protocol appropriately
	_ip->ip_src.s_addr = src_ip;
	_ip->ip_dst.s_addr = dest_ip;
	
	_ip->ip_sum = ip_sum((char*)_ip, 20); //calculate the checksum for the IP header
	
	memcpy(bufferd+20,payload,payload_size);
	
	struct sockaddr_in r_addr;
	r_addr.sin_family = AF_INET;
	r_addr.sin_addr = myInterfaces.at(interface_id).IP_remote;
	r_addr.sin_port = htons(myInterfaces.at(interface_id).port_remote);
	
	//printf("sendTo: fd:%d, len:%d, v_dest: %x, v_src:%x addr:%x, port:%d, sum:%x\n",Node.fd,_ip->ip_hl*4 + payload_size,(int)_ip->ip_dst.s_addr,(int)_ip->ip_src.s_addr,(int)r_addr.sin_addr.s_addr,(int)r_addr.sin_port,(u_short)_ip->ip_sum);
	
	if((sendto(Node.fd, bufferd, 20 + payload_size, 0,
			   (struct sockaddr *)&r_addr, sizeof(r_addr))) == -1){
		
		perror("sendto failure:");
		exit(1);
	}
	
	
	
}


//handles the physical sending through a socket, encapsulating the payload in an IP header
void ip_sendto(bool isRIP, char* payload, int payload_size, int interface_id, uint32_t src_ip, uint32_t dest_ip, u_char timeToLive){
	
	ip_sendPacket(isRIP, payload, payload_size, interface_id, src_ip, dest_ip, timeToLive);
}


void requestRoutes(int command){
	uint16_t request[2];
	request[0] = command;
	request[1] = 0;
	char* message = (char*)request;
	// Send the request packet to all nodes directly linked to it
	for(int i=0; i<myInterfaces.size(); i++){
		if(myInterfaces[i].up && forwardingTable[myInterfaces[i].vip_remote].cost<16){
			//printf("\nrequesting Routes: %d -> %d \n\n ", myInterfaces[i].vip_me,  myInterfaces[i].vip_remote);
			ip_sendto(is_rip, message, 32, i, myInterfaces[i].vip_me, myInterfaces[i].vip_remote, TTL_MAX);
		}
	}
	
}

void advertiseRoutes(uint32_t requesterIp, int inter_id, int flag){
	char message[MTU];
	RIP *packet;
	packet = (RIP*) message;
	packet->command = (uint16_t) flag;
	
	//Event Horizon, only broadcast table about the neighbors
	//Nodes of distance>1 are not published
	int packetEntries = 0;
	for(int i=0; i<myInterfaces.size(); i++){
		uint32_t remoteIp = myInterfaces[i].vip_remote;
		if(remoteIp!=requesterIp && forwardingTable.count(remoteIp)!=0){ //immediate node
			packet->entries[packetEntries].cost =  forwardingTable[remoteIp].cost;
			packet->entries[packetEntries].address = remoteIp;
			
			packet->entries[packetEntries+1].cost =  0;
			packet->entries[packetEntries+1].address = myInterfaces[i].vip_me;
			packetEntries +=2;
		}
	}
	packet->num_entries = packetEntries;
 
	ip_sendto(is_rip, message, ripMessageSize(packet), inter_id, myInterfaces[inter_id].vip_me, requesterIp, TTL_MAX);
}

void shareTable(int flag){
	for(int i=0; i<myInterfaces.size(); i++){
		advertiseRoutes(myInterfaces[i].vip_remote, i, flag);
	}
}

void processRoutes(RIP *packet, uint32_t source_ip){
	//printf("\n\n");
	//printf("processing routes!\n");
	
	
	//packet from some other node
	//if destination exists in the forwarding table
	bool changed = false;
	for(int i=0; i<packet->num_entries; i++){
		if(forwardingTable.count(packet->entries[i].address)==0){
			//table doesn't have a node, add a new one!
			
			int cost = packet->entries[i].cost;
			cost = (cost>=TTL_MAX)? TTL_MAX:cost+1; //infinite cost
			
			forwarding_table_entry newEntry;
			newEntry.cost = (uint16_t)cost;
			newEntry.hop_ip = source_ip;
			
			forwardingTable[packet->entries[i].address] = newEntry;
			//printf("New entry, %d %d %d \n", packet->entries[i].address, newEntry.cost, newEntry.hop_ip);
			changed = true;
		} else{
			if(forwardingTable[packet->entries[i].address].cost> packet->entries[i].cost+1){
				//pick shortest path!
				int cost = packet->entries[i].cost;
				cost = (cost>=TTL_MAX)? TTL_MAX:cost+1; //infinite cost
				forwardingTable[packet->entries[i].address].hop_ip = source_ip;
				forwardingTable[packet->entries[i].address].cost = cost;
				changed = true;
				//printf("Updated entry, %d %d %d \n", packet->entries[i].address, forwardingTable[packet->entries[i].address].cost, forwardingTable[packet->entries[i].address].hop_ip);
			} else if(packet->entries[i].cost>=16){
				forwardingTable[packet->entries[i].address].cost = 16;
			}
		}
		//printf("\n\n");
	}
	if (changed)
		shareTable(RIP_UPRESP);
}


int findInterID(uint32_t vip){
	for(int i=0; i<myInterfaces.size(); i++){
		if(myInterfaces[i].vip_remote == vip)
			return i;
	}
	return -1;
}

//takes in a virtual IP address and determines which interface to send it along by searching the forwarding table
int getNextHop(uint32_t vip){
	std::map<uint32_t, forwarding_table_entry>::iterator it;
	for (it = forwardingTable.begin(); it != forwardingTable.end(); it++)
	{
		//printf("\t%x",it->first);
	}
	//printf("\n");
	
	if(forwardingTable.count(vip)==0)
		return -1;
	return findInterID(forwardingTable[vip].hop_ip);
}
void cmd_ifconfig(){
	for(std::vector<net_interface>::iterator iter = myInterfaces.begin(); iter != myInterfaces.end(); ++iter)
	{
		iter->print();
	}
}

void cmd_routes(){
	std::map<uint32_t, forwarding_table_entry>::iterator it;
	for (it = forwardingTable.begin(); it != forwardingTable.end(); it++)
	{
		struct in_addr ip_dest, ip_hop;
		ip_dest.s_addr = (in_addr_t)htonl(it->first);
		ip_hop.s_addr = (in_addr_t)htonl(it->second.hop_ip);
		
		printf("%s\t%d\t%d\n",inet_ntoa(ip_dest), getNextHop(it->first)+1, it->second.cost);
	}
}
void cmd_down(int id){
	if(id > myInterfaces.size()) {printf("Interface %d not found\n",id);}
	else {
		myInterfaces[id-1].up = false;
		//Make route that was taken down infinite
		forwardingTable[myInterfaces[id-1].vip_remote].cost=TTL_MAX;
		
		printf("interface %d down\n",id);
	}
}
void cmd_up(int id){
	if(id > myInterfaces.size()) {printf("Interface %d not found\n",id);}
	else {
		myInterfaces[id-1].up = true;
		printf("Interface %d up\n",id);
		forwardingTable[myInterfaces[id-1].vip_remote].cost = 1;
		forwardingTable[myInterfaces[id-1].vip_remote].init = time(NULL);
	}
}
void cmd_send(uint32_t vip, char* buf){
	printf("str: %s\tvip: %x\tint_id: %d\n\n",buf,vip,getNextHop(vip));
	if(forwardingTable[vip].cost==16){
		printf("Cannot send: unreachable IP");
		return;
	}
	ip_sendto(false, buf, strlen(buf), getNextHop(vip), myInterfaces.at(0).vip_me, vip, TTL_MAX);
}

void processCommand(char* cmmd){
	char arg0[10], arg1[20], arg2[MTU]; //TODO: go back and give a better size for arg2
	sscanf(cmmd,"%s %s %[^\n]s",arg0,arg1,arg2);
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
		uint32_t vip;
		//inet_aton(arg1,&vip); //HEREISPROB
		std::string str = std::string(arg1);
		printf("\t\t\t\tstringIP: %s\n",str.c_str());
		vip = IPStringToInt(str);
		printf("\t\t\t\vip: %x\n",vip);
		cmd_send(vip,arg2);
		return;
	}
	if(strncmp(cmmd,"printT",6 )==0){
		
	}
}

void keepAlive(uint32_t vip){
	forwardingTable[vip].cost = 1;
	forwardingTable[vip].init = time(NULL);
	std::map<uint32_t, forwarding_table_entry>::iterator it;
	//timeout for route that uses this entry as hop
	for (it = forwardingTable.begin(); it != forwardingTable.end(); it++)
	{
		if(it->second.hop_ip==vip)
			it->second.init = time(NULL);
	}
}



void processIncomingPacket(char* buff) {
	struct ip* header = (ip*)&buff[0];
	char * payload = buff + (header->ip_hl*4);
	
	u_short sum = header->ip_sum;
	header->ip_sum=0;
	if(sum!=ip_sum(buff,20)) {
		//the checksum does not match, discard packet
		return;
	}
	if(header->ip_p==RIP_PROTOCOL){
		RIP *rip = (RIP *)payload;
		//TODO: Verify if ip_src is the source IP
		if(rip->command==RIP_RESPONSE)
			processRoutes(rip, (uint32_t)header->ip_src.s_addr);
		else if(rip->command==RIP_REQUEST){
			if(forwardingTable.count((uint32_t)header->ip_src.s_addr)==0){
				perror("RIP Request with invalid source location");
				return;
			}
			int id = findInterID(forwardingTable[(uint32_t)header->ip_src.s_addr].hop_ip);
			
			keepAlive((uint32_t)header->ip_src.s_addr);
			
			advertiseRoutes((uint32_t)header->ip_src.s_addr, id, RIP_RESPONSE);
			return;
		}
	}
	if(header->ip_p==SENT_PROTOCOL){
		for(int i=0; i<myInterfaces.size(); i++){
			if((uint32_t)header->ip_dst.s_addr==myInterfaces[i].vip_me){
				printf("%s\n",payload);
				return;
			}
		}
		
		//forward packet!
		int inter_id;
		if((inter_id = getNextHop((uint32_t)header->ip_dst.s_addr))==-1 || header->ip_ttl<=1){
			perror("Was not able to route message packet, no matching ip");
			return;
		}
		ip_sendto(false, payload, strlen(payload), inter_id, myInterfaces[inter_id].vip_me, (uint32_t)header->ip_dst.s_addr, header->ip_ttl-1);
		return;
	}
	//if the packet is not a valid IP packet or RIP packet, ignore it
}

void preprocessIncomingPacket(char* buff) {
	struct ip* header = (ip*)&buff[0];
	char * payload = buff + (header->ip_hl*4);
	int blah =(header->ip_off & IP_DF);
	if(blah==0){
		//fragmented
		
		int offset = (header->ip_off & IP_OFFMASK)*8;
		int inter_id;
		for(int i=0; i<myInterfaces.size(); i++){
			if((uint32_t)header->ip_dst.s_addr==myInterfaces[i].vip_me){
				inter_id = i;
				break;
			}
		}
		
		int buffOffset = myInterfaces[inter_id].packet_index;
		if((buffOffset+header->ip_len>IN_BUFFER_SIZE) || (buffOffset != offset)){
			//attack? drop all
			myInterfaces[inter_id].packet_index = 0;
			return;
		}
		if(buffOffset==0){
			//first packet, copy header
			strncpy(myInterfaces[inter_id].buffer, buff, header->ip_len);
			myInterfaces[inter_id].packet_index = header->ip_len;
		} else {
			//copy only payload
			if((header->ip_off & IP_MF)>0){
				strncpy(myInterfaces[inter_id].buffer + buffOffset, payload, header->ip_len - (header->ip_hl*4));
				myInterfaces[inter_id].packet_index += (header->ip_len - (header->ip_hl*4));
			} else {
				//last packet
				strncpy(myInterfaces[inter_id].buffer + buffOffset, payload, header->ip_len - (header->ip_hl*4));
				myInterfaces[inter_id].packet_index += (header->ip_len - (header->ip_hl*4));
				myInterfaces[myInterfaces[inter_id].packet_index] = '\0'; //this may be wrong!
				
				processIncomingPacket(myInterfaces[inter_id].buffer);
				myInterfaces[inter_id].packet_index = 0;
			}
		}
		
	} else {
		processIncomingPacket(buff);
	}
	
}

time_t lastRIP;

void initMapTime(){
	std::map<uint32_t, forwarding_table_entry>::iterator it;
	for (it = forwardingTable.begin(); it != forwardingTable.end(); it++)
	{
		it->second.init = time(NULL);
	}
}

void checkMapTime(){
	std::map<uint32_t, forwarding_table_entry>::iterator it;
	for (it = forwardingTable.begin(); it != forwardingTable.end(); it++)
	{
		if(difftime(time(NULL),it->second.init) > routingTimeout){
			//timeout the routing entry
			it->second.cost = TTL_MAX;
			std::map<uint32_t, forwarding_table_entry>::iterator it2;
			//timeout for route that uses this entry as hop
			for (it2 = forwardingTable.begin(); it2 != forwardingTable.end(); it2++)
			{
				if(it2->second.hop_ip==it->first)
					it2->second.cost=TTL_MAX;
			}
			
		}
	}
}

int main(int argv, char* argc[]){
	
	//if there is no arguments, then exit
	if (argv < 2) {
		perror("No input file:");
		exit(1);
	}
	readFile(argc[1],&Node,&myInterfaces);  //get the file's information
	
	createReadSocket();
	
	lastRIP = time(NULL);
	
	fd_set rfds, fullrfds;
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	int activity;
	
	std::map<uint32_t, forwarding_table_entry>::iterator it;
	
	initMapTime();
	
	
	FD_ZERO(&fullrfds);
	FD_SET(Node.fd, &fullrfds);
	FD_SET(STDIN_FILENO, &fullrfds);
	
	requestRoutes(RIP_REQUEST);
	lastRIP = time(NULL);
	initMapTime();
	
	while(1){
		rfds = fullrfds;
		select(Node.fd+1,&rfds,NULL,NULL,&tv);
		
		if(FD_ISSET(STDIN_FILENO, &rfds)) { //user input, TODO: need to add a bigger size
			char buf[MTU] = "";
			fgets(buf,MTU,stdin);
			processCommand(buf);
		}
		if(FD_ISSET(Node.fd, &rfds)) {
			//yay! we got a packet, I wonder what it is?
			
			char buf[IN_BUFFER_SIZE] = "";
			
			if((recv(Node.fd,buf,IN_BUFFER_SIZE,0))==-1){
				perror("recv failed:");
				exit(1);
			}
			//printf("Got Packet: %s\n",buf);
			preprocessIncomingPacket(buf);
			
			//printf("stopped here\n");sleep(5);
		}
		
		//check timers
		if(difftime(time(NULL),lastRIP) > ripTimer){
			requestRoutes(RIP_REQUEST);
			lastRIP = time(NULL);
		}
		checkMapTime();
		//sleep(5);
	}
	
}























