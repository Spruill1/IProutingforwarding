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
        struct in_addr temp;
        temp.s_addr = vip_me;
        printf("%d\t%s\t%s\n",id,inet_ntoa(temp),up ? "up" : "down");
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
    
    forwarding_table_entry() {
        hop_ip = 0;
        cost=TTL_MAX;
        int_id = -1;}
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
    
    Node->print();
    
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
        perror("bind failed:");
        exit(1);
    }
    
    Node.fd = nodeSocket;
}


void requestRoutes(int command){
    
    if(command==RIP_REQUEST)
        char message[4]={0x0,0x1,0x0,0x0};
    
    else if (command==RIP_TRIGREQ)
        char message[4] ={0x0,0x6,0x0,0x0};
    else
        return;
    // Send the request packet to all nodes directly linked to it
    for(int i=0; i<myInterfaces.size(); i++){
        //ip_sendto(message, 32, uint32_t *route_ip, uint32_t *src_ip, uint32_t *dest_ip);
    }
    
}

void respondRoutes(uint32_t requesterIp, int flag){
    char message[MTU];
    struct RIP *package;
    package = (struct RIP*) message;
    package->command = (uint16_t) flag;
    
    //Event Horizon, only broadcast table about the neighbors
    //no hops
    package->num_entries = forwardingTable.size();
    
    int i=0;
    std::map<uint32_t, forwarding_table_entry>::iterator it;
    for (it = forwardingTable.begin(); it != forwardingTable.end(); it++)
    {
        if(it->first==it->second.hop_ip){
            package->entries[i].cost =  it->second.cost;
            package->entries[i].address = it->first;
            i++;
        }
    }
    //ip_sendto
}

void shareTable(int flag){
    for(int i=0; i<myInterfaces.size(); i++){
        respondRoutes(myInterfaces[i].vip_remote, flag);
    }
}

void processRoutes(char* message, uint32_t source_ip){
    RIP *package = (struct RIP *) message;
    //packet from some other node
    //if destination exists in the forwarding table
    bool changed = false;
    for(int i=0; i<package->num_entries; i++){
        if(forwardingTable.find(package->entries[i].address) ==  forwardingTable.end()){
            //table doesn't have a node, add a new one!
            
            int cost = package->entries[i].cost;
            cost = (cost>=16)? 16:cost+1; //infinite cost
            
            forwarding_table_entry newEntry;
            newEntry.cost = (uint16_t)cost;
            newEntry.hop_ip = source_ip;
            
            forwardingTable[package->entries[i].address] = newEntry;
            changed = true;
        } else if(forwardingTable[package->entries[i].address].cost> package->entries[i].cost+1){
            //pick shortest path!
            int cost = package->entries[i].cost;
            cost = (cost>=16)? 16:cost+1; //infinite cost
            forwardingTable[package->entries[i].address].hop_ip = source_ip;
            forwardingTable[package->entries[i].address].cost = cost;
            changed = true;
        }
    }
    if (changed)
        shareTable(RIP_UPRESP);
}

void takeDown(){
    //advertise distance to other immediate nodes that it is down
    for(int i=0; i<myInterfaces.size(); i++){
        myInterfaces[1].up = false;
    }
}

int ripMessageSize(RIP *package){
    //gets the actual message size
    return sizeof(uint16_t)*2+sizeof(uint32_t)*2*package->num_entries;
}

//takes in a virtual IP address and determines which interface to send it along by searching the forwarding table
int getNextHop(struct in_addr vip){
    return 0;
}

//handles the physical sending through a socket, encapsulating the payload in an IP header
void ip_sendto(bool isRIP, char* payload, int payload_size, int interface_id, uint32_t src_ip, uint32_t dest_ip){
    char buffer[MTU];
    struct ip *ip;
    ip = (struct ip*) buffer;
    
    //process package
    // Must fill this up
    ip->ip_hl = 5; //header length  5 is the minimum length, counts # of 32-bit words in the header
    ip->ip_v = 4; //version
    ip->ip_tos = 0; //Type of service
    ip->ip_len = htons(ip->ip_hl*4 + payload_size); //Total length, ip_hl is in 32-bit words, need bytes
    ip->ip_id = 0; //id
    ip->ip_off= 0; //offset
    ip->ip_ttl = TTL_MAX; //time to live
    ip->ip_p = isRIP ? RIP_PROTOCOL:SENT_PROTOCOL; //set the protocol appropriately
    ip->ip_src.s_addr = src_ip;
    ip->ip_dst.s_addr = dest_ip;
    
    ip->ip_sum = ip_sum(buffer, ip->ip_hl*4); //calculate the checksum for the IP header
    
    memcpy(buffer+ip->ip_hl*4,payload,payload_size);
    
    struct sockaddr_in r_addr;
    r_addr.sin_family = AF_INET;
    r_addr.sin_addr = myInterfaces.at(interface_id).IP_remote;
    r_addr.sin_port = htons(myInterfaces.at(interface_id).port_remote);
    
    printf("sendTo: fd:%d, len:%d, addr:%x, port:%d\n",Node.fd,ip->ip_hl*4 + payload_size,(int)r_addr.sin_addr.s_addr,(int)r_addr.sin_port);
    
    if((sendto(Node.fd, buffer, ip->ip_hl*4 + payload_size, 0,
               (struct sockaddr *)&r_addr, sizeof(r_addr))) == -1){
        
        perror("sendto failure:");
        exit(1);
    }
}

void cmd_ifconfig(){
    for(std::vector<net_interface>::iterator iter = myInterfaces.begin(); iter != myInterfaces.end(); ++iter)
    {
        iter->print();
    }
}

void cmd_routes(){} //needs a working forwarding table, RIP has to have been completed
void cmd_down(int id){
    if(id > myInterfaces.size()) {printf("interface %d not found\n",id);}
    else myInterfaces[id-1].up = false;}
void cmd_up(int id){
    if(id > myInterfaces.size()) {printf("interface %d not found\n",id);}
    else myInterfaces[id-1].up = true;}
void cmd_send(struct in_addr vip, char* buf){ //TODO: may need to create new socket...
    printf("str: %s\n",buf);
    ip_sendto(is_ip, buf, strlen(buf), 0, myInterfaces.at(0).vip_me, vip.s_addr);
}

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

void processIncomingPacket(char* buff) {
    struct ip* header = (ip*)&buff[0];
    char * payload = buff + (header->ip_hl*4);
    
    if(header->ip_p==RIP_PROTOCOL){
        RIP *rip = (RIP *)payload;
        //TODO: now we have a RIP packet, need to update with it.
        return;
    }
    if(header->ip_p==SENT_PROTOCOL){
        printf("Recieved: %s\n",payload);
        return;
    }
    //if the packet is not a valid IP packet or RIP packet, ignore it
}

int main(int argv, char* argc[]){
    
    //if there is no arguments, then exit
    if (argv < 2) {
        perror("No input file:");
        exit(1);
    }
    readFile(argc[1],&Node,&myInterfaces);  //get the file's information
    
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
        
        if(FD_ISSET(STDIN_FILENO, &rfds)) { //user input, TODO: need to add a bigger size
            char buf[128];
            fgets(buf,128,stdin);
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
            processIncomingPacket(buf);
            
        }
    }
    
}























