#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <arpa/inet.h>
#define BUFSIZE 8192

struct route_info{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId);
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo);
int get_gateway(char * iface_name, char * gatewayip, int size);
