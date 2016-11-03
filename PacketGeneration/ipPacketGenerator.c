#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <sys/types.h>
#include <fcntl.h>
#include "../Interfaces/constants.h"

#define PROTOCOL_NUM 145
#define MAX 1024
u_int16_t get_checksum(u_int16_t* buf, int nwords) {
	u_int32_t sum;
	for (sum=0; nwords>0; nwords--) sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (u_int16_t)(~sum);
}

char **my_addrs(int *addrtype)
{
	struct hostent *hptr;
	struct utsname myname;

	if (uname(&myname) < 0)
		return NULL;
	if((hptr = gethostbyname(myname.nodename)) == NULL)
		return NULL;

	*addrtype = hptr->h_addrtype;

	return (hptr->h_addr_list);
}


int main(int argc, char* args[]) {
	if(argc != 2) {
		printf("usage: ./ipPacketGenerator [Website]\n");
		return -1;
	}

	struct utsname myname;
	if (uname(&myname) < 0)
		return 0;
	struct in_addr in;
	char **addr;
	int type;
	int fd;
	int readn = 0;
	char buf[MAX];
	char src_ip[MAX] = " ";
	int num = 0;
	char *dest_ip;
	char *split_buf[30];
	int split_buf_num = 0;
	char name[20];

	system("ip addr | grep \"inet\" | grep \"brd\" >> temp.txt");
	//system("ls -al >> temp.txt");
	fd = open("temp.txt", O_RDONLY, 0644);
	if( fd == -1 ) {
		printf("File open failed \n");
		return 1;
	}
	memset(buf, 0x00, MAX);
	readn = read(fd, buf, MAX-1);
	close(fd);
	system("rm temp.txt");


	printf(" %s\n", buf);
	split_buf[split_buf_num] = strtok(buf," ");
	while(split_buf[split_buf_num] != NULL) {
		split_buf_num++;
		split_buf[split_buf_num] = strtok(NULL," ");
	}

	////////// Select own ip address. /////////////////
	strcpy(buf, split_buf[1]);
	while(1) {
			if(buf[num] ==  '/') {
				src_ip[num] = '\0';
			break;
		} else {
			src_ip[num] = buf[num];
			num++;
		}

	}

	///////// Select own name. //////////////
	num = 0;
	strcpy(buf,split_buf[6]);
	while(1) {
			if(buf[num] ==  '-') {
				name[num] = '\0';
			break;
		} else {
			name[num] = buf[num];
			num++;
		}

	}

	if(strcasecmp(args[1], "FACEBOOK") == 0)
		dest_ip = FACEBOOK;
	else if (strcasecmp(args[1], "GOOGLE") == 0)
		dest_ip = GOOGLE;
	else if (strcasecmp(args[1], "NAVER") == 0)
		dest_ip = NAVER;
	else
		dest_ip = INSTAGRAM;


	

	char *srcIP = src_ip;;
	char *destIP = dest_ip;

	printf("%s\n",srcIP);
	printf("%s\n",destIP);
	printf("%s\n",name);

	
	int sd = socket(PF_INET, SOCK_RAW, PROTOCOL_NUM);
	if(sd < 0) {
		printf("socket() error\n");
		return -1;
	}

	int turn_on = 1;
	int turn_off = 0;

	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &turn_on, sizeof(turn_on)) < 0){
		printf("setsockopt() error\n");
		return -1;
	}

	struct iphdr iphdr;     /* Source */
	struct sockaddr_in din; /* Destination */

	din.sin_family = AF_INET;
	din.sin_port = 0;
	din.sin_addr.s_addr = inet_addr(destIP);

	iphdr.ihl = 5;
	iphdr.version = 4;
	iphdr.tos = 0;
	iphdr.tot_len = htons(sizeof(struct iphdr));
	iphdr.id = htons(rand() % 65535);
	iphdr.frag_off = 0;
	iphdr.ttl = 64;
	iphdr.protocol = PROTOCOL_NUM;
	iphdr.saddr = inet_addr(srcIP);
	iphdr.daddr = inet_addr(destIP);

	while(1) {

		/////////////////Send the packet.////////////
		if(sendto(sd, &iphdr, sizeof(iphdr), 0,
			(struct sockaddr*) &din, sizeof(din)) < 0) {
			printf("sendto() error\n");
			return -1;
		}else {
			printf("%s is trying to access www.%s.com\n", name, args[1]);

//			printf("Send packet from %s to %s\n", srcIP, destIP);
		}

		sleep(1);
	}
	

	return 0;
}
