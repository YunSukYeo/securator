#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "../Interfaces/constants.h"
#include <mysql/mysql.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_IP_SIZE 65535
#define MAX_UDP_PAYLOAD_SIZE 65507
#define PROTOCOL_NUM 145

//#define ETH_FRAME_LEN 1518

int start_ehternet_listening(char *ifName);


char* get_name_with_ip_address(struct iphdr* iphdr) {

	char* name;

	if(strcmp(inet_ntoa(*(struct in_addr *)&iphdr->saddr), STAFF_1) == 0) {
		name = "staff_1";
	} else if (strcmp(inet_ntoa(*(struct in_addr *)&iphdr->saddr), STAFF_2) == 0) {
		name = "staff_2";
	} else if (strcmp(inet_ntoa(*(struct in_addr *)&iphdr->saddr), MANAGER) == 0) {
		name = "manager";
	} else if (strcmp(inet_ntoa(*(struct in_addr *)&iphdr->saddr), PRESIDENT) == 0) {
		name = "president";
	} else {
		name = "None";
	}


	return name;

}

int main(int argc, char *argv[]) {
	if(argc < 2) {
		printf("usage: ipPacketReceiver [hostName] [hostIP]\n");
		return -1;
	}

	start_ip_listening(argv[1], argv[2]);
	return 0;
}

int start_ip_listening(char *hostName, char *hostIP) {
    printf("Start %s:%s listening\n", hostName, hostIP);



    fflush(stdout);

    int sd = socket(PF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (sd < 0) {
        printf("socket() error\n");
        return -1;
    }

    char buffer[MAX_IP_SIZE] = {0};
	char *position_name;
    int receivedBytes = 0;
    struct ifreq ifopts;
    ifopts.ifr_flags |= IFF_PROMISC;
    ioctl(sd, SIOCSIFFLAGS, &ifopts);
    while(1) {

		////////////////////Receive the packet./////////////////
        if((receivedBytes = recv(sd, buffer, MAX_IP_SIZE, 0)) < 0) {
            printf("recvfrom() failed\n");
            return -1;
        }
        buffer[receivedBytes] = '\0';
		fflush(stdout);

        struct iphdr* iphdr = (struct iphdr*) buffer;
		
		position_name = get_name_with_ip_address(iphdr);


		if(strcmp(inet_ntoa(*(struct in_addr *)&iphdr->daddr), FACEBOOK) == 0) {
			printf("[www.facebook.com] Receive the packet from %s (%s)\n",inet_ntoa(*(struct in_addr *)&iphdr->saddr),position_name);
			fflush(stdout);

		} else if(strcmp(inet_ntoa(*(struct in_addr *)&iphdr->daddr), GOOGLE) == 0) {
			printf("[www.google.com] Receive the packet from %s (%s)\n",inet_ntoa(*(struct in_addr *)&iphdr->saddr),position_name); 
			fflush(stdout);

		} else if(strcmp(inet_ntoa(*(struct in_addr *)&iphdr->daddr), NAVER) == 0) {
			printf("[www.naver.com] Receive the packet from %s (%s)\n",inet_ntoa(*(struct in_addr *)&iphdr->saddr), position_name); 
			fflush(stdout);

		} else if(strcmp(inet_ntoa(*(struct in_addr *)&iphdr->daddr), INSTAGRAM) == 0) {
			printf("[www.instagram.com] Receive the packet from %s (%s)\n",inet_ntoa(*(struct in_addr *)&iphdr->saddr),position_name); 
			fflush(stdout);

		} else {

			printf("read succeeded\n");
		    printf("pkt_size = %d\n", receivedBytes);
	        printf("iphdr.ihl = %d\n", iphdr->ihl);
	        printf("iphdr.version = %d\n", iphdr->version);
		    printf("iphdr.tos = %d\n", iphdr->tos);
	        printf("iphdr.tot_len = %d\n", htons(iphdr->tot_len));
	        printf("iphdr.frag_off = %d\n", iphdr->frag_off);
	        printf("iphdr.ttl = %d\n", iphdr->ttl);
	        printf("iphdr.protocol = %d\n", iphdr->protocol);
	        printf("Source IP Address: %s\n", inet_ntoa(*(struct in_addr *)&iphdr->saddr));
	        printf("Destination IP Address: %s\n", inet_ntoa(*(struct in_addr *)&iphdr->daddr));
	        fflush(stdout);
		}
    }

    return 1;
}
