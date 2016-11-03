#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include "nsf-secu-controller-interface.h"
#include "../../Interfaces/nsf-sff-interface.h"
#include "../../Interfaces/mysql-interface.h"
#include "../../Interfaces/constants.h"

int ipHeaderLen;
int getCurrentTime() {
    /*TODO - implement time function, return current hour*/
}

void processSenderProtocol(uint8_t *data, int dataLen, struct iphdr *ipheader) {
	char where[256] = {0}, action = PASS;
	int n = sprintf(where, "`saddr`=\"%lu\" AND `daddr`=\"%lu\" AND `stime`<%d AND `etime`>%d", (unsigned long)(ipheader->saddr), (unsigned long)(ipheader->daddr), 12, 12); //CURRENT_TIME, CURRENT_TIME);
    where[n] = '\0';
    MYSQL_RES *sqlResult = MysqlSelectQuery("`firewall_rule`", "`action`", where, true);

    if(MysqlGetNumRows(sqlResult) > 0) {
        MYSQL_ROW row = MysqlGetRow(sqlResult);
        action = (int) *(row[0]);
    }

    int metadataNum = 0;
    int resultHeaderLen = (2 /*resultCode(1) + metadataNum(1)*/ + metadataNum ) * sizeof(uint8_t);
    int packetLen = ipHeaderLen + resultHeaderLen + (dataLen - ipHeaderLen);

    uint8_t *packet = (uint8_t *)malloc(packetLen);
    uint8_t metadataCodes[1] = {DDOS_INSPECTION};

    /* Attach our header & outter trunneling header */
    attach_outter_encapsulation(packet, FIREWALL_IP, SFF_IP, TUNNELING_PROTOCOL, packetLen);
    attach_inspection_result((packet + ipHeaderLen), action, metadataNum, metadataCodes);
    memcpy((void *)(packet + ipHeaderLen + resultHeaderLen), (void *)(data + ipHeaderLen), dataLen - ipHeaderLen); //Deteach IP Header of outter encapsulation in data 

    /* Send inspection result packet to SFF */
    sendPacket(packet);

    free(packet);
}

void processUdpProtocol(uint8_t *data, int dataLen, struct iphdr *ipheader) {
	struct udphdr *udpheader = (struct udphdr *) (data + ipHeaderLen + ipHeaderLen); // outterIpHeader + innerIpHeader + udpHeader ...

	printUdpHeader(udpheader);
	int udpHeaderLen = sizeof(struct udphdr);
	int sourcePort = ntohs(udpheader->source);
	int destPort = ntohs(udpheader->dest);

	uint8_t *sipContents = (uint8_t *)(data + ipHeaderLen + ipHeaderLen + udpHeaderLen);


	char *start = strstr(sipContents, "From:") + 6;
	start = strchr(start, ':') + 1;
	char *end = strchr(start, '@');
	char fromPhoneNumber[32];
	strncpy(fromPhoneNumber, start, end - start);
	fromPhoneNumber[end - start] = '\0';


	start = strstr(sipContents, "To:") + 4;
	start = strchr(start, ':') + 1;
	end = strchr(start, '@');
	char toPhoneNumber[32];
	strncpy(toPhoneNumber, start, end - start);
	toPhoneNumber[end - start] = '\0';


	start = strstr(sipContents, "User-Agent:") + 12;
	end = strstr(start, "\r\n");
	char userAgent[64];
	strncpy(userAgent, start, end - start);
	userAgent[end - start] = '\0';


	printf("From: %s, To: %s User-Agent: %s\n", fromPhoneNumber, toPhoneNumber, userAgent);


	int action = PASS;
    int metadataNum = 0;
    int resultHeaderLen = (2 /*resultCode(1) + metadataNum(1)*/ + metadataNum ) * sizeof(uint8_t);
    int packetLen = ipHeaderLen + resultHeaderLen + (dataLen - ipHeaderLen);

    uint8_t *packet = (uint8_t *)malloc(packetLen);
    uint8_t metadataCodes[1] = {DDOS_INSPECTION};

    /* Attach our header & outter trunneling header */
    attach_outter_encapsulation(packet, FIREWALL_IP, SFF_IP, TUNNELING_PROTOCOL, packetLen);
    attach_inspection_result((packet + ipHeaderLen), action, metadataNum, metadataCodes);
    memcpy((void *)(packet + ipHeaderLen + resultHeaderLen), (void *)(data + ipHeaderLen), dataLen - ipHeaderLen); //Deteach IP Header of outter encapsulation in data 

    /* Send inspection result packet to SFF */
    sendPacket(packet);

    free(packet);
}

void processPacket(uint8_t *data, int dataLen, int protocol) {
    if(protocol != TUNNELING_PROTOCOL) return;

    ipHeaderLen = sizeof(struct iphdr);
    struct iphdr *ipheader = (struct iphdr *) (data + ipHeaderLen); /* After outter IP header */
   
	/* Print Ip Header Info*/
	printIPHeader(ipheader);

	if (ipheader->protocol == SENDER_PROTOCOL) {
		processSenderProtocol(data, dataLen, ipheader);
	} else if(ipheader->protocol == UDP_PROTOCOL) {
		processUdpProtocol(data, dataLen, ipheader);
	}
}


void *nsf_sff_interface(void *arg) {
    char *interfaceName = (char *) arg;
    start_listening(interfaceName, &processPacket, DPI_MODE);
    return NULL;
}


int main(int argc, char *argv[]) {
    if(argc < 2) { 
        printf("Usage: ./firewall [interface name] \n");
        exit(-1);
    }

    pthread_t nsf_sff_interface_thread;
    int thread_id;

    if(MysqlInitialize()) {
        thread_id = pthread_create(&nsf_sff_interface_thread, NULL, nsf_sff_interface, (void *)argv[1]);
        if(thread_id < 0) {
            printf("thread create error \n");
            exit(-1);
        }

        start_confd();
    } else {
        fprintf(stderr, "\nMysqlInitialize() Failed\n");
    }


    return 0;
}
