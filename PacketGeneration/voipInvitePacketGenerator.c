#include "udpPacketGenerator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUF_SIZE 256
#define MAX_PAYLOAD_SIZE 1024


uint8_t* generateVoipInvitePacket(char *userName, char *fromPhoneNumber, char *toPhoneNumber, char *host, char *srcIp) {
	uint8_t *data = (uint8_t *)malloc(MAX_PAYLOAD_SIZE);
	int ic = 0; // index counter
	char method[8] = "INVITE ";
	char requestUri[64] = "";
	strcat(requestUri, "sip:");
	strcat(requestUri, toPhoneNumber);
	strcat(requestUri, "@");
	strcat(requestUri, host);
	strcat(requestUri, " ");
	char version[16] = "SIP/2.0\r\n";
	char via[128] = "";
	strcat(via, "Via: SIP/2.0/UDP ");
	strcat(via, srcIp);
	strcat(via, ":5060;branch=z9hG4bKnp104984053-44ce4a41");
	strcat(via, srcIp);
	strcat(via, ";rport\r\n");

	char from[128] = "";
	strcat(from, "From: \"");
	strcat(from, userName);
	strcat(from, "\" <sip:");
	strcat(from, fromPhoneNumber);
	strcat(from, "@");
	strcat(from, host);
	strcat(from, ">;tag=6433ef9\r\n");

	char to[128] = "";
	strcat(to, "To: <sip:");
	strcat(to, toPhoneNumber);
	strcat(to, "@");
	strcat(to, host);
	strcat(to, ">\r\n");

	char callId[64] = "";
	strcat(callId, "Call-ID: 105090259-446faf7a");
	strcat(callId, "@");
	strcat(callId, srcIp);
	strcat(callId, "\r\n");

	char cseq[32] = "CSeq: 1 INVITE\r\n";
	char userAgent[64] = "User-Agent: Nero SIPPS IP Phone Version 2.0.51.16\r\n";
	char expire[16] = "Expires: 120\r\n";
	char accept[32] = "Accept: application/sdp\r\n";
	char contentType[32] = "Content-Type: application/sdp\r\n";
	char contentLength[32] = "Content-Length: 272\r\n";
	char contact[64] = "";
	strcat(contact, "Contact: <sip:");
	strcat(contact, fromPhoneNumber);
	strcat(contact, "@");
	strcat(contact, srcIp);
	strcat(contact, ">\r\n");
	char maxForward[32] = "Max-Forwards: 70\r\n";
	char allow[128] = "Allow: INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, INFO\r\n\r\n";

	memcpy(data, method, 7); ic += 7;// method
	memcpy(data + ic, requestUri, strlen(requestUri)); ic += strlen(requestUri); // request line
	memcpy(data + ic, version, 9); ic += 9; // version
	memcpy(data + ic, via, strlen(via)); ic += strlen(via); // via
	memcpy(data + ic, from, strlen(from)); ic += strlen(from);
	memcpy(data + ic, to, strlen(to)); ic += strlen(to);
	memcpy(data + ic, callId, strlen(callId)); ic += strlen(callId);
	memcpy(data + ic, cseq, strlen(cseq)); ic += strlen(cseq);
	memcpy(data + ic, userAgent, strlen(userAgent)); ic += strlen(userAgent);
	memcpy(data + ic, expire, strlen(expire)); ic += strlen(expire);
	memcpy(data + ic, accept, strlen(accept)); ic += strlen(accept);
	memcpy(data + ic, contentType, strlen(contentType)); ic += strlen(contentType);
	memcpy(data + ic, contentLength, strlen(contentLength)); ic += strlen(contentLength);
	memcpy(data + ic, contact, strlen(contact)); ic += strlen(contact);
	memcpy(data + ic, maxForward, strlen(maxForward)); ic += strlen(maxForward);
	memcpy(data + ic, allow, strlen(allow)); ic += strlen(allow);

	data[ic] = '\0';
	//printf("%s\n", (char *)data); 

	return data;
}

// from udpPacketGenerator.h
// int generateUdpPacket (char* interface, char* srcIPv4Address, char* destIPv4Address, int srcPort, int destPort, char* contents)
int main(int argc, char *args[]) {
	if(argc != 2) {
		printf("usage: ./voipInvitePacketGenerator destIPAddress \n");
		return -1;
	}

	FILE *fp;
	int readn, split_buf_num = 0, index = 0;
	char buf[BUF_SIZE], src_ip[16], if_name[20] = {'\0'};
	char *split_buf[30];

	/* Ex - inet 192.168.30.132/24 brd 192.168.30.255 scope global eth0 */
	system("ip addr | grep \"eth0\" | grep \"inet\" | grep \"brd\" >> /tmp/temp.txt");
	fp = fopen("/tmp/temp.txt", "r");
	if(fp == NULL) {
		printf("File open failed \n");
		return -1;
	}



	memset(buf, 0x00, BUF_SIZE);
	readn = fread(buf, BUF_SIZE - 1, 1, fp);
	fclose(fp);
	system("rm /tmp/temp.txt");

	split_buf[split_buf_num] = strtok(buf, " ");
	while(split_buf[split_buf_num] != NULL) {
		split_buf_num++;
		split_buf[split_buf_num] = strtok(NULL, " ");
	}

	/* IP Address */
	char *endPoint = strchr(split_buf[1], '/');
	int endIndex = (int)(endPoint - split_buf[1]);
	strncpy(src_ip, split_buf[1], endIndex);
	src_ip[endIndex] = '\0';

	/* Interface Name */
	endPoint = strchr(split_buf[6], '\n');
	endIndex = (int)(endPoint - split_buf[6]);
	strncpy(if_name, split_buf[6], endIndex);
	if_name[endIndex] = '\0';


	printf("src_ip: %s\n", src_ip);
	printf("if_name: %s\n", if_name);

	// uint8_t* generateVoipInvitePacket(char *userName, char *fromPhoneNumber, char *toPhoneNumber, char *host, char *srcIp)
	uint8_t *data = generateVoipInvitePacket("yys", "070-123-4567", "070-884-1231", "voip.kt.com", src_ip);

	/* 5060 is used for sip port number in UDP/TCP */
	generateUdpPacket(if_name, src_ip, args[1], 5060, 5060, data);
	free(data);
	return 0;
}
