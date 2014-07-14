/*
   IPMI commands responder
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/types.h>
#include <stdint.h>
#include "listener.h"

struct rmcp_header
{
	/*RMCP header*/
	uint8_t rmcp_version;
	uint8_t rmcp_reserved;
	uint8_t rmcp_seq_number;
	uint8_t rmcp_msg_cls;

}__attribute__((packed));

struct asf_msg
{
	/*ASF message*/
	uint32_t asf_iana_no;
	uint8_t asf_msg_type;
	uint8_t asf_msg_tag;
	uint8_t asf_reserved;
	uint8_t asf_datalen;
	uint32_t asf_iana_no_2;
	uint32_t asf_oem;
	uint8_t asf_ipmi_support;
	uint8_t asf_interactions;
	uint8_t asf_reserved1;
	uint8_t asf_reserved2;
	uint8_t asf_reserved3;
	uint8_t asf_reserved4;
	uint8_t asf_reserved5;
	uint8_t asf_reserved6;
}__attribute__((packed));

struct ipmi_session
{
	/*IPMI session header*/
	uint8_t auth_type;
	uint32_t seq_no;
	uint32_t ipmi_1v5_session_id;
	uint8_t msg_len;}__attribute__((packed));


struct ipmi_payload
{
	/*IPMI payload*/
	uint8_t req_address;
	uint8_t req_lun;
	uint8_t checksum1;
	uint8_t resp_address;
	uint8_t resp_seq;
	uint8_t cmd;

}__attribute__((packed));

struct get_channel_auth_response
{
	uint8_t complete_code;
	uint8_t channel;
	uint8_t auth_type;
	uint8_t auth_status;
	uint8_t ipmi_version;
	uint8_t oem_id_0;
	uint8_t oem_id_1;
	uint8_t oem_id_2;
	uint8_t oem_data;
	uint8_t checksum;
}__attribute__((packed));

struct get_session_challenge_response
{
	uint8_t complete_code;
	uint32_t session_id;
	uint64_t challenge_string[1];
	uint8_t checksum;
}__attribute__((packed));

struct activate_session_response
{
	uint8_t complete_code;
	uint8_t auth_type;
	uint8_t privilege;
	uint32_t challenge_string;
	uint32_t seq_no;
	uint8_t checksum;
}__attribute__((packed));

struct set_privilege_response
{
	uint8_t complete_code;
	uint8_t privilege;
	uint8_t checksum;
}__attribute__((packed));

struct get_device_id_response
{
	uint8_t complete_code;
	uint8_t device_id;
	uint8_t device_rev;
	uint8_t firmware_major;
	uint8_t firmware_minor;
	uint8_t ipmi_version;
	uint8_t device_support;
	uint16_t man_id;
	uint8_t man_id_reserved;
	uint16_t product_id;
	uint8_t aux_data[3];
	uint8_t checksum;
}__attribute__((packed));

struct close_session_response
{
	uint8_t complete_code;
	uint8_t checksum;
}__attribute__((packed));

struct get_picmg_response
{
	uint8_t complete_code;
	uint8_t identifier;
	uint8_t extension_ver;
	uint8_t max_fru;
	uint8_t fru_id;
	uint8_t checksum;
}__attribute__((packed));

int checksum(char msg[],int len)
{
	int i,sum=0,checksum;
	for(i=0;i<len;i++)
		sum+=msg[i];
	checksum=~sum+len;
	return checksum;
}

/*create_packet() constructs the response packet for each of the IPMI commands received from client*/
void create_packet(int tag,char msg[],int type)
{
	rmcp_header *rmcp;
	asf_msg *asf;
	ipmi_session *ipmi_s;
	ipmi_payload *ipmi_p;
	get_channel_auth_response *get_channel_auth;
	get_session_challenge_response *get_session_challenge;
	activate_session_response *activate_session;
	set_privilege_response *set_privilege;
	get_device_id_response *get_device_id;	
	close_session_response *close_session;
	get_picmg_response *get_picmg;	

	/*RMCP header*/
	rmcp=(rmcp_header *)msg;
	rmcp->rmcp_version=RMCP_VERSION;
	rmcp->rmcp_reserved=0x00;
	rmcp->rmcp_seq_number=0xff;

	/*Presence ping packet received,pong packet to be sent back*/
	if(type==PING_CMD)
	{
		rmcp->rmcp_msg_cls=ASF_MSG;
		asf=(asf_msg *)(msg+sizeof rmcp);
		asf->asf_iana_no=0x11be0000;
		asf->asf_msg_type=0x40;//pong
		asf->asf_msg_tag=tag;
		asf->asf_reserved=0x00;
		asf->asf_datalen=0x10;
		asf->asf_iana_no_2=0x8e710000;
		asf->asf_oem=0x00000000;
		asf->asf_ipmi_support=0x81;
		asf->asf_interactions=0x00;
		asf->asf_reserved1=0x00;
		asf->asf_reserved2=0x00;
		asf->asf_reserved3=0x00;
		asf->asf_reserved4=0x00;
		asf->asf_reserved5=0x00;
		asf->asf_reserved6=0x00;
	}
	else
	{
		rmcp->rmcp_msg_cls=IPMI_MSG;
		/*IPMI session header*/
		ipmi_s=(ipmi_session *)(msg+sizeof (rmcp_header));
		ipmi_s->auth_type=AUTH_NONE;
		ipmi_s->seq_no=0x00000000;
		ipmi_s->ipmi_1v5_session_id=SESSION_ID;

		/*IPMI payload*/
		ipmi_p=(ipmi_payload *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session));
		ipmi_p->req_address=IPMI_REQUESTER;
		ipmi_p->req_lun=IPMI_REQ_LUN_NETFN;//LUN and netfn
		ipmi_p->checksum1=IPMI_CHECKSUM1;
		ipmi_p->resp_address=IPMI_RESPONDER;
		ipmi_p->resp_seq=tag;
		ipmi_p->cmd=type;

		switch(type)
		{

				/*Get channel authentication capabilities*/
			case GET_CHANNEL_AUTH_CMD:
				ipmi_s->msg_len=0x10;	
				get_channel_auth=(get_channel_auth_response *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session)+sizeof(ipmi_payload));
				get_channel_auth->complete_code=SUCCESS;
				get_channel_auth->channel=0x01;
				get_channel_auth->auth_type=0x81;
				get_channel_auth->auth_status=0x1c;
				get_channel_auth->ipmi_version=0x00;//version 1.5 supported
				get_channel_auth->oem_id_0=0x00;
				get_channel_auth->oem_id_1=0x00;
				get_channel_auth->oem_id_2=0x00;
				get_channel_auth->oem_data=0x00;
				get_channel_auth->checksum=checksum(msg,get_channel_auth_len-1);
				break;

				/*Get session challenge*/
			case GET_SESSION_CHALLENGE_CMD:
				ipmi_s->msg_len=0x1c;
				get_session_challenge=(get_session_challenge_response *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session)+sizeof(ipmi_payload));
				get_session_challenge->complete_code=SUCCESS;
				get_session_challenge->session_id=SESSION_ID_TEMP;
				get_session_challenge->challenge_string[0]=0x4b3ebf1c129031fb;
				get_session_challenge->challenge_string[1]=0x8b4a6299cdf9bff8;
				get_session_challenge->checksum=checksum(msg,get_session_challenge_len-1);
				break;

				/*Activate session*/
			case ACTIVATE_SESSION_CMD:
				ipmi_s->msg_len=0x12;
				activate_session=(activate_session_response *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session)+sizeof(ipmi_payload));
				activate_session->complete_code=SUCCESS;
				activate_session->auth_type=AUTH_NONE;
				activate_session->privilege=PRIVILEGE_USER;
				activate_session->challenge_string=0x00000000;
				activate_session->seq_no=0x00000000;
				activate_session->checksum=checksum(msg,activate_session_len-1);
				break;

				/*Set session privilege*/
			case SET_PRIVILEGE_CMD:	
				ipmi_s->msg_len=0x09;
				set_privilege=(set_privilege_response *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session)+sizeof(ipmi_payload));
				set_privilege->complete_code=SUCCESS;
				set_privilege->privilege |=(0x0F&PRIVILEGE_USER);//change to user privilege
				set_privilege->checksum=checksum(msg,set_privilege_len-1);
				break;

				/*Get device id*/
			case GET_DEVICE_ID_CMD:
				ipmi_s->msg_len=0x19;
				get_device_id=(get_device_id_response *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session)+sizeof(ipmi_payload));
				get_device_id->complete_code=SUCCESS;
				get_device_id->device_id=DEVICE_ID;
				get_device_id->device_rev=DEVICE_REV;
				get_device_id->firmware_major=(DEVICE_NORMAL_OPERATION)|(FIRMWARE_MAJOR);
				get_device_id->firmware_minor=FIRMWARE_MINOR;
				get_device_id->ipmi_version=IPMI_VERSION;
				get_device_id->device_support=DEVICE_NONE;
				get_device_id->man_id=MANUFACTURER_ID;
				get_device_id->man_id_reserved=0x00;
				get_device_id->product_id=PRODUCT_ID;
				get_device_id->aux_data[0]=0x00;
				get_device_id->aux_data[1]=0x00;
				get_device_id->aux_data[2]=0x00;
				get_device_id->aux_data[3]=0x00;
				get_device_id->checksum=checksum(msg,get_device_id_len-1);
				break;


				/*Close session*/
			case CLOSE_SESSION_CMD:
				ipmi_s->msg_len=0x08;
				close_session=(close_session_response *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session)+sizeof(ipmi_payload));
				close_session->complete_code=SUCCESS;
				close_session->checksum=checksum(msg,close_session_len-1);
				break;


				/*Get PICMG*/
			case GET_PICMG_CMD:
				ipmi_s->msg_len=0x0b;
				get_picmg=(get_picmg_response *)(msg+sizeof (rmcp_header)+sizeof(ipmi_session)+sizeof(ipmi_payload));
				get_picmg->complete_code=SUCCESS;
				get_picmg->identifier=0x00;
				get_picmg->extension_ver=0x01;
				get_picmg->max_fru=0x00;
				get_picmg->fru_id=0x00;
				get_picmg->checksum=checksum(msg,get_picmg_len-1);
				break;
		}
	}
}

int main(void)
{

	struct addrinfo hints, *servinfo, *p;
	int rv,sockfd,numbytes,len=0;
	char msg[50],msg1[50];
	char buf[MAXBUFLEN];
	struct sockaddr_storage their_addr;

	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];

	/*set to AF_INET to force IPv4*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; 
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; 

	if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	/*Bind to a socket*/
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}

	freeaddrinfo(servinfo);

	printf("Listening on UDP port\n");
	while(1)
	{
		addr_len = sizeof their_addr;
		if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
						(struct sockaddr *)&their_addr, &addr_len)) == -1) {
			perror("recvfrom");
			exit(1);
		}

		
		buf[numbytes] = '\0'; 
		if(buf[8]==PING_CMD)
		{	
			printf("Received Presence Ping\n");	
			len=pong_len;
			create_packet(buf[9],msg,buf[8]);
			sendto(sockfd,msg,len,0,(struct sockaddr *)&their_addr,(sizeof their_addr));
		}


		else 
		{

			create_packet(buf[18],msg,buf[19]);
			switch(buf[19])
			{
				case GET_CHANNEL_AUTH_CMD:
					printf("Received Get Channel Authentication Capabilities\n");
					len=get_channel_auth_len;
					break;

				case GET_SESSION_CHALLENGE_CMD:
					printf("Received Get Session Challenge\n");
					len=get_session_challenge_len;
					break;

				case ACTIVATE_SESSION_CMD:
					printf("Received Activate Session\n");
					len=activate_session_len;
					break;

				case SET_PRIVILEGE_CMD:
					printf("Received Set Privilege\n");
					len=set_privilege_len;
					break;

				case CLOSE_SESSION_CMD:
					printf("Received Close Session\n");
					len=close_session_len;
					break;

				case GET_DEVICE_ID_CMD:
					printf("Received Get Device ID\n");
					len=get_device_id_len;
					break;


				default:
					len=get_picmg_len;

			}
			sendto(sockfd,msg,len,0,(struct sockaddr *)&their_addr, (sizeof their_addr));


		}
	}
	close(sockfd);

	return 0;
}
