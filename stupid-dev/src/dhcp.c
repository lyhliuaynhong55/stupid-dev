#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "netdevice.h"
#include "skbuff.h"
#include "sock.h"
#include "udp.h"
#include "dhcp.h"
#include "utils.h"

int DHCP_Done = 0; 
int xid; 
struct sock sock_dhcp; 

void random_xid()
{
	srand((unsigned)time(NULL));
	xid = rand();
}

struct dhcp_msg dhmsg;
struct dhcp_msg discover_msg;
struct dhcp_msg request_msg;
struct dhcp_info dhinfo;

void init_sock_dhcp()
{
	sock_dhcp.port = htons(DHCP_CHADDR_LEN);
	sock_dhcp.dest.ip = inet_addr("255.255.255.255");
	sock_dhcp.dest.port = htons(DHCP_SERVER_PORT);
	sock_dhcp.nic = &nic;
}

static void *init_dhcp_msg(struct dhcp_msg *msg, int type)
{
	//random_xid();
	unsigned char *x = NULL;
	memset(msg, 0, sizeof(struct dhcp_msg));
	
	msg->op = 1;
	msg->htype = HTYPE_ETHER;
	msg->hlen = 6;
	msg->hops = 0;
	
	msg->flags = htons(FLAGS_BROADCAST);
	msg->xid = xid;

	memcpy(msg->chaddr, nic.dev_addr, 6);
	
	x = msg->options;
	
	*x++ = OPT_COOKIE1;
	*x++ = OPT_COOKIE2;
	*x++ = OPT_COOKIE3;
	*x++ = OPT_COOKIE4;

	*x++ = OPT_MESSAGE_TYPE;
	*x++ = 1;
	*x++ = type;
	
	return x;
}

void dhcp_discover()
{
	unsigned char *x;
	
	x = init_dhcp_msg(&discover_msg, DHCP_DISCOVER);
	
	*x++ = OPT_PARAMETER_LIST;
	*x++ = 4;
	*x++ = OPT_SUBNET_MASK;
	*x++ = OPT_GATEWAY;
	*x++ = OPT_DNS;
	*x++ = OPT_BROADCAST_ADDR;

	*x++ = OPT_END;
	
	int len = DHCP_MSG_FIXED_SIZE + (x - discover_msg.options);
	if(len < 300)
		len = 300;

	printf("send dhcp discover\n");

	udp_send((unsigned char *)&discover_msg, len, &sock_dhcp);
}

void dhcp_request()
{
	unsigned char *x = NULL;
	
	x = init_dhcp_msg(&request_msg, DHCP_REQUEST);
	
	*x++ = OPT_PARAMETER_LIST;
	*x++ = 4;
	*x++ = OPT_SUBNET_MASK;
	*x++ = OPT_GATEWAY;
	*x++ = OPT_DNS;
	*x++ = OPT_BROADCAST_ADDR;

	*x++ = OPT_REQUESTED_IP;
	*x++ = 4;
	memcpy(x, &dhinfo.ipaddr, 4);
	x +=  4;

	*x++ = OPT_END;
	
	int len = DHCP_MSG_FIXED_SIZE + (x - request_msg.options);

	printf("send dhcp request\n");
	if(len < 300)
		len = 300;
	udp_send((unsigned char *)&request_msg, len, &sock_dhcp);
}

int decode_dhcp_msg(struct dhcp_msg *msg, int len)
{
	unsigned char *x;
	unsigned int opt;
	int optlen;
	
	memset(&dhinfo, 0, sizeof(struct dhcp_info));
	if (len < (DHCP_MSG_FIXED_SIZE + 4)) return -1;

	len -= (DHCP_MSG_FIXED_SIZE + 4);

	if (msg->options[0] != OPT_COOKIE1) return -1;
	if (msg->options[1] != OPT_COOKIE2) return -1;
	if (msg->options[2] != OPT_COOKIE3) return -1;
	if (msg->options[3] != OPT_COOKIE4) return -1;
	
	x = msg->options + 4;
	
	while(len > 2)
	{
		opt = *x++;
		if(opt == OPT_PAD)
		{
			len--;
			continue;
		}
		if(opt == OPT_END)
		{
			break;
		}
		optlen = *x++;
		len -= 2;
		if(optlen > len)
		{
			break;
		}
		switch(opt)
		{
		case OPT_SUBNET_MASK:
			if (optlen >= 4) memcpy(&dhinfo.netmask, x, 4);
			break;
		case OPT_GATEWAY:
			if (optlen >= 4) memcpy(&dhinfo.gateway, x, 4);
			break;
		case OPT_LEASE_TIME:
			if (optlen >= 4) {
				memcpy(&dhinfo.lease, x, 4);
				dhinfo.lease = ntohl(dhinfo.lease);
			}
			break;
		case OPT_SERVER_ID:
			if (optlen >= 4) memcpy(&dhinfo.serveraddr, x, 4);
			break;
		case OPT_MESSAGE_TYPE:
			dhinfo.type = *x;
			break;
		default:
			break;
		}
		x += optlen;
		len -= optlen;
	}

	dhinfo.ipaddr = msg->yiaddr;
	//printf("IP address:%s assigned by server\n", (char *)c_ntoa(dhinfo.ipaddr));

	return 0;
}

void do_dhcp(unsigned char *msg, int len)
{
	if(DHCP_Done == 1) 
		return;

	printf("receive DHCP packet from server, the lenght is %d\n", len);
	memset(&dhmsg, 0, sizeof(struct dhcp_msg));
	memcpy(&dhmsg, msg, len);

	decode_dhcp_msg(&dhmsg, len);
	if(dhinfo.type == DHCP_OFFER)
		dhcp_request();
	else if(dhinfo.type == DHCP_ACK)
	{
		DHCP_Done = 1;
		printf("ip:%s\n", (char *)c_ntoa(nic.ip = dhinfo.ipaddr));
		printf("netmask:%s\n", (char *)c_ntoa(nic.netmask = dhinfo.netmask));
		printf("gateway:%s\n", (char *)c_ntoa(nic.gateway = dhinfo.gateway));
	}
}

void dhcp_wait()
{
	int i;
	for(i = 0; i < 3; i++)
	{
		sleep(1);
		if(DHCP_Done == 1)
			break;
		printf("DHCP configing now, please wait\n");
	}
	if(DHCP_Done == 0)
	{
		DHCP_Done = 1;
		printf("Sorry! Dynamic IP config fail, use Static IP now\n");
	}
}
		
		
void dhcp_init()
{
	init_sock_dhcp();
	random_xid();
	dhcp_discover();
}
