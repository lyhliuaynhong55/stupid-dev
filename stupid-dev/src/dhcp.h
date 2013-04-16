#ifndef _DHCP_H
#define _DHCP_H

#include <linux/types.h>
#include "sock.h"

#define DHCP_CHADDR_LEN     16U
#define DHCP_SNAME_LEN      64U
#define DHCP_FILE_LEN       128U
#define DHCP_VEND_LEN       312U

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define FLAGS_BROADCAST     0X8000

#define HTYPE_ETHER         1

/* minimum set of fields of any DHCP message */
struct dhcp_msg
{
	unsigned char op;
	unsigned char htype;
	unsigned char hlen;
	unsigned char hops;
	unsigned int xid;       /* 4 */
	unsigned short secs;    /* 8 */
	unsigned short flags;   
	__be32 ciaddr;          /* 12 */
	__be32 yiaddr;          /* 16 */
	__be32 siaddr;          /* 20 */
	__be32 giaddr;          /* 24 */
	unsigned char chaddr[DHCP_CHADDR_LEN];  /* 28 */
	unsigned char sname[DHCP_SNAME_LEN];    /* 44 */
	unsigned char file[DHCP_FILE_LEN];  /* 108 */
	unsigned char options[DHCP_VEND_LEN];
};

#define DHCP_MSG_FIXED_SIZE 236

/* first four bytes of options are a cookie to indicate that
 * the payload are DHCP options as opposed to some other BOOTP
 * extension
 */
#define OPT_COOKIE1	0x63
#define OPT_COOKIE2	0x82
#define OPT_COOKIE3 	0x53
#define OPT_COOKIE4	0x63
 
/* BOOTP/DHCP options - see RFC 2132 */
#define OPT_PAD              0

#define OPT_SUBNET_MASK      1     /* 4 <ipaddr> */
#define OPT_TIME_OFFSET      2     /* 4 <seconds> */
#define OPT_GATEWAY          3     /* 4*n <ipaddr> * n */
#define OPT_DNS              6     /* 4*n <ipaddr> * n */
#define OPT_DOMAIN_NAME      15    /* n <domainnamestring> */
#define OPT_BROADCAST_ADDR   28    /* 4 <ipaddr> */

#define OPT_REQUESTED_IP     50    /* 4 <ipaddr> */
#define OPT_LEASE_TIME       51    /* 4 <seconds> */
#define OPT_MESSAGE_TYPE     53    /* 1 <msgtype> */
#define OPT_SERVER_ID        54    /* 4 <ipaddr> */
#define OPT_PARAMETER_LIST   55    /* n <optcode> * n */
#define OPT_MESSAGE          56    /* n <errorstring> */
#define OPT_CLASS_ID         60    /* n <opaque> */
#define OPT_CLIENT_ID        61    /* n <opaque> */
#define OPT_END              255

/* DCHP message types */
#define DHCP_DISCOVER   1 
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_DECLINE    4
#define DHCP_ACK        5
#define DHCP_NACK       6
#define DHCP_RELEASE    7
#define DHCP_INFORM     8

struct dhcp_info
{
	unsigned int type;
	unsigned int ipaddr;
	unsigned int gateway;
	unsigned int netmask;
	
	unsigned int serveraddr;/*not use now */
	unsigned int lease; /*also */ 
};

extern int DHCP_Done;
extern struct sock sock_dhcp;
extern void do_dhcp(unsigned char *msg, int len);
extern void dhcp_init();
extern void dhcp_wait();
#endif


