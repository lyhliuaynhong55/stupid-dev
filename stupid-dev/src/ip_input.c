#include <stdio.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "ip.h"
#include "udp.h"
#include "tcp.h"
#include "utils.h"
#include "icmp.h"

void ip_rcv(struct sk_buff *skb)
{
	struct iphdr *iph;

	iph = skb->nh.iph = (struct iphdr *) skb->data;
	skb->data += iph->ihl * 4;
	/* skb->len -= iph->ihl * 4; */
	skb->len = ntohs(iph->tot_len) - iph->ihl * 4;

	if (iph->version != 4)
		goto drop;
	if (iph->ihl < 5)
		goto drop;
	if (!skb->ip_summed)
		skb->csum = in_checksum((__u16 *) iph, iph->ihl * 4);
	if (skb->csum != 0)
		goto drop;
	if (iph->daddr != skb->nic->ip && iph->daddr != inet_addr("255.255.255.255")) /* broadcast? */
		goto drop;
	
	char s[20], d[20];
	strncpy(s, c_ntoa(iph->saddr), 20);
	strncpy(d, c_ntoa(iph->daddr), 20);
	printf("--- IP: %d bytes  dest: %s  src: %s  ttl:%d\n",
	       ntohs(iph->tot_len), d, s, iph->ttl);

	skb->protocol = iph->protocol;
	switch (iph->protocol)
	{
	case IPPROTO_UDP:
		udp_rcv(skb);
		break;
	case IPPROTO_TCP:
		tcp_rcv(skb);
		break;
	case IPPROTO_ICMP:
		printf("ICMP packet received\n");
		icmp_rcv_send(skb,iph->daddr,iph->saddr);
		break;
	case IPPROTO_IGMP:
		printf("IGMP packet received\n");
		goto drop;
		break;
	default:
		printf("Transport layer protocol %d not supported\n",
		       iph->protocol);
		goto drop;
	}
		
	return;

drop:
	skb_free(skb);
	return;
	/* printf("IP: dropped, csum %x, hlen: %d, dest %s\n", skb->csum, iph->ihl * */
	/*        4, c_ntoa(iph->daddr)); */
}
