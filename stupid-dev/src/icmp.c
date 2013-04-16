#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <netdb.h> 

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/msg.h>
#include <fcntl.h>
#include <sys/un.h>


#include "sock.h"
#include "skbuff.h"
#include "icmp.h"
#include "utils.h"
#include "ip.h"
#include "arp.h"
#include "dev.h"
#include "ip_route.h"


static int Sendnum;
static char Mac[ETH_ALEN];

/* really small chance with race condition here, so lock will be added later */


void *do_ping(void *arg)
{
    char cPing[21];
    char temp[16];
    char pingh[5];
    char str[5]={'p','i','n','g'};
    __u32 dest;
		
	while(1)
	{
    	//	printf("Please input ping IP:"); 
	       	gets(cPing);
		int j=5;
	        while(j--)
	        {
                 pingh[j-1]=cPing[j-1];
	        }	       
	        	       
	       if(strcmp(pingh,str)==0)
                  {
	        	 int i=16;
                         while(i--)	
	        	{
		        	temp[i-1]=cPing[i+4];
		        }
	        
	        	dest = inet_addr(temp);
                        arp_request(dest);
	        	arp_table[arp_hash(dest)].status = ARP_STATUS_REQUEST;
	        	while(1)
	         	{	   
                             if(arp_table[arp_hash(dest)].status == ARP_STATUS_OK)
			     {
				     memcpy(Mac, arp_table[arp_hash(dest)].mac, ETH_ALEN);
				     break;
			     }
			}
	  	  } 
		ping(dest);  
	}
}

void ping(__u32 dest)    
{        

        struct sk_buff *skb;
	struct icmphdr *icmph;		
	struct iphdr *iph;
	struct ethhdr *eh;
	
	int hl;
	pid_t pid;

	skb = alloc_skb(&nic);
	skb->len = 0;
	hl = sizeof(struct ethhdr);
	skb->len += hl;
    eh = (struct ethhdr *) skb->data;
	memcpy(eh->h_source, nic.dev_addr, ETH_ALEN);		
	memcpy(eh->h_dest, Mac, ETH_ALEN);
	eh->h_proto = htons(ETH_P_IP);
	
	pid = getpid();
	icmph = skb->h.icmph = (struct icmphdr*) (skb->data + 34);
    icmph->type = ICMP_ECHO;
	icmph->checksum = 0;
	icmph->un.echo.id = pid;
	icmph->un.echo.sequence = 1;
	icmph->checksum = in_checksum((__u16 *)(skb->data + 34),8);
    skb->len += 40;

	hl = sizeof(struct iphdr);
	skb->len += hl;
    iph = (struct iphdr *) (skb->data + 14);
	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(skb->len - 14);
	iph->tos = 0;
	iph->id = pid;
	iph->frag_off = 0;
	iph->ttl = 32;
	iph->protocol = 1;
	iph->saddr = nic.ip;
	iph->daddr = dest;
	iph->check = 0;
	iph->check = in_checksum((__u16 *)(skb->data + 14), hl);
	skb->protocol = ETHERTYPE_IP;
	Sendnum = 4;
//	printf("here \n");	
	dev_xmit(skb);
}

void icmp_rcv_send(struct sk_buff *skb,__u32 scr,__u32 dest)
{
	struct icmphdr *icmph;		
	struct iphdr *iph;
	struct ethhdr *eh;
	unsigned char mac[ETH_ALEN];
	int hl;
	struct in_addr addr1;
	
	icmph = skb->h.icmph = (struct icmphdr*) skb->data;
    switch(icmph->type)
    {
    case ICMP_ECHOREPLY:
		addr1.s_addr = dest;
		icmph->type = ICMP_ECHO;
		Sendnum --;
		if(Sendnum == 0)
		{
            printf("Ping succeed!\n");
			goto drop;
			
		}
		printf("come from %s reply:%dByte\n",inet_ntoa(addr1),(skb->len-8));
		sleep(1);
		break;    
	case ICMP_ECHO:
		icmph->type = ICMP_ECHOREPLY;
                sleep(1);
		break;
	case ICMP_DEST_UNREACH:
                printf("Destination Unreachable");
		break;
	 case ICMP_SOURCE_QUENCH:
		printf("Source Quench");
                break;
         case ICMP_REDIRECT:
		printf("Redirect-> change route");
		break;
	 case ICMP_TIME_EXCEEDED:
                printf("Time Exceeded  ");
                break;
         case ICMP_PARAMETERPROB:
		printf("Parameter Problem ");
		break;
         case ICMP_TIMESTAMP:
                printf("Timestamp Request");
                break;
         case ICMP_TIMESTAMPREPLY:
	       printf("Timestamp Reply");
	       break;
	 case ICMP_INFO_REQUEST:
	       printf("Information Request");
	       break;
	 case ICMP_INFO_REPLY:
	       printf("Information Reply");
	       break;
	 case ICMP_ADDRESS:
	       printf("Address Mask Request");
	       break;
	 case ICMP_ADDRESSREPLY:
	       printf("Address Mask Reply");
	       break;
         default :
	       printf("Unkown icmp packet\n");
               goto drop;	      
	}
	
	icmph->checksum = 0;
	icmph->checksum = in_checksum((__u16 *)skb->data,skb->len);

	hl = sizeof(struct iphdr);
	/* assumed that no ip options here */
	skb->data -= hl;
	skb->len += hl;

	skb->nh.iph = iph = (struct iphdr *) skb->data;
	memset(iph, 0, hl);

	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(skb->len);
	iph->ttl = 32;
	iph->protocol = skb->protocol;
	iph->saddr = scr;
	iph->daddr = dest;
	iph->check = in_checksum((__u16 *)skb->data, hl);

	skb->protocol = ETHERTYPE_IP;

	hl = sizeof(struct ethhdr);
	skb->data -= hl;
	skb->len += hl;
    eh = (struct ethhdr *) skb->data;
	memcpy(mac, eh->h_dest, ETH_ALEN);
	memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
	memcpy(eh->h_source, mac, ETH_ALEN);
	eh->h_proto = htons(ETH_P_IP);
//	for(i=0;i<=70;i++)
//		printf("%x ",((__u16 *)skb->data)[i]);
//	printf("\n ");
	dev_xmit(skb);
	return;
	
drop:
	skb_free(skb);
	return;
}


