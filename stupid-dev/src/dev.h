#ifndef _DEV_H
#define _DEV_H

#include <linux/types.h>

#include "sock.h"
#include "skbuff.h"

extern struct sk_buff_head backlog;

extern void dev_xmit_init();
extern void net_rx_action(struct sk_buff *skb);
extern __be16 eth_type_trans(struct sk_buff *skb);
extern void dev_send(struct sk_buff *skb);

extern void *do_dev_receive_thread(void *arg);
extern void *do_protocol_receive_thread(void *arg);
extern int dev_xmit(struct sk_buff *skb);

#endif
