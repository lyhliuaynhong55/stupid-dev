#ifndef _UTILS_H
#define _UTILS_H

#include <linux/types.h>

struct pseudo_header {
	__be32 saddr;
	__be32 daddr;
	__u8 resv;
	__u8 protocol;
	__be16 len;
};

extern void error_msg_and_die(char *);
extern __u16 in_checksum(__u16 *addr, int len);
extern void data_dump(char *des, unsigned char *data, int len);

extern char *c_ntoa(__u32 addr);
extern int get_second();

extern int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t
		    len);
extern pid_t lock_test(int fd, int type, off_t offset, int whence, off_t len);

extern void utils_init();

#endif
