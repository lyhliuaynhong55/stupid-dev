all: stupid

objs = main.o utils.o skbuff.o dev.o ip_input.o udp.o tcp.o ip_output.o arp.o icmp.o \
ip_route.o netdevice.o sock.o dhcp.o

$(objs):%.o:%.c
	gcc -Wall -c -o $@ $<

stupid:	$(objs)
	gcc -Wall -g -o $@ $(objs) -lpthread
clean:
	rm stupid $(objs)

# auto generated rules
arp.o: arp.c arp.h skbuff.h netdevice.h dev.h sock.h utils.h
dev.o: dev.c dev.h sock.h skbuff.h netdevice.h ip.h arp.h utils.h
ip_input.o: ip_input.c ip.h skbuff.h netdevice.h udp.h sock.h tcp.h icmp.h\
 utils.h
ip_output.o: ip_output.c ip.h skbuff.h netdevice.h sock.h dev.h utils.h \
 ip_route.h
ip_route.o: ip_route.c ip_route.h utils.h netdevice.h
main.o: main.c utils.h ../include/common.h ../include/../src/sock.h \
 ../include/../src/skbuff.h ../include/../src/netdevice.h sock.h skbuff.h \
 netdevice.h dev.h udp.h arp.h ip_route.h
netdevice.o: netdevice.c netdevice.h
skbuff.o: skbuff.c sock.h skbuff.h netdevice.h utils.h arp.h
sock.o: sock.c utils.h ../include/common.h ../include/../src/sock.h \
 ../include/../src/skbuff.h ../include/../src/netdevice.h sock.h udp.h \
 skbuff.h
tcp.o: tcp.c tcp.h skbuff.h netdevice.h
udp.o: udp.c sock.h skbuff.h netdevice.h udp.h utils.h ip.h
icmp.o:icmp.c icmp.h sock.h  skbuff.h  utils.h ip.h arp.h dev.h ip_route.h
utils.o: utils.c ../include/common.h ../include/../src/sock.h \
 ../include/../src/skbuff.h ../include/../src/netdevice.h sock.h utils.h
