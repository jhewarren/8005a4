
# Makefile for dns0

CC=gcc -g
CLIB=-lpcap
PKG=dns0

default: $(PKG)

$(PKG): $(PKG).o proc_ether.o proc_hdrs.o proc_payload.o stealth.o pkt_sniff.h
	$(CC) -o $(PKG) $(PKG).o proc_ether.o proc_hdrs.o proc_payload.o stealth.o $(CLIB)

clean:
	rm -f *.o core $(PKG)

	$(PKG).o:
$(PKG).o: $(PKG).c
	$(CC) -c $(PKG).c

stealth.o: stealth.c
	$(CC) -c stealth.c

proc_ether.o: proc_ether.c
	$(CC) -c proc_ether.c

proc_hdrs.o: proc_hdrs.c
	$(CC) -c proc_hdrs.c

proc_payload.o: proc_payload.c
	$(CC) -c proc_payload.c
