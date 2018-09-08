#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include<string.h> 
#include<stdio.h>
#include<stdlib.h>
#include <time.h>

struct ipheader {
 unsigned char          iph_ihl:4, /* Little-endian */
                        iph_ver:4;
 unsigned char          iph_tos;
 unsigned short int     iph_len;
 unsigned short int     iph_ident;
 unsigned short int     iph_offset:13,  /* Little-endian*/
                        iph_flags:3;
 unsigned char          iph_ttl;
 unsigned char          iph_protocol;
 unsigned short int     iph_chksum;
 unsigned int           iph_sourceip;
 unsigned int           iph_destip;
};

struct tcpheader {
 u_int16_t      tcph_srcport;
 u_int16_t      tcph_destport;
 u_int32_t      tcph_seqnum;
 u_int32_t      tcph_acknum;
 u_int16_t
                tcph_ns:1,
                tcph_reserved:3,
                tcph_offset:4,
                tcph_fin:1,
                tcph_syn:1,
                tcph_rst:1,
                tcph_psh:1,
                tcph_ack:1,
                tcph_urg:1,
                tcph_ece:1,
                tcph_cwr:1;
 u_int16_t      tcph_win;
 u_int16_t      tcph_chksum;
 u_int16_t      tcph_urgptr;
};

struct tcpheaderOptions
{

    u_int16_t 
        tcph_mssOpt:8,
        tcph_mssLen:8;
    u_int16_t
        tcph_mss;
    u_int16_t
        tcph_sack:8,
        tcph_sackLen:8;
    u_int16_t
        tcph_winOpt:8,
        tcph_winLen:8;
    u_int32_t
        tcph_win:8,
        tcph_winNOP:8,
        tcph_timeOpt:8,
        tcph_timeLen:8;
    u_int32_t tcph_time;
    u_int32_t tcph_timeEcho;
};


/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}



int main(void)
{
  char datagram[4096];
  char data[] = "";
  char srcIP[]="192.168.1.100"; 
  char dstIP[]="192.168.100.1";
  memset(datagram,0,4096);
  struct ipheader *IPInfo = (struct ipheader *) datagram;
  struct tcpheader *TCPHeader = (struct tcpheader *) (datagram + sizeof(struct ipheader));
  struct tcpheaderOptions *TCPOptions = (struct tcpheaderOptions *) (datagram + sizeof(struct tcpheader) + sizeof(struct ipheader));
  struct sockaddr_in sin;               //Te destination
  sin.sin_family = AF_INET;
  sin.sin_port = htons(4);
  sin.sin_addr.s_addr = inet_addr("192.168.100.1");

  IPInfo->iph_ver       = 4;            //What IP version are we using? v4
  IPInfo->iph_ihl       = 5;            //The IP header size in bytes
  IPInfo->iph_tos       = 0;            //The IP header type of service 0x00 is normal
  IPInfo->iph_len       = sizeof(struct ipheader) + sizeof(struct tcpheader) + sizeof(struct tcpheaderOptions);            //The IP length of the IP datagram
  IPInfo->iph_ident     = htonl(54321);         //The IP header ID (used when fragmented)
  IPInfo->iph_offset    = 0;            //IP fragment offset
  IPInfo->iph_ttl       = 255;          //The IP TTL
  IPInfo->iph_protocol          = 6;            //The transport layer protocol (6 for TCP, 1 for ICMP, 17 for UDP)
  IPInfo->iph_chksum    = 0;            //Checksum
  IPInfo->iph_sourceip  = inet_addr("192.168.1.100"); //source
//  IPInfo->iph_destip = sin.sin_addr.s_addr;
  IPInfo->iph_destip    = inet_addr("192.168.100.1");
char source[20];
char dest[20];
inet_ntop(AF_INET, &(IPInfo->iph_sourceip), source, 20);
inet_ntop(AF_INET, &(IPInfo->iph_destip), dest, 20);
printf("Source: %s\n", source);
printf("Dest: %s\n", dest);
  //IPInfo->ip_dst.s_addr       = inet_addr("192.168.1.114");
  TCPHeader->tcph_srcport       = htons(56540);           //The source port
  TCPHeader->tcph_destport      = htons(80);          //The destination port
  srand(time(NULL));
  TCPHeader->tcph_seqnum        = rand();          //the sequence number
  TCPHeader->tcph_acknum        = 0;                 //ACK packet
  TCPHeader->tcph_reserved      = 0;                    //Not used
  TCPHeader->tcph_offset        = 10;                 //
  TCPHeader->tcph_cwr           = 0;
  TCPHeader->tcph_ns            = 0;
  TCPHeader->tcph_syn           = 0;
  TCPHeader->tcph_rst           = 0;
  TCPHeader->tcph_psh           = 0;
  TCPHeader->tcph_ack           = 1;
  TCPHeader->tcph_urg           = 0;
  TCPHeader->tcph_ece           = 0;
  TCPHeader->tcph_cwr           = 0;
  TCPHeader->tcph_ns            = 0;
  TCPHeader->tcph_win           = htons(1024);
  TCPHeader->tcph_chksum        = 0;
  TCPHeader->tcph_urgptr        = 0;
  TCPOptions->tcph_mssOpt       = 2;
  TCPOptions->tcph_mssLen       = 4;
  TCPOptions->tcph_winOpt       = 3;
  TCPOptions->tcph_winLen       = 3;
  TCPOptions->tcph_sack         = 4;
  TCPOptions->tcph_sackLen      = 2;
  TCPOptions->tcph_win          = 7;
  TCPOptions->tcph_winNOP       = 1;
  TCPOptions->tcph_mss          = htons(1460);
  TCPOptions->tcph_timeOpt      = 8;
  TCPOptions->tcph_timeLen      = 10;
  TCPOptions->tcph_time         = 0xdb2b0d00;
  //Adding the data
  //strcpy(datagram + sizeof(struct ipheader) + sizeof(struct tcpheader),data);
  TCPHeader->tcph_chksum = csum((unsigned short *) datagram,TCPHeader->tcph_offset >> 1);
  IPInfo->iph_chksum = csum((unsigned short *) datagram, IPInfo->iph_len >> 1);


  int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if(sockfd == -1) {
    perror("sockfd");
    exit(1);
  }

  //Setting IP_HDRINCL so that the system doesnt add headers to my packets
  {
    int one = 1;
    const int *val = &one;
    if(setsockopt(sockfd,IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
      perror("setsockopt");
      return -1;
    }
    else
      printf("Using your own header\n");
  }
  //Creating a raw socket to send info on
    if(sendto(sockfd, datagram, IPInfo->iph_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
      perror("send");
    else
      printf("sending\n");

  printf("Sent sequence number: %d\n",TCPHeader->tcph_seqnum);

        //Now we will wait to receive a message back
        memset(datagram,0,4096);
        int results = recv(sockfd,datagram,sizeof(datagram),0);
        printf("Results: %d\n",results);
        IPInfo = (struct ipheader *) datagram;
        TCPHeader = (struct tcpheader * ) (datagram + (IPInfo->iph_ihl * 4));
        printf("Packet: IPInfo->iph_ihl %d\n",IPInfo->iph_ihl);
        printf("ACK num = %d\n",TCPHeader->tcph_ack);

char source1[20];
char dest1[20];
inet_ntop(AF_INET, &(IPInfo->iph_sourceip), source, 20);
inet_ntop(AF_INET, &(IPInfo->iph_destip), dest, 20);    

    printf("Source: %s\n",source1);
    printf("Dest: %s\n",dest1);

    printf("Size of ipheader %d\n",sizeof(struct ipheader));
    printf("size of tcpheader %d\n",sizeof(struct tcpheader));

  return 0;
}