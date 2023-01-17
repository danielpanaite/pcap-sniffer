#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

struct ether_hdr {
	u_int8_t macsrc[6];
	u_int8_t macdst[6];
	u_int8_t ether_type;
};

struct ip_hdr{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#endif
    u_int8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t ip_ttl;			/* time to live */
    u_int8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
  };

const struct tok tcp_flag_values[] = {
        { TH_FIN, "F" },
        { TH_SYN, "S" },
        { TH_RST, "R" },
        { TH_PUSH, "P" },
        { TH_ACK, "." },
        { TH_URG, "U" },
        { TH_ECNECHO, "E" },
        { TH_CWR, "W" },
        { 0, NULL }
};

static const struct tok tcp_option_values[] = {
        { TCPOPT_EOL, "eol" },
        { TCPOPT_NOP, "nop" },
        { TCPOPT_MAXSEG, "mss" },
        { TCPOPT_WSCALE, "wscale" },
        { TCPOPT_SACKOK, "sackOK" },
        { TCPOPT_SACK, "sack" },
        { TCPOPT_ECHO, "echo" },
        { TCPOPT_ECHOREPLY, "echoreply" },
        { TCPOPT_TIMESTAMP, "TS" },
        { TCPOPT_CC, "cc" },
        { TCPOPT_CCNEW, "ccnew" },
        { TCPOPT_CCECHO, "" },
        { TCPOPT_SIGNATURE, "md5" },
        { TCPOPT_SCPS, "scps" },
        { TCPOPT_UTO, "uto" },
        { TCPOPT_TCPAO, "tcp-ao" },
        { TCPOPT_MPTCP, "mptcp" },
        { TCPOPT_FASTOPEN, "tfo" },
        { TCPOPT_EXPERIMENT2, "exp" },
        { 0, NULL }
};

struct tcp_hdr{
	u_short src_p;
	u_short dst_p;
	u_int32_t seqn;
	u_int32_t ackn;
	unsigned int h_len:4;
	unsigned int reserved:6;
	struct tcp_flag_values;
	u_short win_size;
	u_short chksum;
	u_short urg_ptr;
	struct tcp_option_values;
};

int main(int argc, char **argv){
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *fp;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pk_data;
	struct ether_hdr *eth_h;
	struct ip_hdr *ip_h;
	struct tcp_hdr *tcp_h;
	
	// Trova tutte le interfacce di rete disponibili
	if(pcap_findalldevs(&alldevs,errbuf)==-1){
		printf("%s",errbuf);
		return -1;
	}
	
	if((fp=pcap_open_live("eth0",65535,1,20,errbuf))==NULL){
		printf("%s",errbuf);
		return -1;
	}
	
	while((res = pcap_next_ex(fp, &header,&pk_data))){
	
		printf("%ld ",header->ts.tv_sec);
		
		eth_h = (struct ether_hdr *) pk_data;
		
		if(ntohs(eth_h->ether_type)==0x800){
			ip_h = (struct ip_hdr *)&pk_data[14];
			tcp_h = (struct tcp_hdr *)&pk_data[14 + sizeof(struct ip_hdr)];
			printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X -> ", eth_h->macsrc[0], eth_h->macsrc[1], eth_h->macsrc[2], eth_h->macsrc[3], eth_h->macsrc[4], eth_h->macsrc[5]);
			printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X  ", eth_h->macdst[0], eth_h->macdst[1], eth_h->macdst[2], eth_h->macdst[3], eth_h->macdst[4], eth_h->macdst[5]);
			printf("%s -> ", inet_ntoa(ip_h->ip_src));
			printf("%s  ", inet_ntoa(ip_h->ip_dst));
			printf("%d  ", ip_h->ip_p);
			if((ip_h->ip_p == 6) || (ip_h->ip_p == 17)){ //check if protocol is TCP or UDP
				printf("%d -> ", tcp_h->src_p);
				printf("%d", tcp_h->dst_p);
			}
			printf("\n");
			if(tcp_h->dst_p == 80){

				printf("\n");
			}
		}
	}
	
	return 0;
}
