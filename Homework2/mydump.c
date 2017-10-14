#include <pcap.h>  /* if this gives you an error try pcap/pcap.h */
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ether.h>     /* includes net/ethernet.h */
#include <stdbool.h>            

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

// IP header    Reference: https://advancedinternettechnologies.wordpress.com/ipv4-header/
struct ip_header 
{
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

// TCP header 
// Reference : http://www.tcpdump.org/pcap.html
struct tcp_header 
{
	u_short tcp_sport;	/* source port */
	u_short tcp_dport;	/* destination port */
	u_int tcp_sequence;		/* sequence number */
	u_int th_ack;		/* acknowledgement number */
	u_char tcp_offx2;	/* data offset, rsvd */
	u_char th_flags;

#define TH_OFF(th)	(((th)->tcp_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		// window 
	u_short th_sum;		// checksum 
	u_short th_urp;		// urgent pointer 
};

// UDP header 
struct udp_header 
{
	u_short sport;	// source port 
	u_short dport;	// destination port 
	u_short udp_length;  //length of udp packet
	u_short udp_sum;	// checksum 
};


//Reference: http://www.tcpdump.org/sniffex.c
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const u_char *payload;
	struct ether_header *ethernet;
	const struct ip_header *ip;
	const struct tcp_header *tcp;
	const struct udp_header *udp;
	
	static int count = 1; /* packet counter */
	printf("\nPacket count %d:\n", count);
	count++;

	int pay_size;
	int ip_size;
	int tcp_size;
	int udp_size= 8;
	int icmp_size=8;
	
	bool print_payload = false;
	int i = ETHER_ADDR_LEN;
	int position = 0;
	u_char *ptr;
	char time[26], *str = NULL, print[160];
	

	if (args != NULL) {
		str = (char *) args;
	}

	time_t time = (time_t)header->ts.tv_sec;
	strftime(time, 26, "%Y:%m:%d %H:%M:%S", localtime(&time));
	position += snprintf(print + position, 160, "%s.%06d", time, header->ts.tv_usec); //


	/* define ethernet header reference: http://www.tcpdump.org/sniffex.c */
	ethernet = (struct ether_header *) packet;
	//For the source host
	ptr = ethernet->ether_shost;
	do 
	{
		position += snprintf(print + position, 160, "%s%02x", (i == ETHER_ADDR_LEN) ? " | " : ":", *ptr++);
	} while (--i > 0);

	//for the destination host
	ptr = ethernet->ether_dhost;
	i = ETHER_ADDR_LEN;
	do 
	{
		position += snprintf(print + position, 160, "%s%02x", (i == ETHER_ADDR_LEN) ? " -> " : ":", *ptr++);
	} while (--i > 0);


	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4)  //Check for IPv4
	 {
		position = position+snprintf(print + position, 160, " | type 0x%x", ETHERTYPE_IPV4);

		ip = (struct ip_header*)(packet + SIZE_ETHERNET);
		ip_size = IP_HL(ip) * 4;
		if (ip_size < 20) 
		{
			position += snprintf(print + position, 160, " | Invalid IP header length : %u bytes\n", ip_size);
			print[position] = 0;
			printf("%s", print);
			return;
		}

		if (ip->ip_p == IPPROTO_TCP) {

			tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + ip_size);
			position += snprintf(print + position, 160, " | len %d", ntohs(ip->ip_len));
			position += snprintf(print + position, 160, " | %s.%d ->", inet_ntoa(ip->ip_src), ntohs(tcp->tcp_sport));
			position += snprintf(print + position, 160, " %s.%d", inet_ntoa(ip->ip_dst), ntohs(tcp->tcp_dport));
			position += snprintf(print + position, 160, " | TCP");

			tcp_size = TH_OFF(tcp) * 4;
			/*if (tcp_size < 20) 
			{
				position += snprintf(print + position, 160, " | Invalid TCP header length : %u bytes\n", tcp_size);
				print[position] = 0;
				printf("%s", print);
				return;
			}*/

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + tcp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

			if (pay_size > 0) 
			{
				if (str != NULL && strstr((char *) payload, str) == NULL)
						return;

				position += snprintf(print + position, 160, " | Payload : %d bytes\n", pay_size);
				print_payload = true;
			}
			else 
			{
				if (str != NULL)
					return;

				position += snprintf(print + position, 160, "\n");
			}
		} 
		else if (ip->ip_p == IPPROTO_UDP) //If it is an UDP packet
		 {
			udp = (struct udp_header*)(packet + SIZE_ETHERNET + ip_size);
			position += snprintf(print + position, 160, " | len %d", ntohs(ip->ip_len));
			position += snprintf(print + position, 160, " | %s.%d ->", inet_ntoa(ip->ip_src), ntohs(udp->sport));
			position += snprintf(print + position, 160, " %s.%d", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
			position += snprintf(print + position, 160, " | UDP");

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + udp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + udp_size);

			if (pay_size > 0) 
			{
				if (str != NULL && strstr((char *) payload, str) == NULL)
						return;

				position += snprintf(print + position, 160, " | Payload : %d bytes\n", pay_size);
				print_payload = true;
			}
			else 
			{
				if (str != NULL)
					return;

				position += snprintf(print + position, 160, "\n");
			}
		} 
		else
		 if (ip->ip_p == IPPROTO_ICMP)  //If it is ICMP packet
		 {

			position += snprintf(print + position, 160, " | len %d", ntohs(ip->ip_len));
			position += snprintf(print + position, 160, " | %s ->", inet_ntoa(ip->ip_src));
			position += snprintf(print + position, 160, " %s", inet_ntoa(ip->ip_dst));

			position += snprintf(print + position, 160, " | ICMP");

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size + icmp_size);
			pay_size = ntohs(ip->ip_len) - (ip_size + icmp_size);

			if (pay_size > 0)
			{
				if (str != NULL && strstr((char *) payload, str) == NULL)
						return;

				position += snprintf(print + position, 160, " | Payload : %d bytes\n", pay_size);
				print_payload = true;
			}
			else {
				if (str != NULL)
					return;

				position += snprintf(print + position, 160, "\n");
			}
		}

		else 
		{
			position += snprintf(print + position, 160, " | 0x%x", ip->ip_p);

			payload = (u_char *)(packet + SIZE_ETHERNET + ip_size);
			pay_size = ntohs(ip->ip_len) - (ip_size);

			if (pay_size > 0)
			{
				position += snprintf(print + position, 160, " | Payload : %d bytes)\n", pay_size);

				if (str != NULL && strstr((char *) payload, str) == NULL)
						return;

				print_payload = true;
			}
			else {
				if (str != NULL)
					return;

				position += snprintf(print + position, 160, "\n");
			}
		}
	} else if (str == NULL) {
		position += snprintf(print + position, 160, " | type 0x%x\n", ntohs(ethernet->ether_type));
	}

	//print[position] = 0;
	printf("%s", print);
	if (print_payload == true)
		print_payload_packet(payload, pay_size);
}





//This fumction reference taken from : http://www.tcpdump.org/sniffex.c
void print_hex_ascii_line(const u_char *payload, int len, int offset) 
{

	int i;
	int gap;
	const u_char *character;

	printf("%05d   ", offset);

	character = payload;
	for (i = 0; i < len; i++) 
	{
		printf("%02x ", *character);
		character++;
		// print extra space 
		if (i == 7)
			printf(" ");
	}
	/* print space to handler line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	character = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*character))
			printf("%c", *character);
		else
			printf(".");
		character++;
	}

	printf("\n");

	return;
}

//Reference: http://www.tcpdump.org/sniffex.c
void print_payload_packet(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; )
	 {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


//Reference : http://www.tcpdump.org/sniffex.c

int main(int argc, char *argv[]) 
{
	char err[PCAP_ERRBUF_SIZE];//predefined value of pcap_effbuf_size=256, stored in one of the libraries 
	struct bpf_program filter;
	pcap_t *handler;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	int option = 0;
	char *interface = NULL;
	char *file = NULL;
	char *str = NULL;
	char *expression = NULL;

	while ((option = getopt(argc, argv, "i:r:s")) != -1) 
	{
		switch (option) {
		case 'i':  interface = optarg;
			printf("Interface is : %s\n", interface);
			break;
		case 'r':  file = optarg;
			printf("Given file name is : %s\n", file);
			break;
		case 's':  str = optarg;
			printf("Given string is: %s\n", str);
			break;
		default:  printf("\nPlease enter proper command \n");
			return 0;
		}
	}

	if (optind == argc - 1)
		expression = argv[argc - 1];

	if (interface != NULL && file != NULL) {
		printf("\n Please specify proper options. No file name or interfacegiven");
		return 0;
	}

	if (interface == NULL && file == NULL) 
	{
		interface = pcap_lookupdev(err);
		if (interface == NULL) 
			return 0;
		
	}

	if (interface != NULL)  //For the interface
	{
		if (pcap_lookupnet(interface, &net, &mask, err) == -1)  //If there is an error
		{
			printf("pcap_lookupnet error : %s\n", err);
			net = 0;
			mask = 0;
		}
		handler = pcap_open_live(interface, BUFSIZ, 1, 1000, err);
		if (handler == NULL) 
		  return 0;
	}
	else if (file != NULL)  //For the file name
	 {
		handler = pcap_open_offline(file, err);
		if (handler == NULL) 
		{
			printf("pcap_open_offline error : %s\n", err);
			return 0;
		}
	}

	if (expression != NULL) 
	{
		// compile filter string
		if (pcap_compile(handler, &filter, expression, 0, net) == -1) 
		{
			printf("Pcap Error during compilation : %s\n", pcap_geterr(handler));
			return 0;
		}
		// apply compiled filter 
		if (pcap_setfilter(handler, &filter) == -1) 
		{
			printf("Set Filter error : %s\n", pcap_geterr(handler));
			return 0;
		}
	}

	pcap_loop(handler, -1, got_packet, (u_char *)str);

	pcap_close(handler);
	return 0;
}