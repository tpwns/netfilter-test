#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct my_ipv4_hdr
{
    u_int8_t  ip_v_hl;       /* version, header length */
    u_int8_t  ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t  ip_ttl;          /* time to live */
    u_int8_t  ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IPTYPE_TCP                  0x06

struct my_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t  th_off;        /* data offset */    
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

char targetaddress[30];

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);   //제일 중요, ret는 잡힌 패킷 길이, &data는 패킷 시작 위치를 받는다.
	if (ret >= 0){
		printf("payload_len=%d\n", ret);
    }
	





	struct my_ipv4_hdr *ip_hdr = (struct my_ipv4_hdr *)(data);
	struct my_tcp_hdr *tcp_hdr = (struct my_tcp_hdr *)(ip_hdr+1);

	if(ntohs(tcp_hdr->th_dport) != 80 && ntohs(tcp_hdr->th_sport) != 80)	//1.80번 포트가 아닌 경우 통과
	{
		return id;
	}

	uint16_t tcp_hdr_len = (tcp_hdr->th_off>>4) << 2;	//upper 4bit * 4
	char *http_hdr = (char *)(tcp_hdr);
	http_hdr = http_hdr += tcp_hdr_len;

	if(strncmp(http_hdr,"GET",3)){		//2.http헤더가 위치할 부분에 시작이 GET이 아닌 경우는 통과
		return id;
	}

	//http헤더에서 "Host: "부분을 찾는 코드 
	int i=0;
	while(memcmp(&http_hdr[i],"Host: ",6)){
		i++;
	}
	i+=6;

	if(!strncmp(&http_hdr[i],targetaddress,strlen(targetaddress))){
		printf("**********************************************************\n");
		printf("\"%s\" is blocked\n",targetaddress);
		printf("packet info\n");
		dump(data,ret);
		printf("**********************************************************\n");
		return 0;
	}
	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);  //호출
	//printf("entering callback\n");
	if(id)	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc != 2) {
		printf("syntax : netfilter-test <host>\n");
		printf("sample : netfilter-test test.gilgil.net\n");
		return -1;
	}

	strncpy(targetaddress,argv[1],strlen(argv[1]));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);    //nfq에 cb라는 함수를 등록, 패킷이 넷필터에 들어올때 cb(call back)이 실행
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
