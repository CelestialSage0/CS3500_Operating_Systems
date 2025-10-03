#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02};

static struct spinlock netlock;
#define MAX_PENDING_PACKETS 16
#define min(a, b) ((a) < (b) ? (a) : (b))

struct pending_packet {
    char *data;
    int len;
    uint32 src_ip;
    uint16 src_port;
    struct pending_packet *next;
};

struct bound_port {
    uint16 port;
    int pending_count;
    struct spinlock lock;
    struct pending_packet *head;
    struct pending_packet *tail;
};

#define MAX_PORTS 64
struct {
    struct spinlock lock;
    struct bound_port ports[MAX_PORTS];
    int port_count;
} udp_table;

void netinit(void) {
    initlock(&netlock, "netlock");
    udp_table.port_count = 0;
}

static struct bound_port *find_bound_port(uint16 port) {
    for (int i = 0; i < udp_table.port_count; i++) {
        if (udp_table.ports[i].port == port) {
            return &udp_table.ports[i];
        }
    }
    return 0;
}

//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64 sys_bind(void) {
    int port;
    argint(0, &port);

    acquire(&udp_table.lock);

    if (find_bound_port(port) != 0) {
        release(&udp_table.lock);
        return -1;
    }

    if (udp_table.port_count >= MAX_PORTS) {
        release(&udp_table.lock);
        return -1;
    }

    struct bound_port *bp = &udp_table.ports[udp_table.port_count++];
    bp->port = port;
    bp->pending_count = 0;
    bp->head = bp->tail = 0;
    initlock(&bp->lock, "bound_port");

    release(&udp_table.lock);
    return 0;
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64 sys_unbind(void) {
    //
    // Optional: Your code here.
    //

    return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64 sys_recv(void) {
    int dport;
    uint64 src_arg, sport_arg, buf;
    int maxlen;
    struct proc *p = myproc();
    struct bound_port *bp;
    struct pending_packet *pp;
    int ret = -1;

    argint(0, &dport);
    argaddr(1, &src_arg);
    argaddr(2, &sport_arg);
    argaddr(3, &buf);
    argint(4, &maxlen);

    acquire(&udp_table.lock);
    if ((bp = find_bound_port(dport)) == 0) {
        release(&udp_table.lock);
        return -1;
    }

    acquire(&bp->lock);
    release(&udp_table.lock);

    while (bp->head == 0) {
        if (p->killed) {
            release(&bp->lock);
            return -1;
        }
        sleep(bp, &bp->lock);
    }

    pp = bp->head;
    bp->head = pp->next;
    if (bp->head == 0) {
        bp->tail = 0;
    }
    bp->pending_count--;

    if (copyout(p->pagetable, src_arg, (char *)&pp->src_ip,
                sizeof(pp->src_ip)) < 0 ||
        copyout(p->pagetable, sport_arg, (char *)&pp->src_port,
                sizeof(pp->src_port)) < 0) {
        goto bad;
    }

    int copy_len = pp->len;
    if (copy_len > maxlen) {
        copy_len = maxlen;
    }

    if (copyout(p->pagetable, buf, pp->data, copy_len) < 0) {
        goto bad;
    }

    ret = copy_len;

bad:
    if (pp->data) {
        kfree(pp->data);
    }
    kfree(pp);
    release(&bp->lock);
    return ret;
}

static unsigned short in_cksum(const unsigned char *addr, int len) {
    int nleft = len;
    const unsigned short *w = (const unsigned short *)addr;
    unsigned int sum = 0;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(const unsigned char *)w;
        sum += answer;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);

    answer = ~sum;
    return answer;
}

uint64 sys_send(void) {
    struct proc *p = myproc();
    int sport;
    int dst;
    int dport;
    uint64 bufaddr;
    int len;

    argint(0, &sport);
    argint(1, &dst);
    argint(2, &dport);
    argaddr(3, &bufaddr);
    argint(4, &len);

    int total =
        len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
    if (total > PGSIZE) {
        return -1;
    }

    char *buf = kalloc();
    if (buf == 0) {
        printf("sys_send: kalloc failed\n");
        return -1;
    }
    memset(buf, 0, PGSIZE);

    struct eth *eth = (struct eth *)buf;
    memmove(eth->dhost, host_mac, ETHADDR_LEN);
    memmove(eth->shost, local_mac, ETHADDR_LEN);
    eth->type = htons(ETHTYPE_IP);

    struct ip *ip = (struct ip *)(eth + 1);
    ip->ip_vhl = 0x45;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 100;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_src = htonl(local_ip);
    ip->ip_dst = htonl(dst);
    ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

    struct udp *udp = (struct udp *)(ip + 1);
    udp->sport = htons(sport);
    udp->dport = htons(dport);
    udp->ulen = htons(len + sizeof(struct udp));

    char *payload = (char *)(udp + 1);
    if (copyin(p->pagetable, payload, bufaddr, len) < 0) {
        kfree(buf);
        printf("send: copyin failed\n");
        return -1;
    }

    e1000_transmit(buf, total);

    return 0;
}

void ip_rx(char *buf, int len) {
    static int seen_ip = 0;
    if (seen_ip == 0) {
        printf("ip_rx: received an IP packet\n");
    }
    seen_ip = 1;

    struct eth *ethhdr = (struct eth *)buf;
    struct ip *iphdr = (struct ip *)(ethhdr + 1);

    if (len < sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp)) {
        printf("not udp length\n");
        return;
    }

    struct udp *udphdr = (struct udp *)(iphdr + 1);
    int udp_len = ntohs(udphdr->ulen);
    if (udp_len < sizeof(struct udp) ||
        len < sizeof(struct eth) + sizeof(struct ip) + udp_len) {
        return;
    }

    uint16 dport = ntohs(udphdr->dport);

    acquire(&udp_table.lock);
    struct bound_port *bp = find_bound_port(dport);
    if (bp == 0) {
        printf("bp is 0!\n");
        kfree(buf);
        release(&udp_table.lock);
        return;
    }

    acquire(&bp->lock);
    release(&udp_table.lock);

    if (bp->pending_count >= MAX_PENDING_PACKETS) {
        printf("pending counts is larger than 16!\n");
        goto bad;
    }

    int payload_len = ntohs(udphdr->ulen) - sizeof(struct udp);
    char *data = kalloc();
    if (data == 0) {
        printf("kalloc data failed\n");
        goto bad;
    }

    struct pending_packet *pp = kalloc();
    if (pp == 0) {
        printf("kalloc pending packet failed\n");
        kfree(data);
        goto bad;
    }

    memset(pp, 0, sizeof(*pp));
    memmove(data, (char *)(udphdr + 1), payload_len);
    pp->data = data;
    pp->len = payload_len;
    pp->src_ip = ntohl(iphdr->ip_src);
    pp->src_port = ntohs(udphdr->sport);
    pp->next = 0;

    if (bp->tail == 0) {
        bp->head = bp->tail = pp;
    } else {
        bp->tail->next = pp;
        bp->tail = pp;
    }
    bp->pending_count++;

    wakeup(bp);
bad:
    kfree(buf);
    release(&bp->lock);
}

void arp_rx(char *inbuf) {
    static int seen_arp = 0;

    if (seen_arp) {
        kfree(inbuf);
        return;
    }
    printf("arp_rx: received an ARP packet\n");
    seen_arp = 1;

    struct eth *ineth = (struct eth *)inbuf;
    struct arp *inarp = (struct arp *)(ineth + 1);

    char *buf = kalloc();
    if (buf == 0) {
        panic("send_arp_reply");
    }

    struct eth *eth = (struct eth *)buf;
    memmove(eth->dhost, ineth->shost, ETHADDR_LEN);
    memmove(eth->shost, local_mac, ETHADDR_LEN);
    eth->type = htons(ETHTYPE_ARP);

    struct arp *arp = (struct arp *)(eth + 1);
    arp->hrd = htons(ARP_HRD_ETHER);
    arp->pro = htons(ETHTYPE_IP);
    arp->hln = ETHADDR_LEN;
    arp->pln = sizeof(uint32);
    arp->op = htons(ARP_OP_REPLY);

    memmove(arp->sha, local_mac, ETHADDR_LEN);
    arp->sip = htonl(local_ip);
    memmove(arp->tha, ineth->shost, ETHADDR_LEN);
    arp->tip = inarp->sip;

    e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

    kfree(inbuf);
}

void net_rx(char *buf, int len) {
    struct eth *eth = (struct eth *)buf;

    if (len >= sizeof(struct eth) + sizeof(struct arp) &&
        ntohs(eth->type) == ETHTYPE_ARP) {
        arp_rx(buf);
    } else if (len >= sizeof(struct eth) + sizeof(struct ip) &&
               ntohs(eth->type) == ETHTYPE_IP) {
        ip_rx(buf, len);
    } else {
        kfree(buf);
    }
}
