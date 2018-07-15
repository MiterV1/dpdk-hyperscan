#ifndef _L2HY_PCAP_H_
#define _L2HY_PCAP_H_

extern void dump_pcap_init(void);
extern int dump_pcap_write(struct rte_mbuf *bufptr);

#endif
