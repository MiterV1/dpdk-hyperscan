#ifndef _HYPERSCAN_H_
#define _HYPERSCAN_H_
#if 0
#include <limits.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#endif

#include <rte_hash.h>
#include <rte_hash_crc.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

struct matched_data {
    hash_sig_t hash;
    struct rte_hash *handle;
    struct l2fwd_ipv4_5tuple *tuple;
};

extern int hyperscan_init(void);
extern int hyperscan_destroy(void);
extern int hyperscan_scan(struct rte_mbuf *m, struct matched_data *m_data);

#endif
