#include "header.h"

// wrapper function implementations
// Most compilers support `tail call optimization`, So there are no extra overhead for
// function wrapping.
unsigned rte_lcore_id_()
{
    return rte_lcore_id();
}

int rte_mempool_full_(const struct rte_mempool *mp)
{
    return rte_mempool_full(mp);
}

struct rte_mbuf *rte_pktmbuf_alloc_(struct rte_mempool *mp)
{
    return rte_pktmbuf_alloc(mp);
}

int rte_pktmbuf_alloc_bulk_(struct rte_mempool *pool,
                            struct rte_mbuf **mbufs, unsigned count)
{
    return rte_pktmbuf_alloc_bulk(pool, mbufs, count);
}

void rte_pktmbuf_free_(struct rte_mbuf *m)
{
    rte_pktmbuf_free(m);
}

uint16_t rte_eth_rx_burst_(uint16_t port_id, uint16_t queue_id,
                           struct rte_mbuf **rx_pkts, const uint16_t nb_pkts)
{
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t rte_eth_tx_burst_(uint16_t port_id, uint16_t queue_id,
                           struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

int rte_errno_()
{
    return rte_errno;
}