use crate::error::*;
use crate::{service, MempoolConf, PortConf, RxQueueConf, TxQueueConf};

/// A standard procedure for initializing a DPDK mempool.
pub fn init_mempool(name: &str, n: u32, cache_size: u32, socket_id: u32) -> Result<()> {
    let mut mempool_conf = MempoolConf::default();
    mempool_conf.set_nb_mbufs(n);
    mempool_conf.set_per_core_caches(cache_size);
    mempool_conf.set_socket_id(socket_id);
    service().mempool_create(name, &mempool_conf)?;
    Ok(())
}

/// A standard procedure for initializing a DPDK port.
pub fn init_port(
    port_id: u16,
    nb_rx_queue: u16,
    nb_tx_queue: u16,
    nb_rx_desc: u16,
    mp_name: &str,
    nb_tx_desc: u16,
    socket_id: u32,
) -> Result<()> {
    // make sure that the port is on the correct socket
    let port_info = service().port_info(port_id)?;
    if port_info.socket_id != socket_id {
        return Err(Error::service_err("invalid socket id"));
    }

    // get the default port conf
    let port_conf = PortConf::from_port_info(&port_info)?;

    // configure rxq
    let mut rxq_conf = RxQueueConf::default();
    rxq_conf.set_nb_rx_desc(nb_rx_desc);
    rxq_conf.set_socket_id(socket_id);
    rxq_conf.set_mp_name(mp_name);
    let rxq_confs: Vec<RxQueueConf> = (0..nb_rx_queue as usize)
        .map(|_| rxq_conf.clone())
        .collect();

    // configure txq
    let mut txq_conf = TxQueueConf::default();
    txq_conf.set_nb_tx_desc(nb_tx_desc);
    txq_conf.set_socket_id(socket_id);
    let txq_confs: Vec<TxQueueConf> = (0..nb_tx_queue as usize)
        .map(|_| txq_conf.clone())
        .collect();

    // create the port
    service().port_configure(port_id, &port_conf, &rxq_confs, &txq_confs)?;

    Ok(())
}

/// A standard procedure to fill a mempool with packet template.
/// Note that the underlying mempool should be full and not be used by other threads.
pub fn fill_mempool(mp_name: &str, packet_template: &[u8]) -> Result<()> {
    let mp = service().mempool(mp_name)?;
    let mut v = Vec::new();

    while let Some(mut mbuf) = mp.try_alloc() {
        mbuf.extend_from_slice(packet_template);
        v.push(mbuf);
    }

    Ok(())
}
