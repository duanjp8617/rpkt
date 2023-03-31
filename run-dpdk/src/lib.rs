fn _prevent_compilation() {
    #[cfg(any(not(target_pointer_width = "64"), not(target_os = "linux")))]
    compile_error!("This crate can only be used on 64-bit Linux system.");
}

pub mod error;

mod lcore;
pub use lcore::Lcore;

mod service;
pub use service::{service, try_service, DpdkOption, DpdkService};

mod mempool;
pub use mempool::{Mempool, MempoolConf};

#[cfg(not(feature = "multiseg"))]
mod mbuf;
#[cfg(not(feature = "multiseg"))]
pub use mbuf::Mbuf;

#[cfg(feature = "multiseg")]
mod multiseg;
#[cfg(feature = "multiseg")]
pub use multiseg::Mbuf;
#[cfg(feature = "multiseg")]
mod pbuf;
#[cfg(feature = "multiseg")]
pub use pbuf::Pbuf;

mod port;
pub use port::{
    PortConf, PortInfo, PortStats, RxQueue, RxQueueConf, StatsQueryContext, TxQueue, TxQueueConf,
};

pub mod offload;

pub mod utils;