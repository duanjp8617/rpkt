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
pub use mempool::Mempool;

mod mbuf;
pub use mbuf::Mbuf;

mod pbuf;
pub use pbuf::Pbuf;

// #[cfg(feature = "multiseg")]
// mod multiseg;
// #[cfg(feature = "multiseg")]
// pub use multiseg::Mbuf;
// #[cfg(feature = "multiseg")]
// mod pbuf;
// #[cfg(feature = "multiseg")]
// pub use pbuf::Pbuf;

mod port;
pub use port::{PortStats, RxQueue, StatsQuery, TxQueue};

// pub mod utils;

pub mod sys;

pub mod constant;

mod conf;
pub use conf::{DevInfo, EthConf, RxqConf, TxqConf};

pub mod rdtsc;
