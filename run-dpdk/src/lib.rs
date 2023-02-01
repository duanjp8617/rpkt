fn _prevent_compilation() {
    #[cfg(any(not(target_pointer_width = "64"), not(target_os = "linux")))]
    compile_error!("This crate can only be used on 64-bit Linux system.");
}

// A macro used for generating dpdk bit-level configuration.
macro_rules! dpdk_offload_conf {
    (
        $(#[$conf_attr: meta])*
        pub struct $conf_ident:ident ($val_type:ty) {
            $(
                $(#[$field_attr:meta])*
                $field_name:ident, $enable_field_name:ident, $init_val:literal << $shift_val:literal
            ),+ $(,)?
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        $(#[$conf_attr])*
        pub struct $conf_ident(pub(crate) $val_type);

        impl $conf_ident {
            $(
                $(#[$field_attr])*
                #[inline]
                pub fn $field_name(&self) -> bool {
                    (self.0 & (($init_val as $val_type) << $shift_val)) != 0
                }

                $(#[$field_attr])*
                #[inline]
                pub fn $enable_field_name(&mut self) {
                    self.0 = self.0 | (($init_val as $val_type) << $shift_val);
                }
            )+

            #[allow(dead_code)]
            pub(crate) const ALL_ENABLED: Self = Self (
                $(
                    (($init_val as $val_type) << $shift_val)
                )|+
            );

            pub const ALL_DISABLED: Self = Self(0);
        }
    };
}

pub mod error;

mod lcore;
pub use lcore::Lcore;

mod service;
pub use service::{service, try_service, DpdkOption, DpdkService};

mod mempool;
pub use mempool::{Mempool, MempoolConf};

// #[cfg(not(feature = "multi-seg"))]
// mod mbuf;
// #[cfg(not(feature = "multi-seg"))]
// pub use mbuf::Mbuf;

// #[cfg(feature = "multi-seg")]
mod multiseg;
// #[cfg(feature = "multi-seg")]
pub use multiseg::Mbuf;
// #[cfg(feature = "multi-seg")]
mod pbuf;
// #[cfg(feature = "multi-seg")]
pub use pbuf::Pbuf;

mod port;
pub use port::{PortConf, PortInfo, PortStats, RxQueue, RxQueueConf, TxQueue, TxQueueConf};

pub mod offload;
