macro_rules! enum_sim {
    (
        $(#[$enum_attr: meta])*
        pub struct $tname:ident ($size_t:ty) {
            $(
                $(#[$arm_attr: meta])*
                $enum_arm:ident = $num_exp:expr
            ),+ $(,)?
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        $(#[$enum_attr])*
        pub struct $tname($size_t);

        impl $tname {
            $(
                $(#[$arm_attr])*
                pub const $enum_arm: Self = Self($num_exp);
            )+

            /// Get the raw value.
            pub fn raw(&self) -> $size_t {
                self.0
            }
        }

        impl ::core::convert::From<$size_t> for $tname {
            #[inline]
            fn from(value: $size_t) -> $tname {
                $tname(value)
            }
        }

        impl ::core::convert::From<$tname> for $size_t {
            #[inline]
            fn from(value: $tname) -> $size_t {
                value.0
            }
        }
    };
}
