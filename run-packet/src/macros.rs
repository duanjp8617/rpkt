#[macro_export]
macro_rules! header_field_range_accessors {
    ( $(($get_range: ident, $get_range_mut: ident, $left: literal..$right: literal $(,)?)),* $(,)? )
    => {
        $(
            #[inline]
            fn $get_range(buf: &[u8]) -> &[u8] {
                &buf[$left..$right]
            }
        )*

        $(
            #[inline]
            fn $get_range_mut(buf: &mut [u8]) -> &mut [u8] {
                &mut buf[$left..$right]
            }
        )*
    }
}

#[macro_export]
macro_rules! header_field_val_accessors {
    ( $(($get_val: ident, $get_val_mut: ident, $val: literal $(,)?)),* $(,)? )
    => {
        $(
            #[inline]
            fn $get_val(buf: &[u8]) -> &u8 {
                &buf[$val]
            }
        )*

        $(
            #[inline]
            fn $get_val_mut(buf: &mut [u8]) -> &mut u8 {
                &mut buf[$val]
            }
        )*
    }
}

#[macro_export]
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
        }

        impl ::std::convert::From<$size_t> for $tname {
            #[inline]
            fn from(value: $size_t) -> $tname {
                $tname(value)
            }
        }

        impl ::std::convert::From<$tname> for $size_t {
            #[inline]
            fn from(value: $tname) -> $size_t {
                value.0
            }
        }
    };
}

#[macro_export]
macro_rules! packet_base {
    (
        $(#[$packet_attr: meta])*
        pub struct $packet:ident : $pheader:ident {
            header_len: $hlen:expr,
            get_methods: [
                $(
                    $(#[$gmethod_arm_attr: meta])*
                    ($gmethod_name: ident, $gmethod_return_t: ty $(,)?)
                ),*
                $(,)?
            ],
            set_methods: [
                $(
                    $(#[$smethod_arm_attr: meta])*
                    ($smethod_name: ident $(,$smethod_arg:ident : $smethod_arg_t:ty)*$(,)?)
                ),*
                $(,)?
            ],
            unchecked_set_methods: [
                $(
                    $(#[$ucsmethod_arm_attr: meta])*
                    ($ucsmethod_name: ident, $hd_name: ident $(,$ucsmethod_arg:ident : $ucsmethod_arg_t:ty)*$(,)?)
                ),*
                $(,)?
            ]$(,)?
        }
    ) => {
        $(#[$packet_attr])*
        #[derive(Debug)]
        #[repr(transparent)]
        pub struct $packet<T> {
            buf: T,
        }

        impl<T: ::bytes::Buf> $packet<T> {
            #[inline]
            pub fn parse_unchecked(buf: T) -> Self {
                Self { buf }
            }

            #[inline]
            pub fn buf(&self) -> &T {
                &self.buf
            }

            #[inline]
            pub fn release(self) -> T {
                self.buf
            }

            #[inline]
            pub fn header(&self) -> $pheader<&[u8]> {
                let data = &self.buf.chunk()[..$hlen];
                $pheader::new_unchecked(data)
            }
        }

        impl<T: ::bytes::Buf> $packet<T> {
            $(
                #[inline]
                $(#[$gmethod_arm_attr])*
                pub fn $gmethod_name(&self) -> $gmethod_return_t {
                    <$pheader<&[u8]>>::new_unchecked(self.buf.chunk()).$gmethod_name()
                }
            )*
        }

        impl<T: crate::PktMut> $packet<T> {
            $(
                #[inline]
                $(#[$smethod_arm_attr])*
                pub fn $smethod_name(&mut self $(, $smethod_arg: $smethod_arg_t)*) {
                    <$pheader<&mut [u8]>>::new_unchecked(self.buf.chunk_mut()).$smethod_name($($smethod_arg)*)
                }
            )*

            $(
                #[inline]
                $(#[$ucsmethod_arm_attr])*
                pub fn $ucsmethod_name(&mut self $(, $ucsmethod_arg: $ucsmethod_arg_t)*) {
                    <$pheader<&mut [u8]>>::new_unchecked(self.buf.chunk_mut()).$hd_name($($ucsmethod_arg)*)
                }
            )*
        }
    };
}