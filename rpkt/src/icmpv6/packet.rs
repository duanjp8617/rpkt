use crate::PktMut;
use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;

use super::msg::*;
use super::ndp::{
    NdpMsgNeighborAdv, NdpMsgNeighborSolicit, NdpMsgRedirect, NdpMsgRouterAdv, NdpMsgRouterSolicit,
};
use super::Icmpv6MsgType;

pub enum Icmpv6Msg<'a> {
    DstUnreachable(Icmpv6MsgGeneric<&'a [u8]>),
    PktTooBig(Icmpv6MsgMtu<&'a [u8]>),
    TimeExceed(Icmpv6MsgGeneric<&'a [u8]>),
    ParamProblem(Icmpv6MsgPtr<&'a [u8]>),
    EchoRequest(Icmpv6MsgEcho<&'a [u8]>),
    EchoReply(Icmpv6MsgEcho<&'a [u8]>),
    NdpNeighborAdv(NdpMsgNeighborAdv<&'a [u8]>),
    NdpNeighborSolicit(NdpMsgNeighborSolicit<&'a [u8]>),
    NdpRedirect(NdpMsgRedirect<&'a [u8]>),
    NdpRouterAdv(NdpMsgRouterAdv<&'a [u8]>),
    NdpRouterSolicit(NdpMsgRouterSolicit<&'a [u8]>),
    Invalid(u8),
}

pub enum Icmpv6MsgMut<'a> {
    DstUnreachable(Icmpv6MsgGeneric<&'a mut [u8]>),
    PktTooBig(Icmpv6MsgMtu<&'a mut [u8]>),
    TimeExceed(Icmpv6MsgGeneric<&'a mut [u8]>),
    ParamProblem(Icmpv6MsgPtr<&'a mut [u8]>),
    EchoRequest(Icmpv6MsgEcho<&'a mut [u8]>),
    EchoReply(Icmpv6MsgEcho<&'a mut [u8]>),
    NdpNeighborAdv(NdpMsgNeighborAdv<&'a mut [u8]>),
    NdpNeighborSolicit(NdpMsgNeighborSolicit<&'a mut [u8]>),
    NdpRedirect(NdpMsgRedirect<&'a mut [u8]>),
    NdpRouterAdv(NdpMsgRouterAdv<&'a mut [u8]>),
    NdpRouterSolicit(NdpMsgRouterSolicit<&'a mut [u8]>),
    Invalid(u8),
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Icmpv6Packet<T> {
    buf: T,
}

impl<T: Buf> Icmpv6Packet<T> {
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
    pub fn msg_type(&self) -> Icmpv6MsgType {
        self.buf.chunk()[0].into()
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = &self.buf.chunk()[2..4];
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf.chunk()[4..]
    }

    #[inline]
    pub fn parse(buf: T) -> Result<Icmpv6Packet<T>, T> {
        if buf.chunk().len() >= 8 && buf.chunk().len() == buf.remaining() {
            Ok(Icmpv6Packet { buf })
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn msg(&self) -> Icmpv6Msg {
        match self.msg_type() {
            Icmpv6MsgType::DST_UNREACHABLE => Icmpv6Msg::DstUnreachable(Icmpv6MsgGeneric {
                buf: self.buf.chunk(),
            }),
            Icmpv6MsgType::PKT_TOO_BIG => Icmpv6Msg::PktTooBig(Icmpv6MsgMtu {
                buf: self.buf.chunk(),
            }),
            Icmpv6MsgType::TIME_EXCEED => Icmpv6Msg::TimeExceed(Icmpv6MsgGeneric {
                buf: self.buf.chunk(),
            }),
            Icmpv6MsgType::PARAM_PROBLEM => Icmpv6Msg::ParamProblem(Icmpv6MsgPtr {
                buf: self.buf.chunk(),
            }),
            Icmpv6MsgType::ECHO_REQUEST => Icmpv6Msg::EchoRequest(Icmpv6MsgEcho {
                buf: self.buf.chunk(),
            }),
            Icmpv6MsgType::ECHO_REPLY => Icmpv6Msg::EchoReply(Icmpv6MsgEcho {
                buf: self.buf.chunk(),
            }),
            _ => {
                let pkt_len = self.buf.chunk().len();
                match self.msg_type() {
                    Icmpv6MsgType::NDP_ROUTER_SOLICIT => {
                        if pkt_len < 8 {
                            Icmpv6Msg::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6Msg::NdpRouterSolicit(NdpMsgRouterSolicit {
                                buf: self.buf.chunk(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_ROUTER_ADV => {
                        if pkt_len < 16 {
                            Icmpv6Msg::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6Msg::NdpRouterAdv(NdpMsgRouterAdv {
                                buf: self.buf.chunk(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_NEIGHBOR_SOLICIT => {
                        if pkt_len < 24 {
                            Icmpv6Msg::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6Msg::NdpNeighborSolicit(NdpMsgNeighborSolicit {
                                buf: self.buf.chunk(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_NEIGHBOR_ADV => {
                        if pkt_len < 24 {
                            Icmpv6Msg::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6Msg::NdpNeighborAdv(NdpMsgNeighborAdv {
                                buf: self.buf.chunk(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_REDIRECT => {
                        if pkt_len < 40 {
                            Icmpv6Msg::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6Msg::NdpRedirect(NdpMsgRedirect {
                                buf: self.buf.chunk(),
                            })
                        }
                    }
                    _ => Icmpv6Msg::Invalid(self.msg_type().into()),
                }
            }
        }
    }
}

impl<T: PktMut> Icmpv6Packet<T> {
    #[inline]
    pub fn set_msg_type(&mut self, value: u8) {
        self.buf.chunk_mut()[0] = value;
    }

    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }

    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = &mut self.buf.chunk_mut()[2..4];
        NetworkEndian::write_u16(data, value);
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf.chunk_mut()[4..]
    }

    #[inline]
    pub fn msg_mut(&mut self) -> Icmpv6MsgMut {
        match self.msg_type() {
            Icmpv6MsgType::DST_UNREACHABLE => Icmpv6MsgMut::DstUnreachable(Icmpv6MsgGeneric {
                buf: self.buf.chunk_mut(),
            }),
            Icmpv6MsgType::PKT_TOO_BIG => Icmpv6MsgMut::PktTooBig(Icmpv6MsgMtu {
                buf: self.buf.chunk_mut(),
            }),
            Icmpv6MsgType::TIME_EXCEED => Icmpv6MsgMut::TimeExceed(Icmpv6MsgGeneric {
                buf: self.buf.chunk_mut(),
            }),
            Icmpv6MsgType::PARAM_PROBLEM => Icmpv6MsgMut::ParamProblem(Icmpv6MsgPtr {
                buf: self.buf.chunk_mut(),
            }),
            Icmpv6MsgType::ECHO_REQUEST => Icmpv6MsgMut::EchoRequest(Icmpv6MsgEcho {
                buf: self.buf.chunk_mut(),
            }),
            Icmpv6MsgType::ECHO_REPLY => Icmpv6MsgMut::EchoReply(Icmpv6MsgEcho {
                buf: self.buf.chunk_mut(),
            }),
            _ => {
                let pkt_len = self.buf.chunk().len();
                match self.msg_type() {
                    Icmpv6MsgType::NDP_ROUTER_SOLICIT => {
                        if pkt_len < 8 {
                            Icmpv6MsgMut::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6MsgMut::NdpRouterSolicit(NdpMsgRouterSolicit {
                                buf: self.buf.chunk_mut(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_ROUTER_ADV => {
                        if pkt_len < 16 {
                            Icmpv6MsgMut::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6MsgMut::NdpRouterAdv(NdpMsgRouterAdv {
                                buf: self.buf.chunk_mut(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_NEIGHBOR_SOLICIT => {
                        if pkt_len < 24 {
                            Icmpv6MsgMut::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6MsgMut::NdpNeighborSolicit(NdpMsgNeighborSolicit {
                                buf: self.buf.chunk_mut(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_NEIGHBOR_ADV => {
                        if pkt_len < 24 {
                            Icmpv6MsgMut::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6MsgMut::NdpNeighborAdv(NdpMsgNeighborAdv {
                                buf: self.buf.chunk_mut(),
                            })
                        }
                    }
                    Icmpv6MsgType::NDP_REDIRECT => {
                        if pkt_len < 40 {
                            Icmpv6MsgMut::Invalid(self.msg_type().into())
                        } else {
                            Icmpv6MsgMut::NdpRedirect(NdpMsgRedirect {
                                buf: self.buf.chunk_mut(),
                            })
                        }
                    }
                    _ => Icmpv6MsgMut::Invalid(self.msg_type().into()),
                }
            }
        }
    }

    #[inline]
    fn prepend_msg(buf: &mut T, msg_type: Icmpv6MsgType, msg_len: usize) {
        assert!(msg_len >= 8 && buf.remaining() == 0);

        buf.move_back(msg_len);
        buf.chunk_mut()[0] = msg_type.into();
        (&mut buf.chunk_mut()[1..msg_len]).fill(0);
    }

    #[inline]
    pub fn prepend_msg_dst_unreachable(buf: &mut T, msg_len: usize) -> Icmpv6MsgGeneric<&mut [u8]> {
        Self::prepend_msg(buf, Icmpv6MsgType::DST_UNREACHABLE, msg_len);
        Icmpv6MsgGeneric {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_pkt_too_big(buf: &mut T, msg_len: usize) -> Icmpv6MsgMtu<&mut [u8]> {
        Self::prepend_msg(buf, Icmpv6MsgType::PKT_TOO_BIG, msg_len);
        Icmpv6MsgMtu {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_time_exceed(buf: &mut T, msg_len: usize) -> Icmpv6MsgGeneric<&mut [u8]> {
        Self::prepend_msg(buf, Icmpv6MsgType::TIME_EXCEED, msg_len);
        Icmpv6MsgGeneric {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_param_problem(buf: &mut T, msg_len: usize) -> Icmpv6MsgPtr<&mut [u8]> {
        Self::prepend_msg(buf, Icmpv6MsgType::PARAM_PROBLEM, msg_len);
        Icmpv6MsgPtr {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_echo_request(buf: &mut T, msg_len: usize) -> Icmpv6MsgEcho<&mut [u8]> {
        Self::prepend_msg(buf, Icmpv6MsgType::ECHO_REQUEST, msg_len);
        Icmpv6MsgEcho {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_echo_reply(buf: &mut T, msg_len: usize) -> Icmpv6MsgEcho<&mut [u8]> {
        Self::prepend_msg(buf, Icmpv6MsgType::ECHO_REPLY, msg_len);
        Icmpv6MsgEcho {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_ndp_router_solicit(
        buf: &mut T,
        msg_len: usize,
    ) -> NdpMsgRouterSolicit<&mut [u8]> {
        assert!(msg_len >= 8 && msg_len % 8 == 0);
        Self::prepend_msg(buf, Icmpv6MsgType::NDP_ROUTER_SOLICIT, msg_len);
        NdpMsgRouterSolicit {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_ndp_router_adv(buf: &mut T, msg_len: usize) -> NdpMsgRouterAdv<&mut [u8]> {
        assert!(msg_len >= 16 && msg_len % 8 == 0);
        Self::prepend_msg(buf, Icmpv6MsgType::NDP_ROUTER_ADV, msg_len);
        NdpMsgRouterAdv {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_ndp_neighbor_solicit(
        buf: &mut T,
        msg_len: usize,
    ) -> NdpMsgNeighborSolicit<&mut [u8]> {
        assert!(msg_len >= 24 && msg_len % 8 == 0);
        Self::prepend_msg(buf, Icmpv6MsgType::NDP_NEIGHBOR_SOLICIT, msg_len);
        NdpMsgNeighborSolicit {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_ndp_neighbor_adv(
        buf: &mut T,
        msg_len: usize,
    ) -> NdpMsgNeighborAdv<&mut [u8]> {
        assert!(msg_len >= 24 && msg_len % 8 == 0);
        Self::prepend_msg(buf, Icmpv6MsgType::NDP_NEIGHBOR_ADV, msg_len);
        NdpMsgNeighborAdv {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }

    #[inline]
    pub fn prepend_msg_ndp_redirected(buf: &mut T, msg_len: usize) -> NdpMsgRedirect<&mut [u8]> {
        assert!(msg_len >= 40 && msg_len % 8 == 0);
        Self::prepend_msg(buf, Icmpv6MsgType::NDP_REDIRECT, msg_len);
        NdpMsgRedirect {
            buf: &mut buf.chunk_mut()[..msg_len],
        }
    }
}
