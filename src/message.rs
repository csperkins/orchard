// Copyright (c) 2017 University of Glasgow
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
// 
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use bytes::{Bytes, BytesMut, Buf, BufMut, BigEndian};

pub enum OrchardMessage {
    NatProbe {
        send_addr : IpAddr,
        send_port : u16,
    },
    NatReply {
        send_addr : IpAddr,
        send_port : u16,
        recv_addr : IpAddr,
        recv_port : u16,
    }
}

impl OrchardMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(1024);
        buf.put(&b"ORCHARD"[..]);
        buf.put_u8(0);

        match *self {
            OrchardMessage::NatProbe{send_addr, send_port} => {
                match send_addr {
                    IpAddr::V4(addr) => {
                        buf.put(&b"NP"[..]);                 // "NP" = NAT Probe
                        buf.put_u16::<BigEndian>(4+4);       // Length
                        buf.put_u16::<BigEndian>(0);         // Padding
                        buf.put_u16::<BigEndian>(send_port); // Port
                        buf.put_slice(&addr.octets());       // IPv4 address
                     }
                    IpAddr::V6(addr) => {
                        buf.put(&b"NP"[..]);                 // "NP" = NAT Probe
                        buf.put_u16::<BigEndian>(4+16);      // Length
                        buf.put_u16::<BigEndian>(0);         // Padding
                        buf.put_u16::<BigEndian>(send_port); // Port
                        buf.put_slice(&addr.octets());       // IPv6 address
                    }
                }
            }
            OrchardMessage::NatReply{send_addr, send_port, recv_addr, recv_port} => {
                unimplemented!();
            }
        }

        println!("{:?}", buf);
        buf.to_vec()
    }
}
