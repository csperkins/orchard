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

use std::net::IpAddr;
use bytes::{Bytes, BytesMut, BufMut, BigEndian};

// ================================================================================================
// IpAddr helper extensions:

trait IpAddrExt {
    fn len(&self) -> u16;
    fn version(&self) -> u16;
    fn octets(&self) -> Vec<u8>;
}

impl IpAddrExt for IpAddr {
    fn len(&self) -> u16 {
        match *self {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16
        }
    }

    fn version(&self) -> u16 {
        match *self {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6
        }
    }

    fn octets(&self) -> Vec<u8> {
        let mut octets = Vec::<u8>::new();

        match *self {
            IpAddr::V4(addr) => octets.extend_from_slice(&addr.octets()),
            IpAddr::V6(addr) => octets.extend_from_slice(&addr.octets()),
        }
        octets
    }
}

// ================================================================================================
// Orchard message types and functions:

const ORCHARD_VERSION : u8 = 0;

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
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1024);
        //  0                     1                 2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |      "O"      |      "R"      |      "C"      |     "H"       |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |      "A"      |      "R"      |      "D"      |  version = 0  |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        buf.put(&b"ORCHARD"[..]);
        buf.put_u8(ORCHARD_VERSION);

        match *self {
            OrchardMessage::NatProbe{send_addr, send_port} => {
                //  0                     1                 2                   3
                //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |      "N"      |      "P"      |        length = 8 or 20       |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |           send_port           |    address format = 4 or 6    |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                                                               |
                // |                           send_addr                           |
                // |                       (32 or 128 bits)                        |
                // |                                                               |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                buf.put(&b"NP"[..]);
                buf.put_u16::<BigEndian>(send_addr.len() + 4);
                buf.put_u16::<BigEndian>(send_port);
                buf.put_u16::<BigEndian>(send_addr.version());
                buf.put_slice(&send_addr.octets());
            }
            OrchardMessage::NatReply{send_addr, send_port, recv_addr, recv_port} => {
                // It's possible that the send_addr and recv_addr are different protocols
                // (e.g., if the packet has passed through an IPv6 to IPv4 NAT).
                // 
                //  0                     1                 2                   3
                //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |      "N"      |      "R"      |    length = 16, 28, or 40     |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |           send_port           |    address format = 4 or 6    |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                                                               |
                // |                           send_addr                           |
                // |                       (32 or 128 bits)                        |
                // |                                                               |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |           recv_port           |    address format = 4 or 6    |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                                                               |
                // |                           recv_addr                           |
                // |                       (32 or 128 bits)                        |
                // |                                                               |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                buf.put(&b"NR"[..]);
                buf.put_u16::<BigEndian>(send_addr.len() + recv_addr.len() + 8);
                buf.put_u16::<BigEndian>(send_port);
                buf.put_u16::<BigEndian>(send_addr.version());
                buf.put_slice(&send_addr.octets());
                buf.put_u16::<BigEndian>(recv_port);
                buf.put_u16::<BigEndian>(recv_addr.version());
                buf.put_slice(&recv_addr.octets());
            }
        }

        println!("{:?}", buf);
        buf.freeze()
    }
}

