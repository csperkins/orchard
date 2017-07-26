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

extern crate byteorder;
extern crate mio;

use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::time::Duration;
use mio::*;
use mio::net::UdpSocket;

const SOCKET_TOKEN : mio::Token = mio::Token(0);

fn main() {
    let port = 5004;
    let addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let socket = UdpSocket::bind(&SocketAddr::new(addr, port)).unwrap();

    let poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);

    poll.register(&socket, SOCKET_TOKEN, Ready::readable(), PollOpt::edge()).unwrap();

    loop {
        let timeout = Duration::new(1, 0);

        match poll.poll(&mut events, Some(timeout)) {
            Ok(0) => {
                println!("timeout");
            }
            Ok(n) => {
                println!("got {} events", n);
                for event in &events {
                    match event.token() {
                        SOCKET_TOKEN => {
                            println!("got socket event");
                        }
                        _ => {
                            panic!("event with unexpected token");
                        }
                    }
                }
            }
            Err(_) => {
                panic!("poll failed");
            }
        }
    }
}

