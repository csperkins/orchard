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

extern crate bytes;
extern crate byteorder;
extern crate getopts;
extern crate mio;
extern crate syslog;

mod message;

use std::env::args;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::time::Duration;
use mio::*;
use mio::net::UdpSocket;
use getopts::Options;
use syslog::{Facility,Severity};

use message::OrchardMessage;

const SOCKET_TOKEN : mio::Token = mio::Token(0);

fn send_probe(socket: &UdpSocket) {
    let dest_addr = IpAddr::V4(Ipv4Addr::new(130, 209, 247, 84));
    let dest_port = 5005;
    let dest = SocketAddr::new(dest_addr, dest_port);

    let local_addr = socket.local_addr().unwrap();

    let msg = OrchardMessage::NatProbe { 
        send_addr : local_addr.ip(),
        send_port : local_addr.port()
    };

    socket.send_to(&msg.encode(), &dest);
}

fn main() {
    let mut passive = false;

    // Parse command line options

    let mut opts = Options::new();
    opts.optflag("p", "passive", "only listen, don't initiate requests");

    let argv : Vec<String> = args().collect();
    match opts.parse(&argv[1..]) {
        Ok(matches) => {
            if matches.opt_present("p") {
                println!("passive mode");
                passive = true;
            }
        }
        Err(_) => {
            panic!("cannot parse options");
        }
    }

    let syslog = syslog::unix(Facility::LOG_USER).unwrap();

    syslog.send(Severity::LOG_NOTICE, "orchard: starting");


    // Event loop

    let port = 5005;
    let addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let socket = UdpSocket::bind(&SocketAddr::new(addr, port)).unwrap();

    let poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);

    poll.register(&socket, SOCKET_TOKEN, Ready::readable(), PollOpt::edge()).unwrap();

    loop {
        let timeout = Duration::new(10, 0);

        match poll.poll(&mut events, Some(timeout)) {
            Ok(0) => {
                syslog.send(Severity::LOG_NOTICE, "orchard: timeout");
                if !passive {
                    send_probe(&socket);
                }
            }
            Ok(n) => {
                println!("got {} events", n);
                for event in &events {
                    match event.token() {
                        SOCKET_TOKEN => {
                            syslog.send(Severity::LOG_NOTICE, "orchard: got socket event");
                            let mut buffer = [0; 1500];
                            let res = socket.recv_from(&mut buffer);
                            println!("{:?}", res);
                            syslog.send(Severity::LOG_NOTICE, &format!("orchard: {:?}", res));
                        }
                        _ => {
                            syslog.send(Severity::LOG_NOTICE, "orchard: unexpected event token");
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

