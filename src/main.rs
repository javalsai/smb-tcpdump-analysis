#![feature(iterator_try_collect)]
#![feature(never_type)]

pub mod prettify;
pub mod smb;

pub mod tcp;
pub mod tcpdump;

use tcpdump::TcpdumpIter;

fn main() {
    let mut gdynamic = None;

    for (i, msg) in TcpdumpIter::default().enumerate() {
        let msg = msg.expect("error reading tcpdump stream");

        let dynamic = match gdynamic {
            Some(dynamic) => dynamic,
            None => prettify::conn::Dynamic::new(msg.header.src.ip(), msg.header.dst.ip()),
        };
        if gdynamic.is_none() {
            gdynamic = Some(dynamic);
        }

        let data = msg.data.data;

        print!(
            "{i} ({:?} {}) [seq {:?}, ack {:?}, win {}, {:?}]: ",
            dynamic.direction(msg.header.src.ip(), msg.header.dst.ip()),
            data.len(),
            msg.header.seq,
            msg.header.ack,
            msg.header.win,
            msg.header.flags
        );
        if data.is_empty() {
            println!("\x1b[37;3;4mno smb message\x1b[0m");
        } else {
            match smb::SMBMsg::parse_from_raw(data.clone()) {
                Ok(msg) => {
                    println!(
                        "\n {:?}{}",
                        msg.header,
                        prettify::byte::byte_iter_as_str(&mut msg.payload.iter(), 16)
                            .expect("i/o error")
                    );
                }
                Err(err) => {
                    let mut it = data.iter();
                    println!(
                        "\x1b[31;1;3;4msmb msg parse error: {:?}\x1b[0m{}",
                        err,
                        prettify::byte::byte_iter_as_str(&mut it, 16)
                            .expect("i/o error")
                    );
                }
            };
        }
    }
}
