//! Ancillary parser models, independent of syscall or Android binding behavior.

use super::*;

fn decoded(
    ipv6: bool,
    index: u32,
    gro_stride: Option<i32>,
    flags: i32,
) -> (RecvMeta, Option<NonZeroU32>) {
    let mut name: libc::sockaddr_storage = unsafe { mem::zeroed() };
    name.ss_family = libc::AF_INET as _;
    let name = MaybeUninit::new(name);
    let mut control = cmsg::Aligned([0u8; CMSG_LEN]);
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    hdr.msg_control = control.0.as_mut_ptr().cast();
    hdr.msg_controllen = CMSG_LEN;
    hdr.msg_flags = flags;
    let mut encoder = unsafe { cmsg::Encoder::new(&mut hdr) };
    if ipv6 {
        encoder.push(
            libc::IPPROTO_IPV6,
            libc::IPV6_PKTINFO,
            libc::in6_pktinfo {
                ipi6_addr: libc::in6_addr {
                    s6_addr: Ipv6Addr::LOCALHOST.octets(),
                },
                ipi6_ifindex: index as _,
            },
        );
    } else {
        encoder.push(
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            libc::in_pktinfo {
                ipi_ifindex: index as i32,
                ipi_spec_dst: libc::in_addr { s_addr: 0 },
                ipi_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([192, 0, 2, 1]),
                },
            },
        );
    }
    encoder.push(libc::IPPROTO_IP, libc::IP_TOS, 2u8);
    if let Some(stride) = gro_stride {
        encoder.push(libc::SOL_UDP, gro::UDP_GRO, stride);
    }
    encoder.finish();
    decode_recv(&name, &hdr, 3000)
}

#[test]
fn pktinfo_interfaces_follow_each_buffer_and_cover_all_gro_segments() {
    for ipv6 in [false, true] {
        for index in [7, 19] {
            let (meta, interface) = decoded(ipv6, index, Some(1200), 0);
            assert_eq!(interface, NonZeroU32::new(index));
            assert_eq!(meta.len, 3000);
            assert_eq!(meta.stride, 1200);
            assert_eq!(meta.ecn, Some(EcnCodepoint::Ect0));
            assert_eq!(
                meta.dst_ip,
                Some(if ipv6 {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                } else {
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
                })
            );
        }
    }
}

#[test]
fn absent_zero_negative_or_truncated_packet_info_never_infers_interface() {
    let mut name: libc::sockaddr_storage = unsafe { mem::zeroed() };
    name.ss_family = libc::AF_INET as _;
    let hdr: libc::msghdr = unsafe { mem::zeroed() };
    assert_eq!(decode_recv(&MaybeUninit::new(name), &hdr, 1).1, None);
    for ipv6 in [false, true] {
        assert_eq!(decoded(ipv6, 0, None, 0).1, None);
        assert_eq!(decoded(ipv6, 7, None, libc::MSG_CTRUNC).1, None);
    }
    assert_eq!(decoded(false, u32::MAX, None, 0).1, None);
    #[cfg(target_os = "android")]
    assert_eq!(decoded(true, u32::MAX, None, 0).1, None);
}

#[test]
fn scoped_receive_limits_outputs_and_old_receive_remains_usable() {
    for local in ["127.0.0.1:0", "[::1]:0"] {
        let receiver = std::net::UdpSocket::bind(local).unwrap();
        let sender = std::net::UdpSocket::bind(local).unwrap();
        let state = UdpSocketState::new((&receiver).into()).unwrap();
        let mut first = [0; 128];
        let mut second = [0; 128];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut meta = [RecvMeta::default(); 2];
        assert_eq!(
            state
                .recv_scoped((&receiver).into(), &mut bufs, &mut meta, &mut [])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        sender
            .send_to(&[42], receiver.local_addr().unwrap())
            .unwrap();
        // A blocking receive avoids scheduler/timing assumptions in this kernel test.
        receiver.set_nonblocking(false).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut interfaces = [NonZeroU32::new(999)];
        assert_eq!(
            state
                .recv_scoped((&receiver).into(), &mut bufs, &mut meta, &mut interfaces)
                .unwrap(),
            1
        );
        let loopback: NonZeroU32 = std::ffi::CString::new("lo")
            .ok()
            .and_then(|name| NonZeroU32::new(unsafe { libc::if_nametoindex(name.as_ptr()) }))
            .unwrap();
        assert_eq!(interfaces[0], Some(loopback));
        assert_eq!(meta[0].len, 1);
        sender
            .send_to(&[43], receiver.local_addr().unwrap())
            .unwrap();
        assert_eq!(
            state
                .recv((&receiver).into(), &mut bufs[..1], &mut meta)
                .unwrap(),
            1
        );
        assert_eq!(meta[0].len, 1);
    }
}
