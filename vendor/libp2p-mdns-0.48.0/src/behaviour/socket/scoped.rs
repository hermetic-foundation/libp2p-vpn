//! Kernel ancillary metadata, not sender-supplied addresses, fences receive scope.
use ::tokio::{io::Interest, net::UdpSocket};
use std::{
    io, mem,
    net::SocketAddr,
    num::NonZeroU32,
    os::fd::AsRawFd,
    task::{Context, Poll},
};

const MAX_DISCARDS_PER_POLL: usize = 16;
#[repr(align(16))]
struct Control([u8; 128]);

pub(super) fn poll_read(
    socket: &UdpSocket,
    cx: &mut Context<'_>,
    buffer: &mut [u8],
    interface: NonZeroU32,
) -> Poll<io::Result<(usize, SocketAddr)>> {
    for _ in 0..MAX_DISCARDS_PER_POLL {
        match socket.poll_recv_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => (),
        }
        match socket.try_io(Interest::READABLE, || receive(socket, buffer, interface)) {
            Ok(Some(packet)) => return Poll::Ready(Ok(packet)),
            Ok(None) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
    cx.waker().wake_by_ref();
    Poll::Pending
}

fn receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    interface: NonZeroU32,
) -> io::Result<Option<(usize, SocketAddr)>> {
    // These ABI structs contain only integer fields, arrays and pointers. Every
    // pointer passed to recvmsg refers to initialized, live, bounded storage.
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    let mut vector = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut control = Control([0; 128]);
    message.msg_name = std::ptr::from_mut(&mut address).cast();
    message.msg_namelen = mem::size_of_val(&address)
        .try_into()
        .expect("sockaddr fits socklen_t");
    message.msg_iov = std::ptr::from_mut(&mut vector);
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();
    let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = usize::try_from(received).map_err(|_| malformed())?;
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Ok(None);
    }
    if received > buffer.len() || message.msg_controllen > control.0.len() {
        return Err(malformed());
    }
    if packet_interface(&control.0[..message.msg_controllen])? != interface {
        return Ok(None);
    }
    let minimum = match i32::from(address.ss_family) {
        libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
        _ => return Err(malformed()),
    };
    let length = usize::try_from(message.msg_namelen).map_err(|_| malformed())?;
    if length < minimum || length > mem::size_of_val(&address) {
        return Err(malformed());
    }
    // The family and returned native address length were validated above.
    let remote = unsafe { socket2::SockAddr::new(address, message.msg_namelen) }
        .as_socket()
        .ok_or_else(malformed)?;
    Ok(Some((received, remote)))
}

fn packet_interface(control: &[u8]) -> io::Result<NonZeroU32> {
    let mut offset = 0_usize;
    let mut interface = None;
    let header_size = mem::size_of::<libc::cmsghdr>();
    while control.len().saturating_sub(offset) >= header_size {
        // Ancillary headers and payloads can be unaligned in a borrowed slice.
        let header =
            unsafe { std::ptr::read_unaligned(control[offset..].as_ptr().cast::<libc::cmsghdr>()) };
        let length = header.cmsg_len as usize;
        if length < header_size || length > control.len() - offset {
            return Err(malformed());
        }
        let payload = &control[offset + header_size..offset + length];
        let found = match (header.cmsg_level, header.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                if payload.len() != mem::size_of::<libc::in_pktinfo>() {
                    return Err(malformed());
                }
                let info = unsafe {
                    std::ptr::read_unaligned(payload.as_ptr().cast::<libc::in_pktinfo>())
                };
                Some(u32::try_from(info.ipi_ifindex).map_err(|_| malformed())?)
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                if payload.len() != mem::size_of::<libc::in6_pktinfo>() {
                    return Err(malformed());
                }
                let info = unsafe {
                    std::ptr::read_unaligned(payload.as_ptr().cast::<libc::in6_pktinfo>())
                };
                Some(u32::try_from(info.ipi6_ifindex).map_err(|_| malformed())?)
            }
            _ => None,
        };
        if let Some(found) = found {
            if interface.is_some() {
                return Err(malformed());
            }
            interface = NonZeroU32::new(found);
            if interface.is_none() {
                return Err(malformed());
            }
        }
        let aligned = length
            .checked_add(mem::size_of::<usize>() - 1)
            .ok_or_else(malformed)?
            & !(mem::size_of::<usize>() - 1);
        offset = offset.checked_add(aligned).ok_or_else(malformed)?;
    }
    interface.ok_or_else(malformed)
}

fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid mDNS receive-interface metadata",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(index: u32) -> Vec<u8> {
        let size = mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::in6_pktinfo>();
        let mut control = vec![0; size];
        let header = libc::cmsghdr {
            cmsg_len: size as _,
            cmsg_level: libc::IPPROTO_IPV6,
            cmsg_type: libc::IPV6_PKTINFO,
        };
        let payload = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
            ipi6_ifindex: index.try_into().expect("test interface fits native index"),
        };
        // Both writes fit their checked, disjoint native-structure slots.
        unsafe {
            std::ptr::write_unaligned(control.as_mut_ptr().cast::<libc::cmsghdr>(), header);
            std::ptr::write_unaligned(
                control[mem::size_of::<libc::cmsghdr>()..]
                    .as_mut_ptr()
                    .cast::<libc::in6_pktinfo>(),
                payload,
            );
        }
        control
    }

    #[test]
    fn native_metadata_requires_one_complete_nonzero_interface() {
        assert_eq!(packet_interface(&control(7)).unwrap().get(), 7);
        assert!(packet_interface(&control(0)).is_err());
        assert!(packet_interface(&[]).is_err());
        let correct = control(7);
        for length in 0..correct.len() {
            assert!(packet_interface(&correct[..length]).is_err());
        }
        let mut duplicated = correct.clone();
        let align = mem::size_of::<usize>();
        duplicated.resize((duplicated.len() + align - 1) & !(align - 1), 0);
        duplicated.extend(control(8));
        assert!(packet_interface(&duplicated).is_err());
    }
}
