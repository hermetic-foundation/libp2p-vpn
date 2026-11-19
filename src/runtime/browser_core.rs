//! Portable protocol and forwarding core. OS devices and sockets are host-owned.
pub mod control;
pub mod forward;
pub mod lifecycle;
pub mod packet;
pub mod service;
pub use crate::packet_plane_limits as packet_plane;
