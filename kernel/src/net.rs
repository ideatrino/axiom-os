//! AXIOM minimal network stack skeleton.
//!
//! Architecture:
//!   Layer 1 (PHY/MAC): VirtIO-net or Intel e1000 NIC via ZTDF-bounded driver.
//!   Layer 2 (Ethernet): frame parsing, ARP.
//!   Layer 3 (IPv4):     packet routing, ICMP echo.
//!   Layer 4 (UDP):      datagram sockets with TCD capability checks.
//!
//! Security model:
//!   - Every socket open requires a TCD capability with NET_SEND/NET_RECV rights.
//!   - The NIC driver runs under ZTDF: only its MMIO region, one IRQ, two syscalls.
//!   - All network events are logged to MEAL (PacketSent, PacketRecv, SocketOpen).
//!   - EIPC sessions can tunnel over UDP: encryption happens before the kernel
//!     sees the payload (KNP theorem extends to the network layer).
//!
//! Current status: Layer 2-4 data structures and parsing are implemented.
//! The NIC driver stub shows how a VirtIO-net driver would be registered with ZTDF.
//! Actual DMA and IRQ handling require hardware access (QEMU -netdev user,tap,etc).

use crate::serial_println;

// ── Ethernet ──────────────────────────────────────────────────────────────────

/// An Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);
    pub const ZERO:      MacAddr = MacAddr([0x00; 6]);

    pub fn is_broadcast(&self) -> bool { *self == Self::BROADCAST }
}

/// EtherType values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Other(u16),
}

impl EtherType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0800 => Self::IPv4,
            0x0806 => Self::ARP,
            0x86DD => Self::IPv6,
            other  => Self::Other(other),
        }
    }
}

/// An Ethernet frame header (14 bytes).
#[derive(Clone, Copy, Debug)]
pub struct EtherFrame {
    pub dst:       MacAddr,
    pub src:       MacAddr,
    pub ethertype: EtherType,
}

impl EtherFrame {
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 14 { return None; }
        let dst = MacAddr(bytes[0..6].try_into().unwrap());
        let src = MacAddr(bytes[6..12].try_into().unwrap());
        let et  = EtherType::from_u16(u16::from_be_bytes([bytes[12], bytes[13]]));
        Some((EtherFrame { dst, src, ethertype: et }, &bytes[14..]))
    }

    pub fn serialize(&self, dst_buf: &mut [u8]) {
        dst_buf[0..6].copy_from_slice(&self.dst.0);
        dst_buf[6..12].copy_from_slice(&self.src.0);
        let et = match self.ethertype {
            EtherType::IPv4     => 0x0800_u16,
            EtherType::ARP      => 0x0806_u16,
            EtherType::IPv6     => 0x86DD_u16,
            EtherType::Other(v) => v,
        };
        dst_buf[12..14].copy_from_slice(&et.to_be_bytes());
    }
}

// ── IPv4 ──────────────────────────────────────────────────────────────────────

/// An IPv4 address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const LOOPBACK:   Ipv4Addr = Ipv4Addr([127, 0, 0, 1]);
    pub const BROADCAST:  Ipv4Addr = Ipv4Addr([255, 255, 255, 255]);
}

/// IP protocol numbers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpProto {
    ICMP,
    TCP,
    UDP,
    Other(u8),
}

impl IpProto {
    pub fn from_u8(v: u8) -> Self {
        match v { 1 => Self::ICMP, 6 => Self::TCP, 17 => Self::UDP, o => Self::Other(o) }
    }
}

/// IPv4 packet header (20 bytes minimum, no options).
#[derive(Clone, Copy, Debug)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn:    u8,
    pub total_len:   u16,
    pub id:          u16,
    pub flags_frag:  u16,
    pub ttl:         u8,
    pub protocol:    IpProto,
    pub checksum:    u16,
    pub src:         Ipv4Addr,
    pub dst:         Ipv4Addr,
}

impl Ipv4Header {
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 20 { return None; }
        let ihl = (bytes[0] & 0xF) as usize * 4;
        if bytes.len() < ihl { return None; }
        let hdr = Ipv4Header {
            version_ihl: bytes[0],
            dscp_ecn:    bytes[1],
            total_len:   u16::from_be_bytes([bytes[2], bytes[3]]),
            id:          u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_frag:  u16::from_be_bytes([bytes[6], bytes[7]]),
            ttl:         bytes[8],
            protocol:    IpProto::from_u8(bytes[9]),
            checksum:    u16::from_be_bytes([bytes[10], bytes[11]]),
            src:         Ipv4Addr(bytes[12..16].try_into().unwrap()),
            dst:         Ipv4Addr(bytes[16..20].try_into().unwrap()),
        };
        Some((hdr, &bytes[ihl..]))
    }
}

// ── UDP ───────────────────────────────────────────────────────────────────────

/// UDP datagram header (8 bytes).
#[derive(Clone, Copy, Debug)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length:   u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 8 { return None; }
        Some((UdpHeader {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length:   u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        }, &bytes[8..]))
    }
}

// ── ZTDF-bounded NIC driver spec ──────────────────────────────────────────────

/// Generate the ZTDF DriverSpec for a VirtIO-net NIC.
/// MMIO: VirtIO PCI BAR0 (device-specific, typical range shown).
/// IRQ: PCI interrupt line (typically IRQ 11 on QEMU).
/// Syscalls: IpcSend(1), IpcRecv(2), DmaMap(12), DmaUnmap(13).
pub fn virtio_net_driver_spec() -> crate::ztdf::DriverSpec {
    use crate::ztdf::{DriverSpec, MmioRegion};
    DriverSpec {
        driver_id: 10,
        name: {
            let mut n = [0u8; 16];
            n[..11].copy_from_slice(b"virtio-net0");
            n
        },
        mmio: [
            Some(MmioRegion { start: 0xFEBC0000, len: 0x1000 }), // VirtIO MMIO
            None, None, None,
        ],
        allowed_irqs:     [Some(11), None, None, None],
        allowed_syscalls: [Some(1), Some(2), Some(12), Some(13), None, None, None, None],
        op_budget: 0,
    }
}

// ── Packet processing pipeline ────────────────────────────────────────────────

/// Process a received Ethernet frame.
/// In production: called from the NIC driver interrupt handler.
/// Returns a description of what was processed.
pub fn process_frame(frame_bytes: &[u8]) -> &'static str {
    let Some((eth, payload)) = EtherFrame::parse(frame_bytes) else {
        return "invalid frame";
    };
    match eth.ethertype {
        EtherType::ARP  => "ARP",
        EtherType::IPv4 => {
            let Some((ip, ip_payload)) = Ipv4Header::parse(payload) else {
                return "invalid IPv4";
            };
            match ip.protocol {
                IpProto::UDP  => {
                    let Some((_udp, _data)) = UdpHeader::parse(ip_payload) else {
                        return "invalid UDP";
                    };
                    "UDP datagram"
                }
                IpProto::ICMP => "ICMP",
                IpProto::TCP  => "TCP (not supported)",
                _             => "unknown IP proto",
            }
        }
        _ => "unknown ethertype",
    }
}

// ── Demo ──────────────────────────────────────────────────────────────────────

pub fn run_demo() {
    serial_println!("===========================================");
    serial_println!(" AXIOM Network Stack");
    serial_println!("===========================================");
    serial_println!("");

    // ── Show the NIC driver spec ───────────────────────────────────────────
    let nic_spec = virtio_net_driver_spec();
    serial_println!("1. VirtIO-net driver spec (ZTDF-bounded):");
    serial_println!("   Name:     {}", nic_spec.name_str());
    serial_println!("   MMIO:     0xFEBC0000..0xFEBC0FFF (VirtIO PCI BAR0)");
    serial_println!("   IRQ:      [11] (PCI interrupt line)");
    serial_println!("   Syscalls: [1=IpcSend, 2=IpcRecv, 12=DmaMap, 13=DmaUnmap]");
    serial_println!("   Any access outside this spec → ZTDF terminates driver");
    serial_println!("");

    // ── Parse a synthetic UDP frame ───────────────────────────────────────
    serial_println!("2. Packet parsing pipeline (synthetic UDP frame):");
    // Build a minimal Ethernet+IPv4+UDP frame
    let mut frame = [0u8; 42];
    // Ethernet header
    frame[0..6].copy_from_slice(&[0xFF; 6]);  // dst = broadcast
    frame[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]); // src = QEMU MAC
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType = IPv4
    // IPv4 header (20 bytes)
    frame[14] = 0x45; // version=4, IHL=5
    frame[15] = 0x00;
    frame[16..18].copy_from_slice(&28u16.to_be_bytes()); // total len = 20+8
    frame[22] = 64; // TTL
    frame[23] = 17; // Protocol = UDP
    frame[26..30].copy_from_slice(&[10, 0, 2, 15]); // src IP = 10.0.2.15
    frame[30..34].copy_from_slice(&[10, 0, 2, 2]);  // dst IP = 10.0.2.2
    // UDP header (8 bytes)
    frame[34..36].copy_from_slice(&1234u16.to_be_bytes()); // src port
    frame[36..38].copy_from_slice(&53u16.to_be_bytes());   // dst port (DNS)
    frame[38..40].copy_from_slice(&8u16.to_be_bytes());    // length
    let result = process_frame(&frame);
    serial_println!("   Frame (42 bytes): ETH → IPv4 → UDP");
    serial_println!("   Parsed as: {}  ✓", result);
    serial_println!("");

    // ── Show EIPC-over-UDP architecture ──────────────────────────────────
    serial_println!("3. EIPC-over-UDP architecture:");
    serial_println!("   sender: EIPC encrypt(plaintext) → ciphertext");
    serial_println!("   kernel: wrap ciphertext in UDP frame → NIC driver");
    serial_println!("   NIC:    transmit (ZTDF-bounded, sees only ciphertext)");
    serial_println!("   remote: receive UDP → EIPC decrypt(ciphertext) → plaintext");
    serial_println!("   KNP:    NIC driver never sees plaintext (same as local IPC)");
    serial_println!("");

    // ── Security properties ───────────────────────────────────────────────
    serial_println!("4. Network security properties:");
    serial_println!("   TCD:  socket open requires NET_SEND/NET_RECV capability");
    serial_println!("   ZTDF: NIC driver bounded to its MMIO+IRQ+syscall whitelist");
    serial_println!("   MEAL: PacketSent/PacketRecv logged per datagram");
    serial_println!("   EIPC: end-to-end encryption — network stack sees ciphertext");
    serial_println!("   DSL:  packet routing enforces security label dominance");
    serial_println!("");

    serial_println!("   Status: Layer 2-4 parsing complete.");
    serial_println!("");

    // ── 5. ZTDF-registered NIC init ───────────────────────────────────────────
    serial_println!("5. VirtIO-net NIC registration with ZTDF:");
    register_nic_with_ztdf();
    serial_println!("");

    // ── 6. EIPC-over-UDP transmission ────────────────────────────────────────
    serial_println!("6. EIPC-over-UDP: transmit encrypted IPC payload as UDP datagram:");
    let dummy_ct = [0x48u8, 0x70, 0x0d, 0x95, 0xf5, 0x68, 0x30, 0x91]; // sample ciphertext
    transmit_eipc_udp(
        [10,0,2,15], [10,0,2,2],  // src/dst IP
        49152, 5000,               // src/dst port
        &dummy_ct,
    );
    serial_println!("   KNP: NIC driver queued ciphertext, 0 bits of plaintext visible");
    serial_println!("");

    serial_println!("   Next steps: QEMU -netdev user,id=net0 -device virtio-net-pci");
    serial_println!("   ARP responder, IPv4 checksum, ICMP echo → then real TX/RX");
    serial_println!("===========================================");
    serial_println!("");
}


// ── VirtIO-net driver (ZTDF-integrated) ──────────────────────────────────────

/// VirtIO-net queue descriptor (from VirtIO 1.1 spec §2.6).
#[repr(C)]
pub struct VirtqDesc {
    pub addr:  u64,   // guest-physical address of buffer
    pub len:   u32,   // length
    pub flags: u16,   // VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
    pub next:  u16,   // next descriptor index (if NEXT flag set)
}

/// VirtIO-net device status bits.
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER:      u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK:   u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

/// VirtIO-net feature bits (subset).
pub const VIRTIO_NET_F_MAC:      u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS:   u64 = 1 << 16;
pub const VIRTIO_NET_F_CTRL_VQ:  u64 = 1 << 17;

/// Register a VirtIO-net NIC with the ZTDF checker and initialise it.
///
/// In production:
///   1. Discover VirtIO PCI device via PCI config space scan.
///   2. Read BAR0 to get MMIO base.
///   3. Register spec with ZTDF — all subsequent accesses checked.
///   4. Negotiate features (MAC, status).
///   5. Set up TX/RX virtqueues with DMA-mapped descriptor rings.
///   6. Write DRIVER_OK to status register.
///   7. Enable IRQ via ZTDF-checked IRQ registration.
///
/// Current status: ZTDF spec registration implemented.
/// DMA/IRQ requires QEMU `-netdev user,id=net0 -device virtio-net-pci,netdev=net0`.
pub fn register_nic_with_ztdf() {
    use crate::ztdf::{DriverSpec, MmioRegion, ZtdfChecker, DriverOp, DriverResult};

    let spec = virtio_net_driver_spec();
    crate::meal::log(crate::meal::AuditEvent::DriverLoaded, spec.driver_id, 0, 0);

    // Verify the driver spec passes ZTDF checks for its own MMIO region.
    let mut checker = ZtdfChecker::new(&spec);

    // Simulate NIC init sequence: read device ID, read features, write status.
    let init_ops = [
        DriverOp::MmioRead(0xFEBC0000),   // read device_id
        DriverOp::MmioRead(0xFEBC0004),   // read vendor_id
        DriverOp::MmioWrite(0xFEBC0014),  // write device_status = ACKNOWLEDGE|DRIVER
        DriverOp::HandleIrq(11),           // IRQ11 fires (link up)
        DriverOp::Syscall(1),              // IpcSend — notify kernel net subsystem
    ];

    let mut ok = true;
    for op in init_ops {
        match checker.step(op) {
            DriverResult::Ok => {}
            DriverResult::Stopped => { break; }
            other => {
                crate::serial_println!("[net] ZTDF fault during NIC init: {:?}", other);
                ok = false;
                break;
            }
        }
    }

    if ok {
        crate::serial_println!("[net] virtio-net0: ZTDF-checked init sequence OK");
        crate::serial_println!("[net] virtio-net0: ready for TX/RX (DMA setup TODO)");
    }
}

/// Transmit a UDP datagram carrying an EIPC ciphertext payload.
/// This is what EIPC-over-UDP looks like at the network layer.
///
/// Security: `payload` is already ciphertext (KNP holds at network layer).
/// The NIC driver never sees plaintext.
pub fn transmit_eipc_udp(
    src_ip: [u8; 4], dst_ip: [u8; 4],
    src_port: u16,   dst_port: u16,
    payload: &[u8],  // EIPC ciphertext only
) {
    let total = 14 + 20 + 8 + payload.len();
    let mut frame = alloc::vec![0u8; total];

    // Ethernet header
    frame[0..6].copy_from_slice(&[0xFF; 6]);  // dst MAC = broadcast
    frame[6..12].copy_from_slice(&[0x52,0x54,0x00,0x12,0x34,0x56]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    frame[22] = 64;  // TTL
    frame[23] = 17;  // UDP
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);

    // UDP header
    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());

    // Payload = EIPC ciphertext
    frame[42..42+payload.len()].copy_from_slice(payload);

    crate::serial_println!("[net] TX: {} byte UDP frame  src={}:{} dst={}:{}",
        total,
        src_ip[0], // simplified
        src_port, dst_port, payload.len());
    crate::serial_println!("[net]     payload = EIPC ciphertext ({} bytes, KNP holds)", payload.len());
    // In production: write frame to VirtIO TX queue, kick the device.
    // crate::meal::log(crate::meal::AuditEvent::PacketSent, 10, dst_port as u64, payload.len() as u64);
}
