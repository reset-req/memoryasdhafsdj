// ╔══════════════════════════════════════════════════╗
// ║        NTP v4 Client Request — RFC 5905          ║
// ║        UDP porta 123  |  48 bytes fixos          ║
// ╚══════════════════════════════════════════════════╝

// ──────────────────────────────────────────────────
// HEADER  (byte 0 = LI[2b] | VN[3b] | Mode[3b])
// ──────────────────────────────────────────────────

/// Leap Indicator — 0=sem aviso, 1=+1s, 2=-1s, 3=relógio inválido
pub const LI: u8 = 0;
/// Versão NTP
pub const VN: u8 = 4;
/// Mode — 1=sym_active 2=sym_passive 3=client 4=server 5=broadcast
pub const MODE: u8 = 3; // client

// ──────────────────────────────────────────────────
// CAMPOS NTP
// ──────────────────────────────────────────────────

/// Stratum — 0=unspecified, 1=primary, 2-15=secondary
pub const STRATUM: u8 = 0;
/// Poll — expoente base-2 do intervalo de polling (2^6 = 64 s)
pub const POLL: u8 = 6;
/// Precision — precisão do relógio local (i8 como u8; -20 = 0xEC)
pub const PRECISION: u8 = 0xEC;
/// Root Delay — RTT ao servidor primário (NTP short format, big-endian)
pub const ROOT_DELAY: u32 = 0;
/// Root Dispersion — dispersão máxima ao servidor primário
pub const ROOT_DISPERSION: u32 = 0;
/// Reference ID — 4 bytes: ASCII p/ stratum 1, IP p/ stratum ≥ 2
pub const REFERENCE_ID: u32 = 0;

// ──────────────────────────────────────────────────
// STRUCT + BUILDER
// ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct NtpPacket {
    pub flags: u8, // LI | VN | Mode
    pub stratum: u8,
    pub poll: u8,
    pub precision: u8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    // Epoch NTP = 01 Jan 1900; formato: 32b segundos + 32b frações
    pub reference_ts: u64,
    pub originate_ts: u64,
    pub receive_ts: u64,
    pub transmit_ts: u64,
}

impl NtpPacket {
    pub fn client_request() -> Self {
        Self {
            flags: (LI << 6) | (VN << 3) | MODE,
            stratum: STRATUM,
            poll: POLL,
            precision: PRECISION,
            root_delay: ROOT_DELAY,
            root_dispersion: ROOT_DISPERSION,
            reference_id: REFERENCE_ID,
            reference_ts: 0,
            originate_ts: 0,
            receive_ts: 0,
            transmit_ts: 0,
        }
    }

    /// Serializa para 48 bytes big-endian
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0] = self.flags;
        b[1] = self.stratum;
        b[2] = self.poll;
        b[3] = self.precision;
        b[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        b[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        b[12..16].copy_from_slice(&self.reference_id.to_be_bytes());
        b[16..24].copy_from_slice(&self.reference_ts.to_be_bytes());
        b[24..32].copy_from_slice(&self.originate_ts.to_be_bytes());
        b[32..40].copy_from_slice(&self.receive_ts.to_be_bytes());
        b[40..48].copy_from_slice(&self.transmit_ts.to_be_bytes());
        b
    }
}
