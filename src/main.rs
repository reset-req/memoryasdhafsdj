mod ntp;
mod snmp;

use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    // ─── Construção ────────────────────────────────
    let ntp_bytes  = ntp::NtpPacket::client_request().to_bytes();
    let snmp_bytes = snmp::build_get_request();

    hex_dump("NTP v4 Client Request", &ntp_bytes);
    hex_dump("SNMP v2c Get-Request (sysDescr)", &snmp_bytes);

    // ─── Exemplo: query dinâmica sem alterar constantes
    // let uptime = snmp::build_pdu(snmp::PDU_GET, &[1,3,6,1,2,1,1,3,0]);
    // hex_dump("SNMP sysUpTime", &uptime);

    // ─── Envio (descomente e ajuste o IP) ──────────
    //
    // let target = "192.168.1.1";
    // send_udp(target, 161, &snmp_bytes).unwrap();
    // recv_ntp(&ntp_bytes, target).unwrap(); // envia + aguarda resposta NTP
}

// ──────────────────────────────────────────────────

fn send_udp(host: &str, port: u16, data: &[u8]) -> std::io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let n = sock.send_to(data, format!("{host}:{port}"))?;
    println!("  ▶ {host}:{port}  ({n} bytes enviados)");
    Ok(())
}

fn recv_ntp(request: &[u8], host: &str) -> std::io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.send_to(request, format!("{host}:123"))?;

    let mut buf = [0u8; 48];
    let (n, from) = sock.recv_from(&mut buf)?;
    println!("\n  ◀ resposta NTP de {from} ({n} bytes)");
    hex_dump("NTP Response", &buf[..n]);

    let f = buf[0];
    let tx_secs = u32::from_be_bytes(buf[40..44].try_into().unwrap());
    // Epoch NTP (1900) → Unix (1970): diferença de 70 anos em segundos
    let unix_ts = tx_secs.saturating_sub(2_208_988_800);
    println!("  LI={} VN={} Mode={} Stratum={}  transmit_ts(unix)={unix_ts}",
        (f >> 6) & 0x3, (f >> 3) & 0x7, f & 0x7, buf[1]);
    Ok(())
}

fn hex_dump(label: &str, data: &[u8]) {
    println!("\n┌─ {label} ({} bytes)", data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let asc: String = chunk.iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();
        println!("│ {:04x}  {:<48} |{asc}|", i * 16, hex);
    }
    println!("└{}", "─".repeat(67));
}
