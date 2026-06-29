// ╔══════════════════════════════════════════════════╗
// ║  SNMP v2c Get-Request — RFC 3416 / BER (X.690)  ║
// ║  UDP porta 161  |  tamanho variável              ║
// ╚══════════════════════════════════════════════════╝

#![allow(dead_code)]

// ──────────────────────────────────────────────────
// HEADER  (BER type tags)
// ──────────────────────────────────────────────────

const INTEGER: u8      = 0x02;
const OCTET_STRING: u8 = 0x04;
const NULL: u8         = 0x05;
const OBJECT_ID: u8    = 0x06;
const SEQUENCE: u8     = 0x30; // universal constructed

// PDU types (context-specific, constructed)
pub const PDU_GET:      u8 = 0xA0;
pub const PDU_GET_NEXT: u8 = 0xA1;
pub const PDU_RESPONSE: u8 = 0xA2;
pub const PDU_SET:      u8 = 0xA3;

// ──────────────────────────────────────────────────
// CAMPOS SNMP
// ──────────────────────────────────────────────────

/// Versão — 0=v1, 1=v2c
pub const SNMP_VERSION: i64 = 1;
/// Community string
pub const COMMUNITY: &str = "public";
/// Request ID (livre escolha; usado para correlacionar resposta)
pub const REQUEST_ID: i64 = 1;
/// Error status (sempre 0 em requests)
pub const ERROR_STATUS: i64 = 0;
/// Error index  (sempre 0 em requests)
pub const ERROR_INDEX: i64 = 0;

// ──────────────────────────────────────────────────
// OID ALVO
// ──────────────────────────────────────────────────

/// OID a consultar — troque o slice para mudar o objeto
///   sysDescr    1.3.6.1.2.1.1.1.0
///   sysUpTime   1.3.6.1.2.1.1.3.0
///   sysContact  1.3.6.1.2.1.1.4.0
///   sysName     1.3.6.1.2.1.1.5.0
///   sysLocation 1.3.6.1.2.1.1.6.0
pub const TARGET_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0]; // sysDescr.0

// ──────────────────────────────────────────────────
// BUILDERS PÚBLICOS
// ──────────────────────────────────────────────────

/// Get-Request com o TARGET_OID e constantes acima
pub fn build_get_request() -> Vec<u8> {
    build_pdu(PDU_GET, TARGET_OID)
}

/// PDU genérico — útil para queries dinâmicas sem alterar as constantes
pub fn build_pdu(pdu_type: u8, oid: &[u32]) -> Vec<u8> {
    // VarBind = SEQUENCE { OID, NULL }
    let varbind = {
        let mut inner = encode_oid(oid);
        inner.extend(encode_null());
        encode_tlv(SEQUENCE, &inner)
    };

    // VarBindList = SEQUENCE { varbind }
    let varbindlist = encode_tlv(SEQUENCE, &varbind);

    // PDU = [type] { request-id, error-status, error-index, varbindlist }
    let pdu = {
        let mut inner = encode_integer(REQUEST_ID);
        inner.extend(encode_integer(ERROR_STATUS));
        inner.extend(encode_integer(ERROR_INDEX));
        inner.extend(varbindlist);
        encode_tlv(pdu_type, &inner)
    };

    // Mensagem SNMP = SEQUENCE { version, community, pdu }
    let mut msg = encode_integer(SNMP_VERSION);
    msg.extend(encode_octet_string(COMMUNITY));
    msg.extend(pdu);
    encode_tlv(SEQUENCE, &msg)
}

// ──────────────────────────────────────────────────
// BER ENCODING HELPERS
// ──────────────────────────────────────────────────

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// BER definite-length (short form < 0x80, long form até 2 bytes)
fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// BER INTEGER: two's complement, mínimo de bytes, preserva sinal
fn encode_integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0usize;
    while start < 7 {
        let cur  = bytes[start];
        let next = bytes[start + 1];
        let redundant = (cur == 0x00 && next & 0x80 == 0)  // zero à esquerda positivo
                     || (cur == 0xFF && next & 0x80 != 0);  // extensão de sinal negativo
        if redundant { start += 1; } else { break; }
    }
    encode_tlv(INTEGER, &bytes[start..])
}

fn encode_octet_string(s: &str) -> Vec<u8> {
    encode_tlv(OCTET_STRING, s.as_bytes())
}

fn encode_null() -> Vec<u8> {
    vec![NULL, 0x00]
}

/// BER OID: primeiros dois componentes → X*40+Y; demais em base-128
fn encode_oid(components: &[u32]) -> Vec<u8> {
    assert!(components.len() >= 2, "OID precisa de pelo menos 2 componentes");
    let mut bytes = Vec::new();
    bytes.push((components[0] * 40 + components[1]) as u8);
    for &c in &components[2..] {
        oid_base128(c, &mut bytes);
    }
    encode_tlv(OBJECT_ID, &bytes)
}

fn oid_base128(mut v: u32, out: &mut Vec<u8>) {
    if v == 0 { out.push(0x00); return; }
    let mut stack = Vec::new();
    while v > 0 { stack.push((v & 0x7F) as u8); v >>= 7; }
    stack.reverse();
    let last = stack.len() - 1;
    for (i, &b) in stack.iter().enumerate() {
        out.push(if i == last { b } else { b | 0x80 });
    }
}
