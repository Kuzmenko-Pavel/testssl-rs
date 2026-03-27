//! TLS data constants used for socket-based handshakes
//! Based on testssl.sh etc/tls_data.txt

/// TLS data constants
pub struct TlsData {
    pub tls13_ciphers: &'static str,
    pub tls12_ciphers: &'static str,
    pub tls_ciphers: &'static str,
}

pub static TLS_DATA: TlsData = TlsData {
    // 7 ciphers defined for TLS 1.3 in RFCs 8446 and 9150
    tls13_ciphers: "13,01, 13,02, 13,03, 13,04, 13,05",

    // 113 standard cipher for TLS 1.2 and SPDY/NPN HTTP2/ALPN
    tls12_ciphers: "c0,30, c0,2c, c0,28, c0,24, c0,14, c0,0a, 00,9f, 00,6b, \
00,39, 00,9d, 00,3d, 00,35, c0,2f, c0,2b, c0,27, c0,23, \
c0,13, c0,09, 00,9e, 00,67, 00,33, 00,9c, 00,3c, 00,2f, \
cc,a9, cc,a8, cc,aa, c0,32, c0,2e, c0,2a, c0,26, c0,0f, c0,05",

    // 76 standard cipher for SSLv3, TLS 1, TLS 1.1
    tls_ciphers: "c0,14, c0,0a, 00,39, 00,38, 00,35, c0,13, c0,09, 00,33, 00,32, \
00,2f, 00,16, 00,13, 00,0a, 00,05, 00,04",
};

/// Named groups (supported_groups extension values)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedGroup {
    pub id: u16,
    pub name: &'static str,
    pub bits: u16,
    pub deprecated: bool,
}

pub static NAMED_GROUPS: &[NamedGroup] = &[
    NamedGroup {
        id: 0x0001,
        name: "sect163k1",
        bits: 163,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0002,
        name: "sect163r1",
        bits: 162,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0003,
        name: "sect163r2",
        bits: 163,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0004,
        name: "sect193r1",
        bits: 193,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0005,
        name: "sect193r2",
        bits: 193,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0006,
        name: "sect233k1",
        bits: 232,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0007,
        name: "sect233r1",
        bits: 233,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0008,
        name: "sect239k1",
        bits: 238,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0009,
        name: "sect283k1",
        bits: 281,
        deprecated: true,
    },
    NamedGroup {
        id: 0x000a,
        name: "sect283r1",
        bits: 282,
        deprecated: true,
    },
    NamedGroup {
        id: 0x000b,
        name: "sect409k1",
        bits: 407,
        deprecated: true,
    },
    NamedGroup {
        id: 0x000c,
        name: "sect409r1",
        bits: 409,
        deprecated: true,
    },
    NamedGroup {
        id: 0x000d,
        name: "sect571k1",
        bits: 570,
        deprecated: true,
    },
    NamedGroup {
        id: 0x000e,
        name: "sect571r1",
        bits: 570,
        deprecated: true,
    },
    NamedGroup {
        id: 0x000f,
        name: "secp160k1",
        bits: 161,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0010,
        name: "secp160r1",
        bits: 161,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0011,
        name: "secp160r2",
        bits: 161,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0012,
        name: "secp192k1",
        bits: 192,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0013,
        name: "prime192v1 (P-192)",
        bits: 192,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0014,
        name: "secp224k1",
        bits: 225,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0015,
        name: "secp224r1 (P-224)",
        bits: 224,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0016,
        name: "secp256k1",
        bits: 256,
        deprecated: true,
    },
    NamedGroup {
        id: 0x0017,
        name: "prime256v1 (P-256)",
        bits: 256,
        deprecated: false,
    },
    NamedGroup {
        id: 0x0018,
        name: "secp384r1 (P-384)",
        bits: 384,
        deprecated: false,
    },
    NamedGroup {
        id: 0x0019,
        name: "secp521r1 (P-521)",
        bits: 521,
        deprecated: false,
    },
    NamedGroup {
        id: 0x001a,
        name: "brainpoolP256r1",
        bits: 256,
        deprecated: true,
    },
    NamedGroup {
        id: 0x001b,
        name: "brainpoolP384r1",
        bits: 384,
        deprecated: true,
    },
    NamedGroup {
        id: 0x001c,
        name: "brainpoolP512r1",
        bits: 512,
        deprecated: true,
    },
    NamedGroup {
        id: 0x001d,
        name: "X25519",
        bits: 253,
        deprecated: false,
    },
    NamedGroup {
        id: 0x001e,
        name: "X448",
        bits: 448,
        deprecated: false,
    },
    // FFDHE groups
    NamedGroup {
        id: 0x0100,
        name: "ffdhe2048",
        bits: 2048,
        deprecated: false,
    },
    NamedGroup {
        id: 0x0101,
        name: "ffdhe3072",
        bits: 3072,
        deprecated: false,
    },
    NamedGroup {
        id: 0x0102,
        name: "ffdhe4096",
        bits: 4096,
        deprecated: false,
    },
    NamedGroup {
        id: 0x0103,
        name: "ffdhe6144",
        bits: 6144,
        deprecated: false,
    },
    NamedGroup {
        id: 0x0104,
        name: "ffdhe8192",
        bits: 8192,
        deprecated: false,
    },
];

/// Find a named group by ID
pub fn find_group(id: u16) -> Option<&'static NamedGroup> {
    NAMED_GROUPS.iter().find(|g| g.id == id)
}

/// Signature algorithm information
#[derive(Debug, Clone)]
pub struct SigAlg {
    pub code: u16,
    pub name: &'static str,
}

pub static SIG_ALGS: &[SigAlg] = &[
    SigAlg {
        code: 0x0101,
        name: "RSA+MD5",
    },
    SigAlg {
        code: 0x0102,
        name: "DSA+MD5",
    },
    SigAlg {
        code: 0x0103,
        name: "ECDSA+MD5",
    },
    SigAlg {
        code: 0x0201,
        name: "RSA+SHA1",
    },
    SigAlg {
        code: 0x0202,
        name: "DSA+SHA1",
    },
    SigAlg {
        code: 0x0203,
        name: "ECDSA+SHA1",
    },
    SigAlg {
        code: 0x0401,
        name: "RSA+SHA256",
    },
    SigAlg {
        code: 0x0402,
        name: "DSA+SHA256",
    },
    SigAlg {
        code: 0x0403,
        name: "ECDSA+SHA256",
    },
    SigAlg {
        code: 0x0501,
        name: "RSA+SHA384",
    },
    SigAlg {
        code: 0x0502,
        name: "DSA+SHA384",
    },
    SigAlg {
        code: 0x0503,
        name: "ECDSA+SHA384",
    },
    SigAlg {
        code: 0x0601,
        name: "RSA+SHA512",
    },
    SigAlg {
        code: 0x0602,
        name: "DSA+SHA512",
    },
    SigAlg {
        code: 0x0603,
        name: "ECDSA+SHA512",
    },
    SigAlg {
        code: 0x0804,
        name: "RSA-PSS-RSAE+SHA256",
    },
    SigAlg {
        code: 0x0805,
        name: "RSA-PSS-RSAE+SHA384",
    },
    SigAlg {
        code: 0x0806,
        name: "RSA-PSS-RSAE+SHA512",
    },
    SigAlg {
        code: 0x0807,
        name: "Ed25519",
    },
    SigAlg {
        code: 0x0808,
        name: "Ed448",
    },
    SigAlg {
        code: 0x0809,
        name: "RSA-PSS-PSS+SHA256",
    },
    SigAlg {
        code: 0x080a,
        name: "RSA-PSS-PSS+SHA384",
    },
    SigAlg {
        code: 0x080b,
        name: "RSA-PSS-PSS+SHA512",
    },
];
