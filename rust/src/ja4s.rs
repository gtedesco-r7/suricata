/* Copyright (C) 2023-2024 Open Information Security Foundation
*
* You can copy, redistribute or modify this Program under the terms of
* the GNU General Public License version 2 as published by the Free
* Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* version 2 along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
* 02110-1301, USA.

// Author: Sascha Steinbiss <sascha@steinbiss.name>

*/

#[cfg(feature = "ja4")]
use digest::Digest;
use libc::c_uchar;
#[cfg(feature = "ja4")]
use sha2::Sha256;
#[cfg(feature = "ja4")]
use std::cmp::min;
use std::cell::OnceCell;
use std::os::raw::c_char;
use tls_parser::{TlsCipherSuiteID, TlsExtensionType, TlsVersion};
#[cfg(feature = "ja4")]
use crate::jsonbuilder::HEX;

#[derive(Debug, PartialEq)]
pub struct JA4S {
    result: OnceCell<String>,
    tls_version: Option<TlsVersion>,
    ciphersuite: Option<TlsCipherSuiteID>,
    extensions: Vec<TlsExtensionType>,
    alpn: [char; 2],
    quic: bool,
    // Some extensions contribute to the total count component of the
    // fingerprint, yet are not to be included in the SHA256 hash component.
    // Let's track the count separately.
    nof_exts: u16,
}

impl Default for JA4S {
    fn default() -> Self {
        Self::new()
    }
}

// Stubs for when JA4S is disabled
#[cfg(not(feature = "ja4"))]
impl JA4S {
    pub fn new() -> Self {
        Self {
            result: OnceCell::new(),
            tls_version: None,
            ciphersuite: None,
            extensions: Vec::new(),
            alpn: ['0', '0'],
            quic: false,
            nof_exts: 0,
        }
    }
    pub fn set_quic(&mut self) {}
    pub fn set_tls_version(&mut self, _version: TlsVersion) {}
    pub fn set_alpn(&mut self, _alpn: &[u8]) {}
    pub fn set_cipher_suite(&mut self, _cipher: TlsCipherSuiteID) {}
    pub fn add_extension(&mut self, _ext: TlsExtensionType) {}
    pub fn get_hash(&self) -> &str {
        ""
    }
}

#[cfg(feature = "ja4")]
impl JA4S {
    #[inline]
    fn is_grease(val: u16) -> bool {
        match val {
            0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a | 0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a
            | 0x9a9a | 0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa => true,
            _ => false,
        }
    }

    #[inline]
    fn version_to_ja4code(val: Option<TlsVersion>) -> &'static str {
        match val {
            Some(TlsVersion::Tls13) => "13",
            Some(TlsVersion::Tls12) => "12",
            Some(TlsVersion::Tls11) => "11",
            Some(TlsVersion::Tls10) => "10",
            Some(TlsVersion::Ssl30) => "s3",
            // the TLS parser does not support SSL 1.0 and 2.0 hence no
            // support for "s1"/"s2"
            _ => "00",
        }
    }

    pub fn new() -> Self {
        Self {
            result: OnceCell::new(),
            tls_version: None,
            ciphersuite: None,
            extensions: Vec::with_capacity(20),
            alpn: ['0', '0'],
            quic: false,
            nof_exts: 0,
        }
    }

    #[inline(always)]
    fn dirty(&mut self) {
        self.result = OnceCell::new();
    }

    pub fn set_quic(&mut self) {
        self.dirty();
        self.quic = true;
    }

    pub fn set_tls_version(&mut self, version: TlsVersion) {
        if JA4S::is_grease(u16::from(version)) {
            return;
        }
        // Track maximum of seen TLS versions
        match self.tls_version {
            None => {
                self.dirty();
                self.tls_version = Some(version);
            }
            Some(cur_version) => {
                if u16::from(version) > u16::from(cur_version) {
                    self.dirty();
                    self.tls_version = Some(version);
                }
            }
        }
    }

    pub fn set_alpn(&mut self, alpn: &[u8]) {
        if !alpn.is_empty() {
            // If the first ALPN value is only a single character, then that character is treated as both the first and last character.
            if alpn.len() == 2 {
                // GREASE values are 2 bytes, so this could be one -- check
                let v: u16 = (alpn[0] as u16) << 8 | alpn[alpn.len() - 1] as u16;
                if JA4S::is_grease(v) {
                    return;
                }
            }
            if !alpn[0].is_ascii_alphanumeric() || !alpn[alpn.len() - 1].is_ascii_alphanumeric() {
                // If the first or last byte of the first ALPN is non-alphanumeric (meaning not 0x30-0x39, 0x41-0x5A, or 0x61-0x7A), then we print the first and last characters of the hex representation of the first ALPN instead.
                self.dirty();
                self.alpn[0] = char::from(HEX[(alpn[0] >> 4) as usize]);
                self.alpn[1] = char::from(HEX[(alpn[alpn.len() - 1] & 0xF) as usize]);
                return
            }
            self.dirty();
            self.alpn[0] = char::from(alpn[0]);
            self.alpn[1] = char::from(alpn[alpn.len() - 1]);
        }
    }

    pub fn set_cipher_suite(&mut self, cipher: TlsCipherSuiteID) {
        if JA4S::is_grease(u16::from(cipher)) {
            return;
        }
        self.dirty();
        self.ciphersuite = Some(cipher);
    }

    pub fn add_extension(&mut self, ext: TlsExtensionType) {
        if JA4S::is_grease(u16::from(ext)) {
            return;
        }
        self.dirty();
        if ext != TlsExtensionType::ApplicationLayerProtocolNegotiation
            && ext != TlsExtensionType::ServerName
        {
            self.extensions.push(ext);
        }
        self.nof_exts += 1;
    }

    fn calc_hash(&self) -> String {
        // Calculate JA4S_a
        let ja4_a = format!(
            "{proto}{version}{nof_e:02}{al1}{al2}",
            proto = if self.quic { "q" } else { "t" },
            version = JA4S::version_to_ja4code(self.tls_version),
            nof_e = min(99, self.nof_exts),
            al1 = self.alpn[0],
            al2 = self.alpn[1]
        );

        // Calculate JA4S_b
        let ja4_b = self.ciphersuite.map_or(0, u16::from);

        // Calculate JA4S_c
        let mut sorted_exts = self.extensions.to_vec();
        sorted_exts.sort_by(|a, b| u16::from(*a).cmp(&u16::from(*b)));
        let sorted_extstrings: Vec<String> = sorted_exts
            .iter()
            .map(|v| format!("{:04x}", u16::from(*v)))
            .collect();
        let ja4_c_raw = sorted_extstrings.join(",");
        let mut sha = Sha256::new();
        sha.update(&ja4_c_raw);
        let mut ja4_c = format!("{:064x}", sha.finalize());
        ja4_c.truncate(12);

        return format!("{}_{:04x}_{}", ja4_a, ja4_b, ja4_c);
    }

    pub fn get_hash(&self) -> &str {
        self.result.get_or_init(|| self.calc_hash())
    }
}

#[no_mangle]
pub extern "C" fn SCJA4SNew() -> *mut JA4S {
    let j = Box::new(JA4S::new());
    Box::into_raw(j)
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SSetTLSVersion(j: &mut JA4S, version: u16) {
    j.set_tls_version(TlsVersion(version));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SSetCipherSuite(j: &mut JA4S, cipher: u16) {
    j.set_cipher_suite(TlsCipherSuiteID(cipher));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SAddExtension(j: &mut JA4S, ext: u16) {
    j.add_extension(TlsExtensionType(ext));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SSetALPN(j: &mut JA4S, proto: *const c_char, len: u16) {
    let b: &[u8] = std::slice::from_raw_parts(proto as *const c_uchar, len as usize);
    j.set_alpn(b);
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SGetHash(j: &mut JA4S, out: &mut [u8; 25]) {
    let hash = j.get_hash();
    out[0..25].copy_from_slice(hash.as_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SGetCipherSuite(j: &mut JA4S) -> u16 {
    if let Some(cipher) = j.ciphersuite {
        *cipher
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SGetExtensions(j: &mut JA4S, out: *mut usize) -> *const u16 {
    *out = j.extensions.len();
    j.extensions.as_ptr() as *const u16
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SFree(j: &mut JA4S) {
    let ja4: Box<JA4S> = Box::from_raw(j);
    std::mem::drop(ja4);
}

#[cfg(all(test, feature = "ja4"))]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        let mut alpn = "foobar".as_bytes();
        let mut len = alpn.len();
        let v: u16 = (alpn[0] as u16) << 8 | alpn[len - 1] as u16;
        assert!(!JA4S::is_grease(v));

        alpn = &[0x0a, 0x0a];
        len = alpn.len();
        let v: u16 = (alpn[0] as u16) << 8 | alpn[len - 1] as u16;
        assert!(JA4S::is_grease(v));
    }

    #[test]
    fn test_tlsversion_max() {
        let mut j = JA4S::new();
        assert_eq!(j.tls_version, None);
        j.set_tls_version(TlsVersion::Ssl30);
        assert_eq!(j.tls_version, Some(TlsVersion::Ssl30));
        j.set_tls_version(TlsVersion::Tls12);
        assert_eq!(j.tls_version, Some(TlsVersion::Tls12));
        j.set_tls_version(TlsVersion::Tls10);
        assert_eq!(j.tls_version, Some(TlsVersion::Tls12));
    }

    #[test]
    fn test_get_hash_limit_numbers() {
        // Test whether the limitation of the extension and ciphersuite
        // count to 99 is reflected correctly.
        let mut j = JA4S::new();

        for i in 1..200 {
            j.set_cipher_suite(TlsCipherSuiteID(i));
        }
        for i in 1..200 {
            j.add_extension(TlsExtensionType(i));
        }

        let s = &j.get_hash()[..7];
        assert_eq!(s, "t009900");
    }

    #[test]
    fn test_short_alpn() {
        let mut j = JA4S::new();

        j.set_alpn("b".as_bytes());
        let s = &j.get_hash()[..7];
        assert_eq!(s, "t0000bb");

        j.set_alpn("h2".as_bytes());
        let s = &j.get_hash()[..7];
        assert_eq!(s, "t0000h2");

        // from https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md#alpn-extension-value
        j.set_alpn(&[0xab]);
        let s = &j.get_hash()[..7];
        assert_eq!(s, "t0000ab");

        j.set_alpn(&[0xab, 0xcd]);
        let s = &j.get_hash()[..7];
        assert_eq!(s, "t0000ad");

        j.set_alpn(&[0x30, 0xab]);
        let s = &j.get_hash()[..7];
        assert_eq!(s, "t00003b");

        j.set_alpn(&[0x30, 0x31, 0xab, 0xcd]);
        let s = &j.get_hash()[..7];
        assert_eq!(s, "t00003d");

        j.set_alpn(&[0x30, 0xab, 0xcd, 0x31]);
        let s = &j.get_hash()[..7];
        assert_eq!(s, "t000001");
    }

    #[test]
    fn test_get_hash() {
        let mut j = JA4S::new();

        // the empty JA4S hash
        let s = j.get_hash();
        assert_eq!(s, "t000000_0000_e3b0c44298fc");

        // set TLS version
        j.set_tls_version(TlsVersion::Tls12);
        let s = j.get_hash();
        assert_eq!(s, "t120000_0000_e3b0c44298fc");

        // set QUIC
        j.set_quic();
        let s = j.get_hash();
        assert_eq!(s, "q120000_0000_e3b0c44298fc");

        // set GREASE extension, should be ignored
        j.add_extension(TlsExtensionType(0x0a0a));
        let s = j.get_hash();
        assert_eq!(s, "q120000_0000_e3b0c44298fc");

        // set SNI extension, should only increase count and change i->d
        j.add_extension(TlsExtensionType(0x0000));
        let s = j.get_hash();
        assert_eq!(s, "q120100_0000_e3b0c44298fc");

        // set ALPN extension, should only increase count and set end of JA4S_a
        j.set_alpn(b"h3-16");
        j.add_extension(TlsExtensionType::ApplicationLayerProtocolNegotiation);
        let s = j.get_hash();
        assert_eq!(s, "q1202h6_0000_e3b0c44298fc");

        // set some ciphers
        j.set_cipher_suite(TlsCipherSuiteID(0x1111));
        j.set_cipher_suite(TlsCipherSuiteID(0x0a20));
        j.set_cipher_suite(TlsCipherSuiteID(0xbada));
        let s = j.get_hash();
        assert_eq!(s, "q1202h6_bada_e3b0c44298fc");

        // set some extensions and signature algorithms
        j.add_extension(TlsExtensionType(0xface));
        j.add_extension(TlsExtensionType(0x0121));
        j.add_extension(TlsExtensionType(0x1234));
        let s = j.get_hash();
        assert_eq!(s, "q1205h6_bada_f5cd22c92756");
    }
}
