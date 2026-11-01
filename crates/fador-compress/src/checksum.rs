//! CRC-32 and Adler-32 checksums used by the gzip and zlib wrappers.

/// The reflected CRC-32 polynomial used by gzip (IEEE 802.3).
const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0u8;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ CRC32_POLYNOMIAL
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = crc32_table();

/// Compute the gzip CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xff) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

/// Compute the zlib Adler-32 of `data`.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"hello"), 0x3610_a686);
    }

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(b""), 0x0000_0001);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }
}
