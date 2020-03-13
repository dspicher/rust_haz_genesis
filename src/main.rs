#![allow(non_camel_case_types)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub fn rust_neoscrypt(message: Vec<u8>, options: u32) -> bitcoin::util::uint::Uint256 {
    let mut buf = [0; 32];
    unsafe {
        neoscrypt(message.as_ptr(), buf.as_mut_ptr(), options);
    }
    bitcoin::consensus::encode::deserialize(&buf).unwrap()
}

fn mine(mut header: bitcoin::BlockHeader, initial_nonce: Option<u32>) -> Option<u32> {
    let lower = match initial_nonce {
        None => 0,
        Some(i) => i,
    };
    for nonce in lower..u32::max_value() {
        println!("{:?}", nonce);
        header.nonce = nonce;
        if check_hash(header) {
            return Some(nonce);
        }
    }
    None
}

fn check_hash(header: bitcoin::BlockHeader) -> bool {
    let neo_scrypt_options: u32 = 0x1000;
    rust_neoscrypt(
        bitcoin::consensus::encode::serialize(&header),
        neo_scrypt_options,
    ) < header.target()
}

fn main() {}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    fn into<T: bitcoin::consensus::encode::Decodable>(hex_string: &str) -> T {
        let mut bytes = Vec::from_hex(hex_string).unwrap();
        bytes.reverse();
        bitcoin::consensus::encode::deserialize(&bytes).unwrap()
    }

    #[test]
    fn test_real_blocks() {
        // 277930
        assert!(check_hash(bitcoin::BlockHeader {
            version: 536870912,
            prev_blockhash: into(
                "508ff5554dc9f83e3cab31b8fb89d10604ebcd963c7b8ce131fd3ef47c2a0921"
            ),
            merkle_root: into("a86996c4ae298b22a4a1c971aa29f0ea9fb1d822191fa8e0755b08381a90bc19"),
            time: 1583516502,
            bits: 0x1d01cc13,
            nonce: 867267585,
        }));
        // 277960
        assert!(check_hash(bitcoin::BlockHeader {
            version: 536870912,
            prev_blockhash: into(
                "4cb8068ec9d224d5869fe57144cff796e4c88f9da5ebe81dab88cd247d93e0e2"
            ),
            merkle_root: into("3d976f66323f5d79880c8c87bcd35506f43e27c9ec75468572db57aacf7c1b72"),
            time: 1583519758,
            bits: 0x1d023fa9,
            nonce: 2041135619,
        }));
    }

    #[test]
    fn test_mine() {
        // 277930
        assert_eq!(
            mine(
                bitcoin::BlockHeader {
                    version: 536870912,
                    prev_blockhash: into(
                        "508ff5554dc9f83e3cab31b8fb89d10604ebcd963c7b8ce131fd3ef47c2a0921"
                    ),
                    merkle_root: into(
                        "a86996c4ae298b22a4a1c971aa29f0ea9fb1d822191fa8e0755b08381a90bc19"
                    ),
                    time: 1583516502,
                    bits: 0x1d01cc13,
                    nonce: 0,
                },
                Some(867267585 - 10),
            ),
            Some(867267585),
        );
        // 277960
        assert_eq!(
            mine(
                bitcoin::BlockHeader {
                    version: 536870912,
                    prev_blockhash: into(
                        "4cb8068ec9d224d5869fe57144cff796e4c88f9da5ebe81dab88cd247d93e0e2"
                    ),
                    merkle_root: into(
                        "3d976f66323f5d79880c8c87bcd35506f43e27c9ec75468572db57aacf7c1b72"
                    ),
                    time: 1583519758,
                    bits: 0x1d023fa9,
                    nonce: 0,
                },
                Some(2041135619 - 10)
            ),
            Some(2041135619)
        );
    }
}
