#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use hex::FromHex;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub fn rust_neoscrypt(message: Vec<u8>, options: u32) -> bitcoin::util::uint::Uint256 {
    let mut buf = [0; 32];
    unsafe {
        neoscrypt(message.as_ptr(), buf.as_mut_ptr(), options);
    }
    bitcoin::consensus::encode::deserialize(&buf).unwrap()
}

fn mine(
    nVersion: u32,
    hashPrevBlock: &str,
    hashMerkleRoot: &str,
    nTime: u32,
    nBits: u32,
    initialNonce: Option<u32>,
) -> Option<u32> {
    let lower = match initialNonce {
        None => 0,
        Some(i) => i,
    };
    for nNonce in lower..u32::max_value() {
        println!("{:?}", nNonce);
        if check_hash(
            nVersion,
            hashPrevBlock,
            hashMerkleRoot,
            nTime,
            nBits,
            nNonce,
        ) {
            return Some(nNonce);
        }
    }
    None
}

fn check_hash(
    nVersion: u32,
    hashPrevBlock: &str,
    hashMerkleRoot: &str,
    nTime: u32,
    nBits: u32,
    nNonce: u32,
) -> bool {
    let mut prev_block = Vec::from_hex(hashPrevBlock).unwrap();
    prev_block.reverse();
    let mut merkle_root = Vec::from_hex(hashMerkleRoot).unwrap();
    merkle_root.reverse();

    let header = bitcoin::BlockHeader {
        version: nVersion,
        prev_blockhash: bitcoin::consensus::encode::deserialize(&prev_block).unwrap(),
        merkle_root: bitcoin::consensus::encode::deserialize(&merkle_root).unwrap(),
        time: nTime,
        bits: nBits,
        nonce: nNonce,
    };
    let neo_scrypt_options: u32 = 0x1000;
    rust_neoscrypt(
        bitcoin::consensus::encode::serialize(&header),
        neo_scrypt_options,
    ) < header.target()
}

fn main() {}

#[cfg(test)]
#[test]
fn test_real_blocks() {
    // 277930
    assert!(check_hash(
        536870912,
        "508ff5554dc9f83e3cab31b8fb89d10604ebcd963c7b8ce131fd3ef47c2a0921",
        "a86996c4ae298b22a4a1c971aa29f0ea9fb1d822191fa8e0755b08381a90bc19",
        1583516502,
        0x1d01cc13,
        867267585,
    ));
    // 277960
    assert!(check_hash(
        536870912,
        "4cb8068ec9d224d5869fe57144cff796e4c88f9da5ebe81dab88cd247d93e0e2",
        "3d976f66323f5d79880c8c87bcd35506f43e27c9ec75468572db57aacf7c1b72",
        1583519758,
        0x1d023fa9,
        2041135619,
    ));
}

#[test]
fn test_mine() {
    // 277930
    assert_eq!(
        mine(
            536870912,
            "508ff5554dc9f83e3cab31b8fb89d10604ebcd963c7b8ce131fd3ef47c2a0921",
            "a86996c4ae298b22a4a1c971aa29f0ea9fb1d822191fa8e0755b08381a90bc19",
            1583516502,
            0x1d01cc13,
            Some(867267585 - 10),
        ),
        Some(867267585),
    );
    // 277960
    assert_eq!(
        mine(
            536870912,
            "4cb8068ec9d224d5869fe57144cff796e4c88f9da5ebe81dab88cd247d93e0e2",
            "3d976f66323f5d79880c8c87bcd35506f43e27c9ec75468572db57aacf7c1b72",
            1583519758,
            0x1d023fa9,
            Some(2041135619 - 10),
        ),
        Some(2041135619),
    );
}
