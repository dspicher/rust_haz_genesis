#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub fn rust_neoscrypt(message: [u8; 80], options: u32) -> [u8; 32] {
    let mut buf = [0; 32];
    unsafe {
        neoscrypt(message.as_ptr(), buf.as_mut_ptr(), options);
    }
    buf
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
    let hashPrevBlock = hex::decode(hashPrevBlock).unwrap();
    let hashMerkleRoot = hex::decode(hashMerkleRoot).unwrap();
    let mut header = [0 as u8; 80];
    let mut idx = 0;

    for byte in nVersion.to_le_bytes().iter() {
        header[idx] = *byte;
        idx += 1;
    }
    for byte in hashPrevBlock.iter().rev() {
        header[idx] = *byte;
        idx += 1;
    }
    for byte in hashMerkleRoot.iter().rev() {
        header[idx] = *byte;
        idx += 1;
    }
    for byte in nTime.to_le_bytes().iter() {
        header[idx] = *byte;
        idx += 1;
    }
    for byte in &nBits.to_le_bytes() {
        header[idx] = *byte;
        idx += 1;
    }
    for byte in nNonce.to_le_bytes().iter() {
        header[idx] = *byte;
        idx += 1;
    }

    let neo_scrypt_options: u32 = 0x1000;
    let mut out = rust_neoscrypt(header, neo_scrypt_options);
    out.reverse();

    let target = get_target(nBits);

    check_pow(out, target)
}

fn get_target(nBits: u32) -> [u8; 32] {
    let b = (nBits >> 24) - 3;
    let mut target = [0 as u8; 32];
    target[32 - b as usize - 1] = nBits as u8;
    target[32 - b as usize - 2] = (nBits >> 8) as u8;
    target[32 - b as usize - 3] = (nBits >> 16) as u8;
    target
}

fn main() {}

fn check_pow(hash: [u8; 32], target: [u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true
}

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

#[test]
fn test_target() {
    // from https://en.bitcoin.it/wiki/Difficulty
    let target = get_target(0x1d00ffff);
    assert_eq!(
        hex::encode(target),
        "00000000ffff0000000000000000000000000000000000000000000000000000"
    );

    let target = get_target(0x1b0404cb);
    assert_eq!(
        hex::encode(target),
        "00000000000404cb000000000000000000000000000000000000000000000000"
    );
}
