mod neoscrypt {
    #![allow(dead_code)]
    #![allow(non_camel_case_types)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    static NEOSCRYPT_OPTIONS: u32 = 0x1000;

    pub fn hash(message: Vec<u8>) -> bitcoin::util::uint::Uint256 {
        let mut buf = [0; 32];
        unsafe {
            neoscrypt(message.as_ptr(), buf.as_mut_ptr(), NEOSCRYPT_OPTIONS);
        }
        bitcoin::consensus::encode::deserialize(&buf).unwrap()
    }
}

use futures::stream::StreamExt;
use futures::task::SpawnExt;

fn mine(header: bitcoin::BlockHeader, initial_nonce: Option<u32>) -> Option<u32> {
    let lower = match initial_nonce {
        None => 0,
        Some(i) => i,
    };

    let executor = futures::executor::ThreadPool::new().unwrap();
    let jobs = 10000;

    let nonces = lower..u32::max_value();
    let mut results = nonces
        .clone()
        .take(jobs)
        .map(|nonce| {
            let mut header = header;
            header.nonce = nonce;
            let future = futures::future::join(check_hash(header), futures::future::ready(nonce));
            executor.spawn_with_handle(future).unwrap()
        })
        .collect::<futures::stream::FuturesUnordered<_>>();
    futures::executor::block_on(async {
        for nonce in nonces.skip(jobs) {
            let (found, nonce_result) = results.select_next_some().await;
            if found {
                return Some(nonce_result);
            }
            let mut header = header;
            header.nonce = nonce;
            let future = futures::future::join(check_hash(header), futures::future::ready(nonce));
            results.push(executor.spawn_with_handle(future).unwrap());
        }
        loop {
            futures::select! {
                (found, nonce) = results.select_next_some() => {
                    if (found) {
                        return Some(nonce);
                    }
                },
                complete => return None,
            }
        }
    })
}

async fn check_hash(header: bitcoin::BlockHeader) -> bool {
    neoscrypt::hash(bitcoin::consensus::encode::serialize(&header)) < header.target()
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
        assert!(futures::executor::block_on(check_hash(
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
                nonce: 867267585,
            }
        )));
        // 277960
        assert!(futures::executor::block_on(check_hash(
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
                nonce: 2041135619,
            }
        )));
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
