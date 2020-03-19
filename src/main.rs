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

use bitcoin::BitcoinHash;
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use structopt::StructOpt;

fn mine(header: bitcoin::BlockHeader, initial_nonce: u32) -> Option<u32> {
    let executor = futures::executor::ThreadPool::new().unwrap();
    let jobs = 10000;

    let nonces = initial_nonce..u32::max_value();
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

fn create_genesis_block(
    script_sig: bitcoin::Script,
    out_script: bitcoin::Script,
    time: u32,
    nonce: u32,
    bits: u32,
    satoshi_out: u64,
) -> bitcoin::Block {
    let tx = bitcoin::Transaction {
        version: 1,
        lock_time: 0,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig,
            sequence: bitcoin::blockdata::constants::MAX_SEQUENCE,
            witness: vec![],
        }],
        output: vec![bitcoin::TxOut {
            script_pubkey: out_script,
            value: satoshi_out,
        }],
    };
    let hash: bitcoin::hashes::sha256d::Hash = tx.txid().into();
    bitcoin::Block {
        header: bitcoin::BlockHeader {
            version: 1,
            prev_blockhash: Default::default(),
            merkle_root: hash.into(),
            bits,
            time,
            nonce,
        },
        txdata: vec![tx],
    }
}

fn parse_hex(src: &str) -> Result<u32, std::num::ParseIntError> {
    u32::from_str_radix(src.trim_start_matches("0x"), 16)
}

#[derive(StructOpt)]
struct CliArgs {
    #[structopt(name = "genesis msg", short = "m", long = "msg", required = true)]
    genesis_msg: String,
    #[structopt(
        name = "wif prefix",
        short = "w",
        long = "wif-prefix",
        required = true,
        default_value = "128"
    )]
    wif_prefix: u8,
    #[structopt(
        name = "reward (in satoshi)",
        short = "r",
        long = "reward",
        required = true
    )]
    satoshi_out: u64,
    #[structopt(
        name = "difficulty bits (hex)",
        short = "b",
        long = "bits",
        parse(try_from_str = parse_hex),
        default_value = "0x1d7fffff"
    )]
    bits: u32,
}

fn main() {
    let args = CliArgs::from_args();
    let script_sig = bitcoin::blockdata::script::Builder::new()
        .push_scriptint(486604799)
        .push_scriptint(4)
        .push_slice(args.genesis_msg.as_bytes())
        .into_script();

    let mut rng = rand::rngs::OsRng::new().unwrap();
    let (sk, pk) = secp256k1::Secp256k1::new().generate_keypair(&mut rng);

    let out_script = bitcoin::blockdata::script::Builder::new()
        .push_slice(&pk.serialize())
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
        .into_script();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut block = create_genesis_block(
        script_sig,
        out_script,
        time as u32,
        0,
        args.bits,
        args.satoshi_out,
    );
    block.header.nonce = mine(block.header, 0).unwrap();
    println!(
        r#"
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{{
    const char* pszTimestamp = "{}";
    const CScript genesisOutputScript = CScript() << ParseHex("{}") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}}

        genesis = CreateGenesisBlock({}, {}, {:#x}, 1, {});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x{}"));
        assert(genesis.hashMerkleRoot == uint256S("0x{}"));
"#,
        args.genesis_msg,
        hex::encode(pk.serialize()[..].to_vec()),
        time,
        block.header.nonce,
        block.header.bits,
        args.satoshi_out,
        block.header.bitcoin_hash(),
        block.header.merkle_root
    );
    let mut wif_key = sk[..].to_vec();
    wif_key.insert(0, args.wif_prefix);
    wif_key.push(1);
    println!(
        "WIF key: {}",
        bitcoin::util::base58::check_encode_slice(&wif_key)
    );
}

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
                867267585 - 10,
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
                2041135619 - 10
            ),
            Some(2041135619)
        );
    }

    #[test]
    fn test_create_genesis_block() {
        let script_sig = bitcoin::blockdata::script::Builder::new()
            .push_scriptint(486604799)
            .push_scriptint(4)
            .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
            .into_script();
        let out_script = bitcoin::blockdata::script::Builder::new()
            .push_slice(&Vec::from_hex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f").unwrap())
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script();
        let sats = 50 * bitcoin::blockdata::constants::COIN_VALUE;
        assert_eq!(
            create_genesis_block(script_sig, out_script, 1231006505, 2083236893, 0x1d00ffff, sats),
            bitcoin::blockdata::constants::genesis_block(
                bitcoin::network::constants::Network::Bitcoin
            )
        );
    }
}
