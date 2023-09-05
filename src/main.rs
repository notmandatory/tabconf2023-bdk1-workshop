use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::string::ToString;
use std::{io, io::Write, str::FromStr};

use bdk::bitcoin::bip32;
use bdk::bitcoin::bip32::ExtendedPrivKey;
use bdk::bitcoin::secp256k1::{rand, rand::RngCore, Secp256k1};

use bdk::chain::keychain::WalletUpdate;
use bdk::{bitcoin::Network, descriptor, KeychainKind, Wallet};

use bdk::descriptor::IntoWalletDescriptor;
use bdk::keys::IntoDescriptorKey;
use bdk::wallet::AddressIndex;
use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_file_store::Store;

const CONFIG_FILE: &str = "config.txt";
const CHAIN_DATA_FILE: &str = "chain.dat";
const DB_MAGIC: &[u8] = "TABCONF24".as_bytes();

const STOP_GAP: usize = 50;
const PARALLEL_REQUESTS: usize = 5;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and load or save new descriptors

    let secp = Secp256k1::new();
    let network = Network::Signet;

    // get descriptors from config.txt file, if file is missing create a new ones
    let descriptors = match File::open(CONFIG_FILE) {
        // load descriptors from file
        Ok(mut file) => {
            let mut config = String::new();
            file.read_to_string(&mut config)?;
            let descriptor_strings: [_; 2] = config
                .split("|")
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let external_descriptor = descriptor_strings[0]
                .into_wallet_descriptor(&secp, network)
                .unwrap();
            let internal_descriptor = descriptor_strings[1]
                .into_wallet_descriptor(&secp, network)
                .unwrap();
            (external_descriptor, internal_descriptor)
        }
        Err(_) => {
            // create new descriptors and save them to the file
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            let xprv = ExtendedPrivKey::new_master(network, &seed).unwrap();
            let bip86_external = bip32::DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
            let bip86_internal = bip32::DerivationPath::from_str("m/86'/1'/0'/0/1").unwrap();
            let external_key = (xprv, bip86_external).into_descriptor_key().unwrap();
            let internal_key = (xprv, bip86_internal).into_descriptor_key().unwrap();
            let external_descriptor = descriptor!(tr(external_key))
                .unwrap()
                .into_wallet_descriptor(&secp, network)
                .unwrap();
            let internal_descriptor = descriptor!(tr(internal_key))
                .unwrap()
                .into_wallet_descriptor(&secp, network)
                .unwrap();
            // save descriptor strings to file
            let mut file = File::create(CONFIG_FILE).unwrap();
            println!("Created new descriptor config file: config.txt");
            let config = format!(
                "{}|{}",
                &external_descriptor
                    .0
                    .to_string_with_secret(&external_descriptor.1),
                &internal_descriptor
                    .0
                    .to_string_with_secret(&internal_descriptor.1)
            );
            file.write(config.as_bytes()).unwrap();
            (external_descriptor, internal_descriptor)
        }
    };

    let external_descriptor = descriptors.0;
    let internal_descriptor = descriptors.1;
    println!(
        "External descriptor: {}",
        &external_descriptor
            .0
            .to_string_with_secret(&external_descriptor.1)
    );
    println!(
        "Internal descriptor: {}\n",
        &internal_descriptor
            .0
            .to_string_with_secret(&internal_descriptor.1)
    );

    // Create a wallet and get a new address and current wallet balance

    let db = Store::<bdk::wallet::ChangeSet>::new_from_path(DB_MAGIC, CHAIN_DATA_FILE)?;

    // Create a new wallet
    let mut wallet = Wallet::new(external_descriptor, Some(internal_descriptor), db, network)?;

    // Get a new wallet address
    let address = wallet.get_address(AddressIndex::New);
    println!("Generated Address: {:?}", address);

    // Get the wallet balance before syncing
    let balance = wallet.get_balance();
    println!("Wallet balance before syncing: confirmed {} sats, trusted_pending {} sats, untrusted pending {} sats", balance.confirmed, balance.trusted_pending, balance.untrusted_pending);

    // Create an async esplora client

    let client = esplora_client::Builder::new("http://signet.bitcoindevkit.net").build_async()?;
    let prev_tip = wallet.latest_checkpoint();

    // Prepare the `IndexedTxGraph` update based on whether we are scanning or syncing.

    // Scanning: We are iterating through spks of all keychains and scanning for transactions for
    //   each spk. We start with the lowest derivation index spk and stop scanning after `stop_gap`
    //   number of consecutive spks have no transaction history. A Scan is done in situations of
    //   wallet restoration. It is a special case. Applications should use "sync" style updates
    //   after an initial scan.
    if prompt("Scan wallet") {
        let keychain_spks = wallet
            .spks_of_all_keychains()
            .into_iter()
            // This `map` is purely for logging.
            .map(|(keychain, iter)| {
                let mut first = true;
                let spk_iter = iter.inspect(move |(i, _)| {
                    if first {
                        // TODO impl Display for Keychain
                        eprint!(
                            "\nscanning {}: ",
                            match keychain {
                                KeychainKind::External => "External",
                                KeychainKind::Internal => "Internal",
                            }
                        );
                        first = false;
                    }
                    eprint!("{} ", i);
                    // Flush early to ensure we print at every iteration.
                    let _ = io::stderr().flush();
                });
                (keychain, spk_iter)
            })
            .collect::<BTreeMap<_, _>>();

        // The client scans keychain spks for transaction histories, stopping after `stop_gap`
        // is reached. It returns a `TxGraph` update (`graph_update`) and a structure that
        // represents the last active spk derivation indices of keychains
        // (`keychain_indices_update`).
        let (graph_update, last_active_indices) = client
            .update_tx_graph(
                keychain_spks,
                core::iter::empty(),
                core::iter::empty(),
                STOP_GAP,
                PARALLEL_REQUESTS,
            )
            .await?;

        println!();
        let missing_heights = wallet.tx_graph().missing_heights(wallet.local_chain());
        let chain_update = client
            .update_local_chain(prev_tip.clone(), missing_heights)
            .await?;

        let update = WalletUpdate {
            last_active_indices,
            graph: graph_update,
            chain: chain_update,
        };
        wallet.apply_update(update)?;
        wallet.commit()?;
        println!("Scan completed.");

        let balance = wallet.get_balance();
        println!("Wallet balance after scanning: confirmed {} sats, trusted_pending {} sats, untrusted pending {} sats",
                 balance.confirmed, balance.trusted_pending, balance.untrusted_pending);
    }

    Ok(())
}

fn prompt(question: &str) -> bool {
    print!("{}? (Y/N) ", question);
    std::io::stdout().flush().expect("stdout flush");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).expect("answer");
    answer.trim().to_ascii_lowercase() == "y"
}
