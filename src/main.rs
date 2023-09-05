use std::fs::File;
use std::io::Read;
use std::string::ToString;
use std::{io::Write, str::FromStr};

use bdk::bitcoin::bip32;
use bdk::bitcoin::bip32::ExtendedPrivKey;
use bdk::bitcoin::secp256k1::{rand, rand::RngCore, Secp256k1};

use bdk::{bitcoin::Network, descriptor};

use bdk::descriptor::IntoWalletDescriptor;
use bdk::keys::IntoDescriptorKey;

const CONFIG_FILE: &str = "config.txt";

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

    Ok(())
}