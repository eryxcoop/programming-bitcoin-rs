use programming_bitcoin_rs::{Address, Chain, Encoding, PrivateKey, PublicKey};

extern crate programming_bitcoin_rs;

fn main() {
    let private_key = PrivateKey::new([
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1,
    ]);
    let public_key = PublicKey::from_private_key(private_key);
    let address = Address::new(&public_key, Chain::TestNet, Encoding::Bech32);
    println!("The address is: {}", address);
}
