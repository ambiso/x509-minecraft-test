use pkcs8::EncodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};

fn main() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    for (i, b) in pub_key.to_public_key_der().unwrap().as_bytes().iter().enumerate() {
        if i > 0 && i % 40 == 0 {
            println!("");
        }
        print!("{b:02x}");
    }
    println!("");
}
