use der::{Encode, AnyRef};
use der::asn1::{UintRef, BitString};
use rsa::pkcs1::RsaPublicKey as RsaPublicKeyPkcs1;
use rsa::pkcs8::SubjectPublicKeyInfo;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use x509_cert::spki::{AssociatedAlgorithmIdentifier};

fn main() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let pub_key_der = RsaPublicKeyPkcs1 {
        public_exponent: UintRef::new(pub_key.e().to_bytes_be().as_slice()).unwrap(),
        modulus: UintRef::new(pub_key.n().to_bytes_be().as_slice()).unwrap(),
    }.to_der().unwrap();

    let subject_public_key_info =
    SubjectPublicKeyInfo::<AnyRef<'static>, BitString> {
        algorithm: SigningKey::<Sha256>::ALGORITHM_IDENTIFIER,
        subject_public_key: BitString::new(0, pub_key_der).unwrap(),
    };

    for (i, b) in subject_public_key_info.to_der().unwrap().iter().enumerate() {
        if i > 0 && i % 40 == 0 {
            println!("");
        }
        print!("{b:02x}");
    }
    println!("");
}
