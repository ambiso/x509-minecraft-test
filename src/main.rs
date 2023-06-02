use der::Encode;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use x509_cert::spki::SubjectPublicKeyInfoOwned;

fn main() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    // Encrypt
    let data = b"hello world";
    let enc_data = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    // Decrypt
    let dec_data = priv_key
        .decrypt(Pkcs1v15Encrypt, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);

    // let pub_key_der = pub_key.to_pkcs1_der().unwrap();
    let pub_key_der =
        rsa_der::public_key_to_der(&pub_key.n().to_bytes_be(), &pub_key.e().to_bytes_be());

    let subject_public_key_info =
        SubjectPublicKeyInfoOwned::try_from(pub_key_der.as_slice()).expect("get rsa pub key");

    for (i, b) in subject_public_key_info.to_der().unwrap().iter().enumerate() {
        if i > 0 && i % 40 == 0 {
            println!("");
        }
        print!("{b:02x}");
    }
    println!("");
}
