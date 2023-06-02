use std::time::Duration;

use rsa::traits::PublicKeyParts;
use x509_cert::builder::Builder;

fn main() {
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

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

    use der::{Encode};
    use std::str::FromStr;
    use x509_cert::builder::{CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Root;
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();

    // let pub_key_der = pub_key.to_pkcs1_der().unwrap();
    let pub_key_der = rsa_der::public_key_to_der(&pub_key.n().to_bytes_be(), &pub_key.e().to_bytes_be());

    let pub_key = SubjectPublicKeyInfoOwned::try_from(pub_key_der.as_slice()).expect("get rsa pub key");

    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::sha2::{Digest, Sha256};
    use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};

    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let verifying_key = signing_key.verifying_key();

    // Sign
    let data = b"hello world";
    let signature = signing_key.sign_with_rng(&mut rng, data);
    assert_ne!(signature.to_bytes().as_ref(), data);

    // Verify
    verifying_key
        .verify(data, &signature)
        .expect("failed to verify");

    let builder =
        CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, &signing_key)
            .expect("Create certificate");
    
    let cert=builder.build().unwrap();

    for (i, b) in cert.to_der().unwrap().iter().enumerate() {
        if i > 0 && i % 40 == 0 {
            println!("");
        }
        print!("{b:02x}");
    }
    println!("");
}
