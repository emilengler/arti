use hex_literal::hex;
use tor_llcrypto as ll;

use std::convert::TryInto;

#[test]
fn test_ed25519_identity() {
    use ll::pk::ed25519::{Ed25519Identity, PublicKey};
    let example_key = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    // bad key, but length is okay.
    let bad_pk = hex!("000aaafaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000");

    assert_eq!(Ed25519Identity::from_bytes(&example_key[0..31]), None);
    let ex1 = Ed25519Identity::from_bytes(&example_key[0..32]).unwrap();
    assert_eq!(ex1, Ed25519Identity::new(example_key));

    let ex2: Ed25519Identity = bad_pk.into();

    assert_ne!(ex1, ex2);

    let pk: PublicKey = ex1.try_into().unwrap();
    let no_pk: Result<PublicKey, _> = ex2.try_into();
    assert!(no_pk.is_err());

    let ex3: Ed25519Identity = pk.into();
    assert_eq!(ex3, ex1);

    assert_eq!(
        format!("<<{}>>", ex3),
        "<<11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo>>"
    );
    assert_eq!(
        format!("{:?}", ex1),
        "Ed25519Identity { 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo }"
    );

    assert_eq!(ex3.as_bytes(), &example_key[..]);
}

#[test]
fn batch_verify() {
    use ll::pk::ed25519::*;
    use rand::RngCore;
    use signature::Signer;

    let mut rng = rand::thread_rng();
    let mut sigs = Vec::new();
    for _ in 0..3 {
        let kp = Keypair::generate(&mut rng);

        let mut bytes = [0u8; 128];
        rng.fill_bytes(&mut bytes[..]);

        let sig = kp.sign(&bytes[..]);

        let val = ValidatableEd25519Signature::new(kp.public, sig, &bytes[..]);

        sigs.push(val);
    }

    let sigrefs: Vec<_> = sigs.iter().collect();

    for n in 0..=3 {
        assert!(validate_batch(&sigrefs[0..n]));
    }

    // Now add a junk signature.
    let kp = Keypair::generate(&mut rng);
    let sig = kp.sign(&b"Apples"[..]);
    sigs.push(ValidatableEd25519Signature::new(
        kp.public,
        sig,
        &b"Oranges!"[..],
    ));
    let sigrefs: Vec<_> = sigs.iter().collect();
    assert!(!validate_batch(&sigrefs[..]));
}

#[test]
fn ser_de_rsaid() {
    use serde_test::{assert_tokens, Configure, Token};

    let rsa_id = ll::pk::rsa::RSAIdentity::from_bytes(b"example key id here!").unwrap();

    assert_tokens(
        &rsa_id.readable(),
        &[Token::Str("6578616d706c65206b6579206964206865726521")],
    );
    assert_tokens(&rsa_id.compact(), &[Token::Bytes(b"example key id here!")]);
}

#[test]
fn ser_de_edid() {
    use serde_test::{assert_tokens, Configure, Token};

    let rsa_id =
        ll::pk::ed25519::Ed25519Identity::from_bytes(b"this is another key. not valid..").unwrap();

    assert_tokens(
        &rsa_id.readable(),
        &[Token::Str("dGhpcyBpcyBhbm90aGVyIGtleS4gbm90IHZhbGlkLi4")],
    );

    assert_tokens(
        &rsa_id.compact(),
        &[Token::Bytes(b"this is another key. not valid..")],
    );
}
