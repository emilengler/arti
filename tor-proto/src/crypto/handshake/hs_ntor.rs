//! Implements the HS ntor handshake, as used in v3 onion services.
//!
//! The Ntor protocol of this section is specified in section
//! [NTOR-WITH-EXTRA-DATA] of rend-spec-v3.txt.
//!
//! The main difference between this HS Ntor handshake and the standard Ntor
//! handshake in ./ntor.rs is that this one allows each party to encrypt data
//! (without forward secrecy) after it sends the first message. This
//! opportunistic encryption property is used by clients in the onion service
//! protocol to encrypt introduction data in the INTRODUCE1 cell, and by
//! services to encrypt data in the RENDEZVOUS1 cell.

// We want to use the exact variable names from the rend-spec-v3.txt proposal.
// This means that we allow variables to be named x (privkey) and X (pubkey).
#![allow(non_snake_case)]

use crate::crypto::handshake::KeyGenerator;
use crate::crypto::ll::kdf::{Kdf, ShakeKdf};
use crate::{Result, SecretBytes};
use tor_bytes::{Reader, Writer};
use tor_llcrypto::d::Sha3_256;
use tor_llcrypto::pk::{curve25519, ed25519};
use tor_llcrypto::util::rand_compat::RngCompatExt;

use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;
use zeroize::Zeroizing;

/// The key generator used by the HS ntor handshake.  Implements the simple key
/// expansion protocl specified in section "Key expansion" of rend-spec-v3.txt .
pub struct HSNtorHkdfKeyGenerator {
    /// Secret data derived from the handshake, used as input to HKDF
    seed: SecretBytes,
}

impl HSNtorHkdfKeyGenerator {
    /// Create a new key generator to expand a given seed
    pub fn new(seed: SecretBytes) -> Self {
        HSNtorHkdfKeyGenerator { seed }
    }
}

impl KeyGenerator for HSNtorHkdfKeyGenerator {
    /// Expand the seed into a keystream of 'keylen' size
    fn expand(self, keylen: usize) -> Result<SecretBytes> {
        ShakeKdf::new().derive(&self.seed[..], keylen)
    }
}

/*********************** Client Side Code ************************************/

/// Client side of the HS Ntor handshake
pub struct HSNtorClient;

impl super::ClientHandshake for HSNtorClient {
    type KeyType = HSNtorClientKeys;
    type StateType = HSNtorClientState;
    type KeyGen = HSNtorHkdfKeyGenerator;

    /// Start the HS Ntor handshake as the client. This method is here to
    /// satisfy the ClientHandshake trait but the work actually happens in
    /// client1_with_extra_data() below.
    fn client1<R: RngCore + CryptoRng>(
        rng: &mut R,
        keys: &Self::KeyType,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        let (state, response, _, _) = Self::client1_with_extra_data(rng, keys)?;
        Ok((state, response))
    }

    /// Finish the HS Ntor handshake as the client. This method is here to
    /// satisfy the ClientHandshake trait but the work actually happens in
    /// client2_with_extra_data() below.
    fn client2<T: AsRef<[u8]>>(state: Self::StateType, msg: T) -> Result<Self::KeyGen> {
        let (keygen, _) = Self::client2_with_extra_data(state, msg)?;
        Ok(keygen)
    }
}

/// We add a bunch of advanced functions to HSNtorClient to fit the needs of
/// the HS Ntor handshake. In particular the functions below return additional
/// data to allow the caller to encrypt and MAC the data to be encrypted as
/// part of the HS protocol.
///
/// XXXX We should adapt the ClientHandshake trait to use associated types so
/// that it returns the data below as part of its regular client1() interface.
impl HSNtorClient {
    /// Start the HS Ntor handshake as the client.
    ///
    /// Return the Ntor protocol state, the response to the service, the
    /// encryption key, and the MAC key.
    ///
    /// The response has the public key 'X' of the client.
    fn client1_with_extra_data<R: RngCore + CryptoRng>(
        rng: &mut R,
        keys: &HSNtorClientKeys,
    ) -> Result<(HSNtorClientState, Vec<u8>, [u8; 32], [u8; 32])> {
        client_send_intro(rng, keys)
    }

    /// Finish the HS Ntor handshake as the client
    ///
    /// Return a key generator which is the result of the key exchange, and the
    /// AUTH_INPUT_MAC that should be validated.
    fn client2_with_extra_data<T: AsRef<[u8]>>(
        state: HSNtorClientState,
        msg: T,
    ) -> Result<(HSNtorHkdfKeyGenerator, [u8; 32])> {
        client_verify_rend(msg, state)
    }
}

#[derive(Clone)]
pub struct HSNtorClientKeys {
    /// Introduction point encryption key (aka B)
    /// (found in the HS descriptor)
    B: curve25519::PublicKey,

    /// Introduction point authentication key (aka AUTH_KEY)
    /// (found in the HS descriptor)
    auth_key: ed25519::PublicKey,

    /// Service subcredential
    subcredential: [u8; 32],
}

/// Client state for an ntor handshake.
pub struct HSNtorClientState {
    /// Keys that we received from our caller when we started the protocol. The
    /// rest of the keys in this state structure have been created during the
    /// protocol.
    public_keys: HSNtorClientKeys,

    /// The temporary curve25519 secret that we've generated for this
    /// handshake.
    x: curve25519::StaticSecret,
    /// The corresponding private key
    X: curve25519::PublicKey,
}

/// The client is about to make an INTRODUCE1 cell. Perform the first part of
/// the client handshake.
///
/// Return a state object containing the current progress of the handshake, a
/// vector containing the data that should be encoded in the INTRODUCE1 cell,
/// an encryption key to encrypt other intro data, and a MAC key to
/// authenticate that intro data.
fn client_send_intro<R>(
    rng: &mut R,
    keys: &HSNtorClientKeys,
) -> Result<(HSNtorClientState, Vec<u8>, [u8; 32], [u8; 32])>
where
    R: RngCore + CryptoRng,
{
    // Create client's ephemeral keys to be used for this handshake
    let x = curve25519::StaticSecret::new(rng.rng_compat());
    let X = curve25519::PublicKey::from(&x);

    // Get EXP(B,x)
    let bx = x.diffie_hellman(&keys.B);

    // Compile our state structure
    let state = HSNtorClientState {
        public_keys: keys.clone(),
        x: x,
        X: X,
    };

    // Compute keys required to finish this part of the handshake
    let (enc_key, mac_key) =
        get_introduce1_key_material(&bx, &keys.auth_key, &X, &keys.B, &keys.subcredential)?;

    // Create the relevant parts of INTRO1
    let mut v: Vec<u8> = Vec::new();
    v.write(&X);

    Ok((state, v, enc_key, mac_key))
}

/// The introduction has been completed and the service has replied with a
/// RENDEZVOUS1. Verify it's correct and return a key generator on success.
fn client_verify_rend<T>(
    msg: T,
    state: HSNtorClientState,
) -> Result<(HSNtorHkdfKeyGenerator, [u8; 32])>
where
    T: AsRef<[u8]>,
{
    // Extract the public key of the service from the message
    let mut cur = Reader::from_slice(msg.as_ref());
    let Y: curve25519::PublicKey = cur.extract()?;

    // Get EXP(Y,x) and EXP(B,x)
    let xy = state.x.diffie_hellman(&Y);
    let xb = state.x.diffie_hellman(&state.public_keys.B);

    let (keygen, auth_input_mac) = get_rendezvous1_key_material(
        &xy,
        &xb,
        &state.public_keys.auth_key,
        &state.public_keys.B,
        &state.X,
        &Y,
    )?;

    return Ok((keygen, auth_input_mac));
}

/*********************** Server Side Code ************************************/

/// Server side of the HS ntor handshake.
pub struct HSNtorServer;

impl super::ServerHandshake for HSNtorServer {
    type KeyType = HSNtorServiceKeys;
    type KeyGen = HSNtorHkdfKeyGenerator;

    /// Conduct the HS Ntor handshake as the service. This method is here to
    /// satisfy the ServerHandshake trait but the work actually happens in
    /// server_with_extra_data() below.
    fn server<R: RngCore + CryptoRng, T: AsRef<[u8]>>(
        rng: &mut R,
        keys: &[Self::KeyType],
        msg: T,
    ) -> Result<(Self::KeyGen, Vec<u8>)> {
        let (keygen, reply, _, _, _) = Self::server_with_extra_data(rng, keys, msg)?;
        Ok((keygen, reply))
    }
}

/// Similar to the way we did it for HSNtorClient, we introduce a function
/// below to return additional data that are required by the HS Ntor handshake.
impl HSNtorServer {
    /// Conduct the HS Ntor handshake as the service.
    ///
    /// Return a key generator which is the result of the key exchange, the
    /// response to the client, the encryption key, the MAC key and the
    /// AUTH_INPUT_MAC.
    ///
    /// XXXX Depending on how we use this API on the final code, we might want
    /// to split this function into two. One used when handling the
    /// introduction cell, and one used when creating a rendezvous circuit. We
    /// use this model in little-t-tor and it works nicely.
    fn server_with_extra_data<R: RngCore + CryptoRng, T: AsRef<[u8]>>(
        rng: &mut R,
        keys: &[HSNtorServiceKeys],
        msg: T,
    ) -> Result<(
        HSNtorHkdfKeyGenerator,
        Vec<u8>,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    )> {
        server_handshake_ntor_v1(rng, keys, msg)
    }
}

pub struct HSNtorServiceKeys {
    /// Introduction point encryption keypair
    b: curve25519::StaticSecret,
    B: curve25519::PublicKey,

    /// Introduction point authentication key (aka AUTH_KEY)
    auth_key: ed25519::PublicKey,

    /// Our subcredential
    subcredential: [u8; 32],
}

/// Conduct the HS Ntor handshake as the service.
///
/// Return a key generator which is the result of the key exchange, the
/// response to the client, the encryption key, the MAC key and the
/// AUTH_INPUT_MAC.
fn server_handshake_ntor_v1<R, T>(
    rng: &mut R,
    key_slice: &[HSNtorServiceKeys],
    msg: T,
) -> Result<(
    HSNtorHkdfKeyGenerator,
    Vec<u8>,
    [u8; 32],
    [u8; 32],
    [u8; 32],
)>
where
    R: RngCore + CryptoRng,
    T: AsRef<[u8]>,
{
    let keys = &key_slice[0];

    // Extract the client's public key from the message
    let mut cur = Reader::from_slice(msg.as_ref());
    let X: curve25519::PublicKey = cur.extract()?;

    // Now get keys needed for handling the INTRO1 cell
    let bx = keys.b.diffie_hellman(&X);
    let (enc_key, mac_key) =
        get_introduce1_key_material(&bx, &keys.auth_key, &X, &keys.B, &keys.subcredential)?;

    // Generate ephemeral keys for this handshake
    let y = curve25519::EphemeralSecret::new(rng.rng_compat());
    let Y = curve25519::PublicKey::from(&y);

    // Compute EXP(X,y) and EXP(X,b)
    let xy = y.diffie_hellman(&X);
    let xb = keys.b.diffie_hellman(&X);

    let (keygen, auth_input_mac) =
        get_rendezvous1_key_material(&xy, &xb, &keys.auth_key, &keys.B, &X, &Y)?;

    // Set up RENDEZVOUS1 reply to the client
    let mut reply: Vec<u8> = Vec::new();
    reply.write(&Y);

    Ok((keygen, reply, enc_key, mac_key, auth_input_mac))
}

/*********************** Helper functions ************************************/

/// Implement the MAC function used as part of the HS ntor handshake:
/// MAC(k, m) is H(k_len | k | m) where k_len is htonll(len(k)).
fn hs_ntor_mac(key: &Vec<u8>, message: &[u8]) -> Result<[u8; 32]> {
    let k_len = key.len();

    let mut d = Sha3_256::new();
    d.update((k_len as u64).to_be_bytes());
    d.update(key);
    d.update(message);

    let result = d.finalize();
    Ok(result.try_into().unwrap()) // XXX unwrap but this should not fail (?)
}

/// Helper function: Compute the part of the HS ntor handshake that generates
/// key material for creating and handling INTRODUCE1 cells. Function used
/// by both client and service. Specifically, calculate the following:
///
///  intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
///  info = m_hsexpand | subcredential
///  hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
///  ENC_KEY = hs_keys[0:S_KEY_LEN]
///  MAC_KEY = hs_keys[S_KEY_LEN:S_KEY_LEN+MAC_KEY_LEN]
///
/// Return (ENC_KEY, MAC_KEY).
fn get_introduce1_key_material(
    bx: &curve25519::SharedSecret,
    auth_key: &ed25519::PublicKey,
    X: &curve25519::PublicKey,
    B: &curve25519::PublicKey,
    subcredential: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    let hs_ntor_protoid_constant = &b"tor-hs-ntor-curve25519-sha3-256-1"[..];
    let hs_ntor_key_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract"[..];
    let hs_ntor_expand_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand"[..];

    // Construct hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
    // Start by getting 'intro_secret_hs_input'
    let mut secret_input = Zeroizing::new(Vec::new());
    secret_input.write(bx); // EXP(B,x)
    secret_input.write(auth_key); // AUTH_KEY
    secret_input.write(X); // X
    secret_input.write(B); // B
    secret_input.write(hs_ntor_protoid_constant); // PROTOID

    // Now fold in the t_hsenc
    secret_input.write(hs_ntor_key_constant);

    // and fold in the 'info'
    secret_input.write(hs_ntor_expand_constant);
    secret_input.write(subcredential);

    let hs_keys = ShakeKdf::new().derive(&secret_input[..], 32 + 32)?;
    // Extract the keys into arrays
    let enc_key = hs_keys[0..32].try_into().unwrap(); // XXX bad unwrap turning slice to array
    let mac_key = hs_keys[32..64].try_into().unwrap(); // XXX bad unwrap

    Ok((enc_key, mac_key))
}

/// Helper function: Compute the last part of the HS ntor handshake which
/// derives key material necessary to create and handle RENDEZVOUS1
/// cells. Function used by both client and service. The actual calculations is
/// as follows:
///
///  rend_secret_hs_input = EXP(X,y) | EXP(X,b) | AUTH_KEY | B | X | Y | PROTOID
///  NTOR_KEY_SEED = MAC(rend_secret_hs_input, t_hsenc)
///  verify = MAC(rend_secret_hs_input, t_hsverify)
///  auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
///  AUTH_INPUT_MAC = MAC(auth_input, t_hsmac)
///
/// Return (keygen, AUTH_INPUT_MAC), where keygen is a key generator based on
/// NTOR_KEY_SEED.
fn get_rendezvous1_key_material(
    xy: &curve25519::SharedSecret,
    xb: &curve25519::SharedSecret,
    auth_key: &ed25519::PublicKey,
    B: &curve25519::PublicKey,
    X: &curve25519::PublicKey,
    Y: &curve25519::PublicKey,
) -> Result<(HSNtorHkdfKeyGenerator, [u8; 32])> {
    let hs_ntor_protoid_constant = &b"tor-hs-ntor-curve25519-sha3-256-1"[..];
    let hs_ntor_mac_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_mac"[..];
    let hs_ntor_verify_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_verify"[..];
    let server_string_constant = &b"Server"[..];
    let hs_ntor_expand_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand"[..];
    let hs_ntor_key_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract"[..];

    // Start with rend_secret_hs_input
    let mut secret_input = Zeroizing::new(Vec::new());
    secret_input.write(xy); // EXP(X,y)
    secret_input.write(xb); // EXP(X,b)
    secret_input.write(auth_key); // AUTH_KEY
    secret_input.write(B); // B
    secret_input.write(X); // X
    secret_input.write(Y); // Y
    secret_input.write(hs_ntor_protoid_constant); // PROTOID

    // Build NTOR_KEY_SEED and verify
    let ntor_key_seed = hs_ntor_mac(&secret_input, hs_ntor_key_constant)?;
    let verify = hs_ntor_mac(&secret_input, hs_ntor_verify_constant)?;

    // Start building 'auth_input'
    let mut auth_input = Zeroizing::new(Vec::new());
    auth_input.write(&verify);
    auth_input.write(auth_key); // AUTH_KEY
    auth_input.write(B); // B
    auth_input.write(Y); // Y
    auth_input.write(X); // X
    auth_input.write(hs_ntor_protoid_constant); // PROTOID
    auth_input.write(server_string_constant); // "Server"

    // Get AUTH_INPUT_MAC
    let auth_input_mac = hs_ntor_mac(&auth_input, hs_ntor_mac_constant)?;

    // Now finish up with the KDF construction
    let mut kdf_seed = Zeroizing::new(Vec::new());
    kdf_seed.write(&ntor_key_seed);
    kdf_seed.write(hs_ntor_expand_constant);
    let keygen = HSNtorHkdfKeyGenerator::new(Zeroizing::new(kdf_seed.to_vec()));

    Ok((keygen, auth_input_mac))
}

/*********************** Unit Tests ******************************************/

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]

    /// Basic HS Ntor test that does the handshake between client and service
    /// and makes sure that the resulting keys and KDF is legit.
    fn hs_ntor() -> Result<()> {
        let mut rng = rand::thread_rng().rng_compat();

        // Let's initialize keys for the client (and the intro point)
        let intro_b_privkey = curve25519::StaticSecret::new(&mut rng);
        let intro_b_pubkey = curve25519::PublicKey::from(&intro_b_privkey);
        let intro_auth_key_privkey = ed25519::SecretKey::generate(&mut rng);
        let intro_auth_key_pubkey = ed25519::PublicKey::from(&intro_auth_key_privkey);

        let client_keys = HSNtorClientKeys {
            B: intro_b_pubkey,
            auth_key: intro_auth_key_pubkey,
            subcredential: [5; 32],
        };

        // Client: Sends an encrypted INTRODUCE1 cell
        let (state, cmsg, c_enc_key, c_mac_key) =
            HSNtorClient::client1_with_extra_data(&mut rng, &client_keys)?;

        let service_keys = HSNtorServiceKeys {
            b: intro_b_privkey,
            B: intro_b_pubkey,
            auth_key: intro_auth_key_pubkey,
            subcredential: [5; 32],
        };

        // Service: Decrypts INTRODUCE1 cell
        let (skeygen, smsg, s_enc_key, s_mac_key, s_auth_input_mac) =
            HSNtorServer::server_with_extra_data(&mut rng, &[service_keys], cmsg)?;

        // Test encryption key
        assert_eq!(c_enc_key, s_enc_key);
        // Test MAC key
        assert_eq!(c_mac_key, s_mac_key);

        // Service: Create RENDEZVOUS1 key material
        let (ckeygen, c_auth_input_mac) = HSNtorClient::client2_with_extra_data(state, smsg)?;

        // Test rend MAC
        assert_eq!(c_auth_input_mac, s_auth_input_mac);

        // Test that RENDEZVOUS1 key material match
        let skeys = skeygen.expand(128)?;
        let ckeys = ckeygen.expand(128)?;
        // Test key generator
        assert_eq!(skeys, ckeys);

        Ok(())
    }

    #[test]
    fn ntor_mac() -> Result<()> {
        let result = hs_ntor_mac(&"who".as_bytes().to_vec(), b"knows?")?;
        assert_eq!(
            &result,
            &hex!("5e7da329630fdaa3eab7498bb1dc625bbb9ca968f10392b6af92d51d5db17473")
        );

        let result = hs_ntor_mac(&"gone".as_bytes().to_vec(), b"by")?;
        assert_eq!(
            &result,
            &hex!("90071aabb06d3f7c777db41542f4790c7dd9e2e7b2b842f54c9c42bbdb37e9a0")
        );

        Ok(())
    }
}
