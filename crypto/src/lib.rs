use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use hmac::digest::OutputSizeUser;
use ripemd::{Digest, Ripemd160};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut h = Ripemd160::new();
    h.update(data);
    h.finalize().into()
}

#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    x25519_secret: StaticSecret,
    x25519_public: X25519PublicKey,
}

impl Identity {
    pub fn new() -> Self {
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let x25519_secret = StaticSecret::random_from_rng(&mut csprng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        Self {
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
        }
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn x25519_public(&self) -> &X25519PublicKey {
        &self.x25519_public
    }

    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519_secret
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}

pub fn dh(our_secret: &StaticSecret, their_public: &X25519PublicKey) -> [u8; 32] {
    let shared = our_secret.diffie_hellman(their_public);
    shared.as_bytes()[..32].try_into().expect("x25519 shared secret is 32 bytes")
}

pub fn hkdf(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    type H = Hmac<Ripemd160>;
    let hash_len = H::output_size();
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => vec![0u8; hash_len],
    };
    let mut extract = <H as Mac>::new_from_slice(&salt_bytes).expect("HMAC can take key");
    Mac::update(&mut extract, ikm);
    let prk = Mac::finalize(extract).into_bytes();
    let mut okm = Vec::with_capacity(out_len);
    let mut counter: u8 = 1;
    let mut t = Vec::new();
    while okm.len() < out_len {
        let mut expand = <H as Mac>::new_from_slice(&prk).expect("HMAC can take key");
        Mac::update(&mut expand, &t);
        Mac::update(&mut expand, info);
        Mac::update(&mut expand, &[counter]);
        t = Mac::finalize(expand).into_bytes().to_vec();
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(out_len);
    okm
}

pub fn aead_encrypt(key: &[u8; 32], nonce: &XNonce, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.encrypt(nonce, plaintext).map_err(|_| CryptoError::EncryptionFailed)
}

pub fn aead_decrypt(key: &[u8; 32], nonce: &XNonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(nonce, ciphertext).map_err(|_| CryptoError::DecryptionFailed)
}
