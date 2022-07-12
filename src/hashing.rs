// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! # The Hashing API
//!
//! ## A brief justification for this API
//!
//! The use of hash functions in cryptographic protocols typically assumes and requires that
//! these functions be randomly and independently sampled from an idealized set of all such functions, and have no
//! meaningful correlations to others.
//!
//! In reality, there are a limited number of modern cryptographic hash functions in common use: the SHA-2 family,
//! the SHA-3 family, Blake2b/s, Blake3, and so on. To use a single hash function for producing a sampling of multiple
//! independent hash functions, it's common to employ domain separation.
//!
//! This approach requires care to be done securely, but here's an example. If we want to use a single high-quality
//! cryptographic hash function `D` to produce independent hash functions `D_1` and `D_2`, we give each a unique and
//! meaningful label. We can then define the hash of some message `m` for each of our new hash functions:
//!
//! ```text
//! D_1 = D("label for D_1", msg)
//! D_2 = D("label for D_2", msg)
//! ```
//!
//! Provided the method used for including the label and message in `D` is secure (simple concatenation, for example,
//! is not sufficient), `D_1` and `D_2` behave as independent high-quality cryptographic hash functions, and generally
//! retain the useful properties of `D`.
//!
//! [hmac]: https://en.wikipedia.org/wiki/HMAC#Design_principles "HMAC: Design principles"

use std::{marker::PhantomData, ops::Deref};

use blake2::VarBlake2b;
use digest::{Digest, Output, Update};
use sha3::Sha3_256;
use tari_utilities::ByteArray;

use crate::{errors::HashingError, hash::blake2::Blake256, keys::SecretKey};

/// The `DomainSeparation` trait is used to inject domain separation tags into the [`DomainSeparatedHasher`] in a way
/// that can be applied consistently, but without hard-coding anything into the hasher itself.
///
/// Using a trait is more flexible than const strings, and lets us leverage the type system to have more fine-grained
/// control over allowable use cases.
///
/// For example, not all digest functions are suitable for use with the MAC generator provided in this crate. We can
/// indicate this at _compile time_ by adding a trait bound that prevents a client using these functions. See
/// [`MacDomain`] for details.
pub trait DomainSeparation {
    /// Returns the version number for the metadata tag
    fn version() -> u8;
    /// Returns the category label for the metadata tag. For example, `tari_hmac`
    fn domain() -> &'static str;
    /// The domain separation tag is defined as `{domain}.v{version}.{label}`, where the version and tag are
    /// typically hard-coded into the implementing type, and the label is provided per specific application of the
    /// domain
    fn domain_separation_tag<S: AsRef<str>>(label: S) -> String {
        format!("{}.v{}.{}", Self::domain(), Self::version(), label.as_ref())
    }

    /// Adds the domain separation tag to the given digest. The domain separation tag is defined as
    /// `{domain}.v{version}.{label}`, where the version and tag are typically hard-coded into the implementing
    /// type, and the label is provided per specific application of the domain.
    fn add_domain_separation_tag<S: AsRef<[u8]>, D: Digest>(digest: &mut D, label: S) {
        let domain = Self::domain();
        let (version_offset, version) = byte_to_decimal_ascii_bytes(Self::version());
        // 3 additional bytes are 2 x '.' delimiters and 'v' tag for version
        let len = domain.len() + (3 - version_offset) + label.as_ref().len() + 3;
        let len = (len as u64).to_le_bytes();
        digest.update(len);
        digest.update(domain);
        digest.update(b".v");
        digest.update(&version[version_offset..]);
        digest.update(b".");
        digest.update(label.as_ref());
    }
}

/// Converts a byte value to ASCII bytes that represent its value in big-endian order. This function returns a tuple
/// containing the inclusive index of the most significant decimal value byte, and the 3 ASCII bytes (big-endian). For
/// example, byte_to_decimal_ascii_bytes(0) returns (2, [0, 0, 48]).
/// byte_to_decimal_ascii_bytes(42) returns (1, [0, 52, 50]).
/// byte_to_decimal_ascii_bytes(255) returns (0, [50, 53, 53]).
fn byte_to_decimal_ascii_bytes(mut byte: u8) -> (usize, [u8; 3]) {
    const ZERO_ASCII_CHAR: u8 = 48;
    // A u8 can only ever be a 3 char number.
    let mut bytes = [0u8, 0u8, ZERO_ASCII_CHAR];
    let mut pos = 3usize;
    if byte == 0 {
        return (2, bytes);
    }
    while byte > 0 {
        let rem = byte % 10;
        byte /= 10;
        bytes[pos - 1] = ZERO_ASCII_CHAR + rem;
        pos -= 1;
    }
    (pos, bytes)
}

//--------------------------------------     Domain Separated Hash   ---------------------------------------------------

/// A hash value, guaranteed, as far as possible, to have been created using a hash function that has been randomly and
/// independently sampled from an idealized set of hash functions.
///
/// This is modelled via the strategy of applying a
/// domain separation tag that is unique for this hashing application (assuming clients make proper use of a unique
/// label for every discrete hashing use-case in their applications).
///
/// `DomainSeparatedHash` implements `AsRef<u8>`, so it is easy to use this type as a slice.
///
/// The domain separation information is retained with the hash, and can be queried using
/// [`DomainSeparatedHash::domain_separation_tag_string`].
///
/// To preserve the guarantee that the hash is properly domain separated, you cannot create an instance of this struct
/// directly. It is the result of using [`DomainSeparatedHasher`].
///
/// For details and examples, see [`DomainSeparatedHasher`].
pub struct DomainSeparatedHash<D: Digest> {
    output: Output<D>,
}

impl<D: Digest> DomainSeparatedHash<D> {
    // This constructor is intentionally private. It should be impossible to create an instance of this struct without
    // the guarantees that the data represents a hash containing the domain separation label provided in `M`
    fn new(output: Output<D>) -> Self {
        Self { output }
    }
}

impl<D: Digest> AsRef<[u8]> for DomainSeparatedHash<D> {
    fn as_ref(&self) -> &[u8] {
        self.output.as_slice()
    }
}

//--------------------------------------    Domain Separated Hasher  ---------------------------------------------------

/// A wrapper for hash digest algorithms that produces [`DomainSeparatedHash`] instances.
///
/// The [module documentation](crate::hashing) has details on why this is helpful.
///
/// The API tries to be as helpful and unobtrusive as possible. Firstly, domain tags have several levels of granularity.
/// 1. The version number is fixed for a given schema of the domain tag.
/// 2. The domain represents a broad class of use cases for the hashing, e.g. MACs, or key derivation.
/// 3. The label is used to differentiate different applications of a use case. e.g. there might be two places key
/// derivation is used in your application: for wallet derived keys, and communication derived keys. These might have
/// the label "wallet-key" and "comms-key" respectively.
///
/// [`DomainSeparatedHasher`] is useful for more generic use-cases that aren't covered by the two primary use cases
/// covered in this API (MAcs and key derivation).
///
/// ## Examples
///
/// Using a hash as an object ID, based on the fields of the object.
///
/// ```
/// # use sha2::Sha256;
/// # use tari_crypto::hashing::{DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation, GenericHashDomain};
/// # use tari_utilities::hex::{to_hex, Hex};
///
/// struct Card {
///     name: &'static str,
///     strength: u8,
/// }
///
/// fn card_id(card: &Card) -> DomainSeparatedHash<Sha256> {
///     DomainSeparatedHasher::<Sha256, GenericHashDomain>::new("card_id")
///         .chain(card.name.as_bytes())
///         .chain(&[card.strength])
///         .finalize()
/// }
///
/// assert_eq!(GenericHashDomain::domain_separation_tag("card_id"), "com.tari.generic.v1.card_id");
/// let card = Card {
///     name: "Rincewind",
///     strength: 8,
/// };
///
/// let id = card_id(&card);
/// assert_eq!(
///     to_hex(id.as_ref()),
///     "44fb39bfdd20c93ddf542e4b2d1f4b06448aa1fa2b9c4d138d8e7bbb19aa7c65"
/// );
/// ```
///
/// Calculating a signature challenge
///
/// ```
/// # use tari_utilities::hex::{to_hex, Hex};
/// use tari_crypto::{
///     hash::blake2::Blake256,
///     hashing::{DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation, GenericHashDomain},
/// };
///
/// struct Card {
///     name: &'static str,
///     strength: u8,
/// }
///
/// fn calculate_challenge(msg: &str) -> DomainSeparatedHash<Blake256> {
///     DomainSeparatedHasher::<Blake256, GenericHashDomain>::new("schnorr_challenge")
///         .chain(msg.as_bytes())
///         .finalize()
/// }
///
/// assert_eq!(
///     GenericHashDomain::domain_separation_tag("schnorr_challenge"),
///     "com.tari.generic.v1.schnorr_challenge"
/// );
/// let challenge = calculate_challenge("All is well.");
/// assert_eq!(
///     to_hex(challenge.as_ref()),
///     "6cd8efe7d7f1673ed8cfc0ac67d6979eb50afdbf276adf5221caabfbfd01da8c"
/// );
/// ```
#[derive(Debug, Clone, Default)]
pub struct DomainSeparatedHasher<D, M> {
    inner: D,
    _dst: PhantomData<M>,
}

impl<D: Digest, M: DomainSeparation> DomainSeparatedHasher<D, M> {
    /// Create a new instance of [`DomainSeparatedHasher`] for the given label.
    pub fn new<S>(label: S) -> Self
    where S: AsRef<[u8]> {
        let mut inner = D::new();
        M::add_domain_separation_tag(&mut inner, label);
        Self {
            inner,
            _dst: PhantomData,
        }
    }

    /// Adds the data to the digest function by first appending the length of the data in the byte array, and then
    /// supplying the data itself.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let len = (data.as_ref().len() as u64).to_le_bytes();
        self.inner.update(len);
        self.inner.update(data);
    }

    /// Does the same thing as [`Self::update`], but returns the hasher instance to support fluent syntax.
    #[must_use]
    pub fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
        self.update(data);
        self
    }

    /// Finalize the hasher and return the hash result.
    pub fn finalize(self) -> DomainSeparatedHash<D> {
        let output = self.inner.finalize();
        DomainSeparatedHash::new(output)
    }
}

//-----------------------------------------    Generic Hash Domain  ----------------------------------------------------
/// A domain separation marker for use in general use cases.
pub struct GenericHashDomain;

impl DomainSeparation for GenericHashDomain {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.generic"
    }
}

//----------------------------------------       Extra marker traits      ----------------------------------------------

/// A marker trait for Digest algorithms that are not susceptible to length-extension attacks.
///
/// Notably, the SHA-2 family does *not* have this trait.
pub trait LengthExtensionAttackResistant {}

impl LengthExtensionAttackResistant for Blake256 {}

impl LengthExtensionAttackResistant for VarBlake2b {}

impl LengthExtensionAttackResistant for Sha3_256 {}

//------------------------------------------------    HMAC  ------------------------------------------------------------
/// A domain separation tag for use in MAC derivation algorithms.
pub struct MacDomain;

impl DomainSeparation for MacDomain {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.mac"
    }
}

/// A domain separated MAC using a simple approach to code derivation.
///
/// The MAC is a hash of `H(domain, key, message)` but some safeguards are in place:
/// - Only digest functions that are resistant to length extension attacks are permitted.
/// - The hash function uses a suitable domain separation strategy, with a user-provided label.
/// - The key and message are encoded along with their length
///
/// # Examples
///
/// You cannot use a vulnerable digest function to generate a MAC:
/// ```text
/// use sha2::Sha256;
/// let _ = Mac::generate::<Sha256, _, _>(b"secret key", "a message", "invalid digest");
///         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the trait `LengthExtensionAttackResistant` is not implemented for `Sha256`
/// ```
///
/// ```
/// use sha3::Sha3_256;
/// use tari_crypto::hashing::{DomainSeparation, Mac, MacDomain};
/// use tari_utilities::hex::to_hex;
///
/// fn generate_api_hmac(key: &[u8], msg: &[u8]) -> Mac<Sha3_256> {
///     Mac::<Sha3_256>::generate(key, msg, "api.auth")
/// }
///
/// assert_eq!(MacDomain::domain_separation_tag("api.auth"), "com.tari.mac.v1.api.auth");
/// let mac = generate_api_hmac(b"a secret shared key", b"a message");
/// assert_eq!(
///     to_hex(mac.as_ref()),
///     "796eb496b6672b1b7c4021e603d6b833121d35cd282a1555e3f9dd2eda5658b8"
/// );
/// ```
pub struct Mac<D: Digest> {
    hmac: DomainSeparatedHash<D>,
}

impl<D> Mac<D>
where D: Digest + Update + LengthExtensionAttackResistant
{
    /// Generate a MAC with the given (length extension attack resistant) digest function, shared key, message and
    /// application label.
    pub fn generate<K, S>(key: K, msg: S, label: &str) -> Self
    where
        K: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let hmac = DomainSeparatedHasher::<D, MacDomain>::new(label)
            .chain(key.as_ref())
            .chain(msg.as_ref())
            .finalize();
        Self { hmac }
    }
}

impl<D: Digest> Deref for Mac<D> {
    type Target = DomainSeparatedHash<D>;

    fn deref(&self) -> &Self::Target {
        &self.hmac
    }
}

//------------------------------------------------     KDF  ------------------------------------------------------------

/// `DerivedKeyDomain` is a trait that allows one to safely and easily derive a secondary keys from a primary key.
///
/// For this algorithm to be secure, the primary key must have sufficient entropy, which we cannot check in general.
/// However, a necessary condition is that the primary key must be at least as long as the desired derived key.
///
/// That is to say, this algorithm is _not_ the same as password-based kdf, which uses
/// strategies like key stretching to derive a key from a low entropy input such as a short text password.
/// For this, use algorithms like argon2, pbkdf2, or scrypt instead.
///
/// Constraints:
/// * the length of `key` MUST be at least as long as the output size of the hash function being used (`D`).
/// * The digest output length MUST provide enough data to produce the desired SecretKey type.
///
/// ## Example
///
/// [`RistrettoKdf`] is an implementation of [`DerivedKeyDomain`] that generates Ristretto keys.
///
/// ```
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
/// # use tari_crypto::hash::blake2::Blake256;
/// # use tari_crypto::errors::HashingError;
/// # use tari_crypto::hashing::{DerivedKeyDomain, MacDomain};
/// # use tari_crypto::keys::SecretKey;
/// # use tari_crypto::ristretto::ristretto_keys::RistrettoKdf;
/// # use tari_crypto::ristretto::RistrettoSecretKey;
///
/// fn wallet_keys(primary_key: &RistrettoSecretKey, index: usize) -> Result<RistrettoSecretKey, HashingError> {
///     RistrettoKdf::generate::<Blake256, _>(primary_key.as_bytes(), &index.to_le_bytes(), "wallet")
/// }
///
/// let key = RistrettoSecretKey::from_hex("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c").unwrap();
/// let key_1 = wallet_keys(&key, 1).unwrap();
/// assert_eq!(
///     key_1.to_hex(),
///     "b778b8b5041fbde6c78be5bafd6d62633824bf303c97736d7337b3f6f70c4e0b"
/// );
/// let key_64 = wallet_keys(&key, 64).unwrap();
/// assert_eq!(
///     key_64.to_hex(),
///     "09e5204c93406ef3334ff5f7a4d5d84199ceb9119fafcb98928fa95e95f0ae05"
/// );
/// ```
pub trait DerivedKeyDomain: DomainSeparation {
    /// The associated derived secret key type
    type DerivedKeyType: SecretKey;

    /// Derive a key from the input key using a suitable domain separation tag and the given application label.
    /// An error is returned if the supplied primary key isn't at least as long as the digest algorithm's output size.
    /// If the digest's output size is not sufficient to generate the derived key type, then an error will be thrown.
    fn generate<D, S>(primary_key: &[u8], data: &[u8], label: S) -> Result<Self::DerivedKeyType, HashingError>
    where
        Self: Sized,
        D: Digest + Update,
        S: AsRef<[u8]>,
    {
        if primary_key.as_ref().len() < D::output_size() {
            return Err(HashingError::InputTooShort);
        }
        let hash = DomainSeparatedHasher::<D, Self>::new(label)
            .chain(primary_key)
            .chain(data)
            .finalize();
        let derived_key = Self::DerivedKeyType::from_bytes(hash.as_ref())?;
        Ok(derived_key)
    }
}

#[cfg(test)]
mod test {
    use blake2::Blake2b;
    use digest::Digest;
    use tari_utilities::hex::{from_hex, to_hex};

    use crate::{
        hash::blake2::Blake256,
        hashing::{
            byte_to_decimal_ascii_bytes,
            DomainSeparatedHasher,
            DomainSeparation,
            GenericHashDomain,
            Mac,
            MacDomain,
        },
    };

    #[test]
    // Regression test
    fn mac_domain_metadata() {
        assert_eq!(MacDomain::version(), 1);
        assert_eq!(MacDomain::domain(), "com.tari.mac");
        assert_eq!(MacDomain::domain_separation_tag("test"), "com.tari.mac.v1.test");
    }

    #[test]
    fn dst_hasher() {
        let hash = DomainSeparatedHasher::<Blake256, GenericHashDomain>::new("test_hasher")
            .chain("some foo")
            .finalize();
        let mut hash2 = DomainSeparatedHasher::<Blake256, GenericHashDomain>::new("test_hasher");
        hash2.update("some foo");
        let hash2 = hash2.finalize();
        assert_eq!(hash.as_ref(), hash2.as_ref());
        assert_eq!(
            to_hex(hash.as_ref()),
            "a8326620e305430a0b632a0a5e33c6c1124d7513b4bd84736faaa3a0b9ba557f"
        );
    }

    #[test]
    fn deconstruction() {
        // Illustrate exactly what gets hashed and how we try and avoid collisions
        let hash = DomainSeparatedHasher::<Blake256, GenericHashDomain>::new("mytest")
            .chain("rincewind")
            .chain("hex")
            .finalize();
        let expected = Blake256::new()
            .chain(26u64.to_le_bytes())
            .chain("com.tari.generic.v1.mytest".as_bytes())
            .chain(9u64.to_le_bytes())
            .chain("rincewind".as_bytes())
            .chain(3u64.to_le_bytes())
            .chain("hex".as_bytes())
            .finalize();
        assert_eq!(hash.as_ref(), expected.as_slice());
    }

    #[test]
    fn domain_separation_tag_hashing() {
        struct MyDemoHasher;

        impl DomainSeparation for MyDemoHasher {
            fn version() -> u8 {
                42
            }

            fn domain() -> &'static str {
                "com.discworld"
            }
        }
        let domain = "com.discworld.v42.turtles";
        assert_eq!(MyDemoHasher::domain_separation_tag("turtles"), domain);
        let hash = DomainSeparatedHasher::<Blake2b, MyDemoHasher>::new("turtles").finalize();
        let expected = Blake2b::default()
            .chain((domain.len() as u64).to_le_bytes())
            .chain(domain)
            .finalize();
        assert_eq!(hash.as_ref(), expected.as_ref());
    }

    #[test]
    fn update_domain_separation_tag() {
        let s_tag = GenericHashDomain::domain_separation_tag("mytest");
        let expected_hash = Blake256::new()
            .chain((s_tag.len() as usize).to_le_bytes())
            .chain(s_tag)
            .finalize();

        let mut digest = Blake256::new();
        GenericHashDomain::add_domain_separation_tag(&mut digest, "mytest");
        assert_eq!(digest.finalize(), expected_hash);
    }

    #[test]
    fn application_hasher() {
        struct MyDemoHasher;

        impl DomainSeparation for MyDemoHasher {
            fn version() -> u8 {
                42
            }

            fn domain() -> &'static str {
                "com.discworld"
            }
        }
        let hash = DomainSeparatedHasher::<Blake2b, MyDemoHasher>::new("turtles")
            .chain("elephants")
            .finalize();
        assert_eq!(to_hex(hash.as_ref()), "64a89c7160a1076a725fac97d3f67803abd0991d82518a595072fa62df4c870bddee9160f591231c381087831bf6925616013de317ce0b02846585caf41942ac");
    }

    #[test]
    fn incompatible_tags() {
        // The compiler won't even let you write these tests :), so they're commented out.
        let key = from_hex("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c").unwrap();
        // let mac = Mac::generate::<Sha256, _, _>(&key, "test message", "test");
        //          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the trait `LengthExtensionAttackResistant` is not implemented for
        //          `Sha256`
        let mac = Mac::<Blake256>::generate(&key, "test message", "test");
        assert_eq!(MacDomain::domain_separation_tag("test"), "com.tari.mac.v1.test");
        assert_eq!(
            to_hex(mac.as_ref()),
            "9bcfbe2bad73b14ac42f673ddca34e82ce03cbbac69d34526004f5d108dff061"
        )
    }

    #[test]
    fn check_bytes_to_decimal_ascii_bytes() {
        assert_eq!(byte_to_decimal_ascii_bytes(0), (2, [0u8, 0, 48]));
        assert_eq!(byte_to_decimal_ascii_bytes(42), (1, [0u8, 52, 50]));
        assert_eq!(byte_to_decimal_ascii_bytes(255), (0, [50u8, 53, 53]));
    }
}
