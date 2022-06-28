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
use digest::Digest;
use sha3::Sha3_256;
use tari_utilities::ByteArray;

use crate::{common::Blake256, errors::HashingError, keys::SecretKey};

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
}

//--------------------------------------     Domain Separated Hash   ---------------------------------------------------

/// A hash value, guaranteed, as far as possible, to have been created using a hash function that has been randomly and
/// independently sampled from an idealized set of hash functions.
///
/// This is modelled via the strategy of applying a
/// domain separation tag that is unique for this hashing application (assuming clients make proper use of a unique
/// label for every discrete hashing use-case in their applications).
///
/// `DomainSeparatedHash` implements `AsRef<u8>`, so it is easy to use this type as a slice, or you can discard the
/// domain tag by calling [`DomainSeparatedHash::into_vec`].
///
/// The domain separation information is retained with the hash, and can be queried using
/// [`DomainSeparatedHash::domain_separation_tag`].
///
/// To preserve the guarantee that the hash is properly domain separated, you cannot create an instance of this struct
/// directly. It is the result of using [`DomainSeparatedHasher`].
///
/// For details and examples, see [`DomainSeparatedHasher`].
pub struct DomainSeparatedHash {
    hash: Vec<u8>,
    tag: String,
}

impl DomainSeparatedHash {
    // This constructor is intentionally private. It should be impossible to create an instance of this struct without
    // the guarantees that the data represents a hash containing the domain separation label provided in `M`
    fn new(hash: Vec<u8>, tag: String) -> Self {
        Self { hash, tag }
    }

    /// Return the full string, including the label used as the domain separation tag for this hash
    pub fn domain_separation_tag(&self) -> &str {
        self.tag.as_str()
    }

    /// Convert the hash into a byte vector. This operation consumes `self`, so the domain information will be
    /// discarded.
    pub fn into_vec(self) -> Vec<u8> {
        self.hash
    }
}

impl AsRef<[u8]> for DomainSeparatedHash {
    fn as_ref(&self) -> &[u8] {
        self.hash.as_slice()
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
/// use sha2::Sha256;
/// use tari_crypto::hashing::{DomainSeparatedHash, DomainSeparatedHasher, GenericHashDomain};
/// use tari_utilities::hex::{to_hex, Hex};
/// struct Card {
///     name: &'static str,
///     strength: u8,
/// }
///
/// fn card_id(card: &Card) -> DomainSeparatedHash {
///     DomainSeparatedHasher::<Sha256, GenericHashDomain>::new("card_id")
///         .chain(card.name.as_bytes())
///         .chain(&[card.strength])
///         .finalize()
/// }
///
/// let card = Card {
///     name: "Rincewind",
///     strength: 8,
/// };
///
/// let id = card_id(&card);
/// assert_eq!(id.domain_separation_tag(), "com.tari.generic.v1.card_id");
/// assert_eq!(
///     to_hex(id.as_ref()),
///     "597a73459101ebc5b56545f98bf0c93b1631844b0ff6b13f0123d796c5159a16"
/// );
/// ```
///
/// Calculating a signature challenge
///
/// ```
/// use tari_crypto::{
///     common::Blake256,
///     hashing::{DomainSeparatedHash, DomainSeparatedHasher, GenericHashDomain},
/// };
/// use tari_utilities::hex::{to_hex, Hex};
/// struct Card {
///     name: &'static str,
///     strength: u8,
/// }
///
/// fn calculate_challenge(msg: &str) -> DomainSeparatedHash {
///     DomainSeparatedHasher::<Blake256, GenericHashDomain>::new("schnorr_challenge")
///         .chain(msg.as_bytes())
///         .finalize()
/// }
///
/// let challenge = calculate_challenge("All is well.");
/// assert_eq!(
///     challenge.domain_separation_tag(),
///     "com.tari.generic.v1.schnorr_challenge"
/// );
/// assert_eq!(
///     to_hex(challenge.as_ref()),
///     "f358c075dd820679905447f27a4cf771c2aca91d3985a3f90b54dd2f8d025c47"
/// );
/// ```
pub struct DomainSeparatedHasher<D, M> {
    inner: D,
    label: String,
    dst: PhantomData<M>,
}

impl<D: Digest, M: DomainSeparation> DomainSeparatedHasher<D, M> {
    pub fn new<S>(label: S) -> Self
    where S: AsRef<str> {
        let inner = D::new().chain(M::domain_separation_tag(&label).as_bytes());
        Self {
            inner,
            label: label.as_ref().to_string(),
            dst: PhantomData::<M>::default(),
        }
    }

    /// Adds the data to the digest function by first appending the length of the data in the byte array, and then
    /// supplying the data itself.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.inner.update(data.as_ref().len().to_le_bytes());
        self.inner.update(data);
    }

    /// Does the same thing as [`Self::update`], but returns the hasher instance to support fluent syntax.
    #[must_use]
    pub fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
        self.update(data);
        self
    }

    /// Finalize the hasher and return the hash result.
    pub fn finalize(self) -> DomainSeparatedHash {
        let hash = self.inner.finalize().to_vec();
        let tag = M::domain_separation_tag(self.label);
        DomainSeparatedHash::new(hash, tag)
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
/// use tari_crypto::hashing::Mac;
/// use tari_utilities::hex::to_hex;
///
/// fn generate_api_hmac(key: &[u8], msg: &[u8]) -> Mac {
///     Mac::generate::<Sha3_256, _, _>(key, msg, "api.auth")
/// }
///
/// let mac = generate_api_hmac(b"a secret shared key", b"a message");
/// assert_eq!(mac.domain_separation_tag(), "com.tari.mac.v1.api.auth");
/// assert_eq!(
///     to_hex(mac.as_ref()),
///     "9d36cc40c9e4831efbdd1cd4305fe78bd014b30abd47ae752bf6c15da8644443"
/// );
/// ```
pub struct Mac {
    hmac: DomainSeparatedHash,
}

impl Mac {
    /// Generate a MAC with the given (length extension attack resistant) digest function, shared key, message and
    /// application label.
    pub fn generate<D, K, S>(key: K, msg: S, label: &str) -> Self
    where
        D: Digest + LengthExtensionAttackResistant,
        K: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let hmac = DomainSeparatedHasher::<D, MacDomain>::new(label)
            .chain(key.as_ref())
            .chain(msg.as_ref())
            .finalize();
        Self { hmac }
    }

    /// Consume the MAC type and convert it into a raw byte vector. The domain separation information is discarded.
    pub fn into_vec(self) -> Vec<u8> {
        self.hmac.into_vec()
    }
}

impl Deref for Mac {
    type Target = DomainSeparatedHash;

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
/// # use tari_crypto::common::Blake256;
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
///     "be4b10a3f6669b04c840c34a36312fa6f54df858d1b8a4ea46a7a9e82be2670e"
/// );
/// let key_64 = wallet_keys(&key, 64).unwrap();
/// assert_eq!(
///     key_64.to_hex(),
///     "5c3c8fda79509681caa267bfdad872b912307c0b2bc49a317de534839ee3c60d"
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
        D: Digest,
        S: AsRef<str>,
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
    use tari_utilities::hex::{from_hex, to_hex};

    use crate::{
        common::Blake256,
        hashing::{DomainSeparatedHasher, DomainSeparation, GenericHashDomain, Mac, MacDomain},
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
        assert_eq!(hash.domain_separation_tag(), "com.tari.generic.v1.test_hasher");
        assert_eq!(hash2.domain_separation_tag(), "com.tari.generic.v1.test_hasher");
        assert_eq!(hash.as_ref(), hash2.as_ref());
        assert_eq!(
            to_hex(hash.as_ref()),
            "9ec75b89b25f4c63eb39c717867b4330b66b612cc7c35d698612c9caeda4b281"
        );
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
        assert_eq!(hash.domain_separation_tag(), "com.discworld.v42.turtles");
        assert_eq!(to_hex(hash.as_ref()), "b3a7c29cfb9d9ef1a7cc78015fce04ee43c8448f8d928083ddcdc177d1345e84fc9bfdd9b7120c4d0a23e9d07b1d3a5a552aa11e3e45261dd3e303e879794120");
    }

    #[test]
    fn incompatible_tags() {
        // The compiler won't even let you write these tests :), so they're commented out.
        let key = from_hex("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c").unwrap();
        // let mac = Mac::generate::<Sha256, _, _>(&key, "test message", "test");
        //          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the trait `LengthExtensionAttackResistant` is not implemented for
        //          `Sha256`
        let mac = Mac::generate::<Blake256, _, _>(&key, "test message", "test");
        assert_eq!(mac.domain_separation_tag(), "com.tari.mac.v1.test");
        assert_eq!(
            to_hex(mac.as_ref()),
            "12be06eab67794f1a53dd724c0b4bc72dbefcac0f081685b576e511c0b1419d0"
        )
    }
}
