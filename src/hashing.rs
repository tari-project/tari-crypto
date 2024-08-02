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

use core::{marker::PhantomData, ops::Deref};

use blake2::{Blake2b, Blake2bVar};
use digest::{
    consts::{U32, U64},
    Digest,
    FixedOutput,
    FixedOutputReset,
    Output,
    OutputSizeUser,
    Update,
};
use sha3::Sha3_256;

use crate::{
    alloc::string::ToString,
    errors::{HashingError, SliceError},
    keys::SecretKey,
};

/// An enumeration specifying tags used by hashers.
/// Tags prepend anything included as hasher input.
///
/// The idea is that when putting input into a hasher, we include several things:
/// - A tag indicating the input type, encoded as a byte
/// - If the input is of variable length (determined by the type), a little-endian 64-bit encoding of the length
/// - The input, encoded as bytes
///
/// By doing so, we mitigate the risk of collision.
///
/// These are not exposed to the user; they are used internally only.
#[repr(u8)]
enum Tag {
    /// An initial domain separator indicating the general purpose of the hasher
    DomainSeparator = 0,
    /// The version of the hasher, which MUST be a single byte
    Version = 1,
    /// A label that can be used to differentiate specific uses of the hasher
    Label = 2,
    /// Arbitrary byte data to be added to the hasher, such as via `update` or `chain`
    Data = 3,
}

/// The `DomainSeparation` trait is used to inject domain separation tags into the [`DomainSeparatedHasher`] in a
/// way that can be applied consistently, but without hard-coding anything into the hasher itself.
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

    /// Performs complete domain separation by including a domain separator, version, and (optional) label.
    fn add_domain_separation_tag<S: AsRef<[u8]>, D: Digest>(digest: &mut D, label: Option<S>) {
        // Domain separator
        let domain_bytes = Self::domain().as_bytes();
        let domain_length = domain_bytes.len() as u64;
        digest.update([Tag::DomainSeparator as u8]);
        digest.update(domain_length.to_le_bytes());
        digest.update(domain_bytes);

        // Version; this is of fixed length, so we don't need to use length prepending
        digest.update([Tag::Version as u8]);
        digest.update([Self::version()]);

        // Optional label
        if let Some(label) = label {
            let label_length = label.as_ref().len() as u64;
            digest.update([Tag::Label as u8]);
            digest.update(label_length.to_le_bytes());
            digest.update(label);
        }
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
/// `DomainSeparatedHash` implements `AsRef<u8>`, so it is easy to use this type as a slice.
///
/// The domain separation information is retained with the hash, and can be queried using
/// [`DomainSeparatedHash::domain_separation_tag("<tag>")`].
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
///    derivation is used in your application: for wallet derived keys, and communication derived keys. These might have
///    the label "wallet-key" and "comms-key" respectively.
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
/// # use tari_crypto::{hash_domain, hashing::{ DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation}};
/// # use tari_utilities::hex::{to_hex, Hex};
/// # use blake2::Blake2b;
///
/// hash_domain!(CardHashDomain, "com.cards");
///
/// struct Card {
///     name: &'static str,
///     strength: u8,
/// }
///
/// fn card_id(card: &Card) -> DomainSeparatedHash<Sha256> {
///     DomainSeparatedHasher::<Sha256, CardHashDomain>::new_with_label("card_id")
///         .chain(card.name.as_bytes())
///         .chain(&[card.strength])
///         .finalize()
/// }
///
/// assert_eq!(CardHashDomain::domain_separation_tag(""), "com.cards.v1");
/// assert_eq!(CardHashDomain::domain_separation_tag("card_id"), "com.cards.v1.card_id");
/// let card = Card {
///     name: "Rincewind",
///     strength: 8,
/// };
///
/// let id = card_id(&card);
/// assert_eq!(
///     to_hex(id.as_ref()),
///     "b6d1ccd5e6e7eacedd5f3382b8567878419163257f4910f1f9f6265281b836ec"
/// );
/// ```
///
/// Calculating a signature challenge
///
/// ```
/// # use blake2::Blake2b;
/// # use digest::{consts::U32, Digest};
/// # use tari_utilities::hex::{to_hex, Hex};
/// # use tari_crypto::{
///     hash_domain,
///     hashing::{DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation},
/// };
///
/// hash_domain!(CardHashDomain, "com.cards");
///
/// struct Card {
///     name: &'static str,
///     strength: u8,
/// }
///
/// fn calculate_challenge(msg: &str) -> DomainSeparatedHash<Blake2b<U32>> {
///     DomainSeparatedHasher::<Blake2b<U32>, CardHashDomain>::new_with_label("schnorr_challenge")
///         .chain_update(msg.as_bytes())
///         .finalize()
/// }
///
/// assert_eq!(
///     CardHashDomain::domain_separation_tag("schnorr_challenge"),
///     "com.cards.v1.schnorr_challenge"
/// );
/// let challenge = calculate_challenge("All is well.");
/// assert_eq!(
///     to_hex(challenge.as_ref()),
///     "c84b95fd7134ef3e717fe9aece1de46fa88e13ee9f1eaa2e473263d27137bc87"
/// );
/// ```
#[derive(Debug, Clone, Default)]
pub struct DomainSeparatedHasher<D, M> {
    inner: D,
    label: Option<&'static str>,
    _dst: PhantomData<M>,
}

impl<D: Digest, M: DomainSeparation> DomainSeparatedHasher<D, M> {
    /// Create a new instance of [`DomainSeparatedHasher`] without an additional label (to correspond to 'D::new()').
    /// If you want a label, use `new_with_label` instead.
    pub fn new() -> Self {
        Self::new_internal(None)
    }

    /// Create a new instance of [`DomainSeparatedHasher`] for the given label.
    /// You can use the label to indicate a specific use case for a hasher.
    /// If you don't want a label, don't simply pass an empty string; use `new` instead, which is safer.
    pub fn new_with_label(label: &'static str) -> Self {
        Self::new_internal(Some(label))
    }

    // Helper function that actually instantiates the hasher, handling the optional label.
    fn new_internal(label: Option<&'static str>) -> Self {
        let mut inner = D::new();
        M::add_domain_separation_tag(&mut inner, label);
        Self {
            inner,
            label,
            _dst: PhantomData,
        }
    }

    /// Adds the data to the digest function.
    /// This is done safely in a manner that prevents collisions.
    ///
    /// NOTE: The way this is done might not match what you expect.
    /// In particular, chaining updates is not the same as a single update with concatenated data.
    /// This is intentional, but could lead to unexpected behavior if you're not careful.
    /// You should make sure that you don't rely on this, and always update the hasher the same way!
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let data_length = (data.as_ref().len() as u64).to_le_bytes();
        self.inner.update([Tag::Data as u8]);
        self.inner.update(data_length);
        self.inner.update(data);
    }

    /// Does the same thing as [`Self::update`], but returns the hasher instance to support fluent syntax.
    ///
    /// NOTE: The way this is done might not match what you expect.
    /// In particular, chaining updates is not the same as a single update with concatenated data.
    /// This is intentional, but could lead to unexpected behavior if you're not careful.
    /// You should make sure that you don't rely on this, and always update the hasher the same way!
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

    /// A convenience function to update, then finalize the hasher and return the hash result.
    pub fn digest(mut self, data: &[u8]) -> DomainSeparatedHash<D> {
        self.update(data);
        self.finalize()
    }
}

impl<D: Digest, M: DomainSeparation> PartialEq for DomainSeparatedHasher<D, M> {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
    }
}

impl<D: Digest, M: DomainSeparation> Eq for DomainSeparatedHasher<D, M> {}

/// Convert a finalized hash into a fixed size buffer.
pub trait AsFixedBytes<const I: usize>: AsRef<[u8]> {
    /// A convenience function to convert a finalized hash into a fixed size buffer.
    fn as_fixed_bytes(&self) -> Result<[u8; I], SliceError> {
        let hash_vec = self.as_ref();
        if hash_vec.is_empty() || hash_vec.len() < I {
            let hash_vec_length = if hash_vec.is_empty() { 0 } else { hash_vec.len() };
            return Err(SliceError::CopyFromSlice {
                target: I,
                provided: hash_vec_length,
            });
        }
        let mut buffer: [u8; I] = [0; I];
        buffer.copy_from_slice(&hash_vec[..I]);
        Ok(buffer)
    }
}

impl<TInnerDigest: OutputSizeUser, TDomain: DomainSeparation> OutputSizeUser
    for DomainSeparatedHasher<TInnerDigest, TDomain>
{
    type OutputSize = TInnerDigest::OutputSize;
}

impl<TInnerDigest: Update, TDomain: DomainSeparation> Update for DomainSeparatedHasher<TInnerDigest, TDomain> {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
}

impl<const I: usize, D: Digest> AsFixedBytes<I> for DomainSeparatedHash<D> {}

impl<TInnerDigest: FixedOutput, TDomain: DomainSeparation> FixedOutput
    for DomainSeparatedHasher<TInnerDigest, TDomain>
{
    fn finalize_into(self, out: &mut Output<Self>) {
        self.inner.finalize_into(out);
    }
}

impl<D: FixedOutputReset, M: DomainSeparation> DomainSeparatedHasher<D, M> {
    /// Finalize and reset the hasher and return the hash result.
    pub fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        self.inner.finalize_into_reset(out);
    }
}

// Implements Digest so that it can be used for other crates
impl<TInnerDigest: Digest + FixedOutputReset, TDomain: DomainSeparation> Digest
    for DomainSeparatedHasher<TInnerDigest, TDomain>
{
    fn new() -> Self {
        DomainSeparatedHasher::<TInnerDigest, TDomain>::new()
    }

    // Create new hasher instance which has processed the provided data.
    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        let hasher = DomainSeparatedHasher::<TInnerDigest, TDomain>::new();
        hasher.chain_update(data)
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update(data);
    }

    fn chain_update(self, data: impl AsRef<[u8]>) -> Self
    where Self: Sized {
        self.chain(data)
    }

    fn finalize(self) -> Output<Self> {
        self.finalize().output
    }

    fn finalize_reset(&mut self) -> Output<Self> {
        let value = self.inner.finalize_reset();
        TDomain::add_domain_separation_tag(&mut self.inner, self.label);
        value
    }

    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        Digest::finalize_into_reset(&mut self.inner, out);
    }

    // Write result into provided array and consume the hasher instance.
    fn finalize_into(self, out: &mut Output<Self>) {
        Digest::finalize_into(self.inner, out);
    }

    fn reset(&mut self) {
        Digest::reset(&mut self.inner);
        TDomain::add_domain_separation_tag(&mut self.inner, self.label);
    }

    fn output_size() -> usize {
        <TInnerDigest as Digest>::output_size()
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize().output
    }
}

//----------------------------------------       Extra marker traits      ----------------------------------------------

/// A marker trait for Digest algorithms that are not susceptible to length-extension attacks.
///
/// Notably, the SHA-2 family does *not* have this trait.
pub trait LengthExtensionAttackResistant {}

impl LengthExtensionAttackResistant for Blake2bVar {}

impl LengthExtensionAttackResistant for Sha3_256 {}

impl LengthExtensionAttackResistant for Blake2b<U32> {}

impl LengthExtensionAttackResistant for Blake2b<U64> {}

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
/// assert_eq!(
///     MacDomain::domain_separation_tag("api.auth"),
///     "com.tari.mac.v1.api.auth"
/// );
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
    pub fn generate<K, S>(key: K, msg: S, label: &'static str) -> Self
    where
        K: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let hmac = DomainSeparatedHasher::<D, MacDomain>::new_with_label(label)
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
/// `RistrettoKdf` is an implementation of [`DerivedKeyDomain`] that generates Ristretto keys.
///
/// ```
/// # use blake2::Blake2b;
/// # use digest::{consts::U64, Digest};
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
/// # use tari_crypto::errors::HashingError;
/// # use tari_crypto::hashing::{DerivedKeyDomain, MacDomain};
/// # use tari_crypto::keys::SecretKey;
/// # use tari_crypto::ristretto::ristretto_keys::RistrettoKdf;
/// # use tari_crypto::ristretto::RistrettoSecretKey;
///
/// fn wallet_keys(
///     primary_key: &RistrettoSecretKey,
///     index: usize,
/// ) -> Result<RistrettoSecretKey, HashingError> {
///     RistrettoKdf::generate::<Blake2b<U64>>(
///         primary_key.as_bytes(),
///         &index.to_le_bytes(),
///         "wallet",
///     )
/// }
///
/// let key = RistrettoSecretKey::from_hex(
///     "a8fb609c5ab7cc07548b076b6c25cc3237c4526fb7a6dcb83b26f457b172c20a",
/// )
/// .unwrap();
/// let key_1 = wallet_keys(&key, 1).unwrap();
/// assert_eq!(
///     key_1.to_hex(),
///     "08106b88a2ff4c52d1d8b458cf34802df8655ba989a7d91351e3504e087a2e0c"
/// );
/// let key_64 = wallet_keys(&key, 64).unwrap();
/// assert_eq!(
///     key_64.to_hex(),
///     "2c2206dadd2a21e71b6c52dd321572cde0f2b00e7116e1123fb580b09ed1b70e"
/// );
/// ```
pub trait DerivedKeyDomain: DomainSeparation {
    /// The associated derived secret key type
    type DerivedKeyType: SecretKey;

    /// Derive a key from the input key using a suitable domain separation tag and the given application label by wide
    /// reduction. An error is returned if the supplied primary key isn't at least as long as the derived key.
    /// If the digest's output size is not sufficient to generate the derived key type, then an error will be thrown.
    fn generate<D>(primary_key: &[u8], data: &[u8], label: &'static str) -> Result<Self::DerivedKeyType, HashingError>
    where
        Self: Sized,
        D: Digest + Update,
    {
        // Ensure the primary key is at least as long as the derived key
        if primary_key.len() < <Self::DerivedKeyType as SecretKey>::KEY_LEN {
            return Err(HashingError::InputTooShort {});
        }

        // Ensure the digest length is suitable for wide reduction
        if <D as Digest>::output_size() != <Self::DerivedKeyType as SecretKey>::WIDE_REDUCTION_LEN {
            return Err(HashingError::InputTooShort {});
        }

        let hash = DomainSeparatedHasher::<D, Self>::new_with_label(label)
            .chain(primary_key)
            .chain(data)
            .finalize();
        let derived_key = Self::DerivedKeyType::from_uniform_bytes(hash.as_ref())
            .map_err(|e| HashingError::ConversionFromBytes { reason: e.to_string() })?;
        Ok(derived_key)
    }
}

/// Creates a DomainSeparation struct for a given domain.
#[macro_export]
macro_rules! hash_domain {
    ($name:ident, $domain:expr, $version: expr) => {
        /// A hashing domain instance
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name;

        impl $crate::hashing::DomainSeparation for $name {
            fn version() -> u8 {
                $version
            }

            fn domain() -> &'static str {
                $domain
            }
        }
    };
    ($name:ident, $domain:expr) => {
        hash_domain!($name, $domain, 1);
    };
}

/// Creates a domain separated hasher type and domain in one
#[macro_export]
macro_rules! hasher {
    ($digest:ty, $name:ident, $domain:expr, $version: expr, $mod_name:ident) => {
        mod $mod_name {
            use $crate::hash_domain;

            hash_domain!(__HashDomain, $domain, $version);
        }
        pub type $name = $crate::hashing::DomainSeparatedHasher<$digest, $mod_name::__HashDomain>;
    };
    ($digest: ty, $name:ident, $domain:expr, $version: expr) => {
        hasher!($digest, $name, $domain, $version, __inner_hasher_impl);
    };
    ($digest: ty, $name:ident, $domain:expr) => {
        hasher!($digest, $name, $domain, 1, __inner_hasher_impl);
    };
}

/// Convenience function for creating a DomainSeparatedHasher with an added label
pub fn create_hasher_with_label<D: Digest, HD: DomainSeparation>(label: &'static str) -> DomainSeparatedHasher<D, HD> {
    DomainSeparatedHasher::<D, HD>::new_with_label(label)
}

/// Convenience function for creating a DomainSeparatedHasher
pub fn create_hasher<D: Digest, HD: DomainSeparation>() -> DomainSeparatedHasher<D, HD> {
    DomainSeparatedHasher::<D, HD>::new()
}

#[cfg(test)]
mod test {
    use blake2::Blake2b;
    use digest::{
        consts::{U32, U64},
        generic_array::GenericArray,
        Digest,
        Update,
    };
    use tari_utilities::hex::{from_hex, to_hex};

    use crate::hashing::{AsFixedBytes, DomainSeparatedHasher, DomainSeparation, Mac, MacDomain, Tag};

    mod util {
        use digest::Digest;
        use tari_utilities::hex::to_hex;

        pub(crate) fn hash_test<D: Digest>(data: &[u8], expected: &str) {
            let mut hasher = D::new();
            hasher.update(data);
            let hash = hasher.finalize();
            assert_eq!(to_hex(&hash), expected);
        }

        pub(crate) fn hash_from_digest<D: Digest>(mut hasher: D, data: &[u8], expected: &str) {
            hasher.update(data);
            let hash = hasher.finalize();
            assert_eq!(to_hex(&hash), expected);
        }
    }

    #[test]
    fn hasher_macro_tests() {
        {
            hasher!(Blake2b<U32>, MyDemoHasher, "com.macro.test");

            util::hash_from_digest(
                MyDemoHasher::new(),
                &[0, 0, 0],
                "7f018785a03c826fe26be7a1d4c90cf99db0d8e313c3dd6d53eeb6233827e8e3",
            );
        }
        {
            hasher!(Blake2b<U32>, MyDemoHasher2, "com.macro.test", 1);

            util::hash_from_digest(
                MyDemoHasher2::new(),
                &[0, 0, 0],
                "7f018785a03c826fe26be7a1d4c90cf99db0d8e313c3dd6d53eeb6233827e8e3",
            );
        }
    }

    #[test]
    fn mac_domain_metadata() {
        assert_eq!(MacDomain::version(), 1);
        assert_eq!(MacDomain::domain(), "com.tari.mac");
    }

    #[test]
    fn finalize_into() {
        hash_domain!(TestHasher, "com.example.test");
        let mut hasher = DomainSeparatedHasher::<Blake2b<U32>, TestHasher>::new();
        hasher.update([0, 0, 0]);

        let mut output = GenericArray::<u8, U32>::default();
        hasher.finalize_into(&mut output);
    }

    #[test]
    fn finalize_into_reset() {
        hash_domain!(TestHasher, "com.example.test");
        let mut hasher = DomainSeparatedHasher::<Blake2b<U32>, TestHasher>::new();
        hasher.update([0, 0, 0]);

        let mut output = GenericArray::<u8, U32>::default();
        hasher.finalize_into_reset(&mut output);
    }

    #[test]
    fn test_safe_array() {
        use tari_utilities::{hidden::Hidden, hidden_type, safe_array::SafeArray};
        use zeroize::Zeroize;

        hash_domain!(TestHasher, "com.example.test");
        let mut hasher = DomainSeparatedHasher::<Blake2b<U32>, TestHasher>::new();
        hasher.update([0, 0, 0]);

        hidden_type!(Key, SafeArray<u8, 32>);
        let mut key = Key::from(SafeArray::default()); // all zeroes
        hasher.finalize_into_reset(GenericArray::from_mut_slice(key.reveal_mut()));
    }

    #[test]
    fn dst_hasher() {
        hash_domain!(GenericHashDomain, "com.tari.generic");
        assert_eq!(GenericHashDomain::domain(), "com.tari.generic");
        assert_eq!(GenericHashDomain::version(), 1);
        let hash = DomainSeparatedHasher::<Blake2b<U32>, GenericHashDomain>::new_with_label("test_hasher")
            .chain("some foo")
            .finalize();
        let mut hash2 = DomainSeparatedHasher::<Blake2b<U32>, GenericHashDomain>::new_with_label("test_hasher");
        hash2.update("some foo");
        let hash2 = hash2.finalize();
        assert_eq!(hash.as_ref(), hash2.as_ref());
        assert_eq!(
            to_hex(hash.as_ref()),
            "f2288bde23da07c021468a1b63487514cc4cbb68d15c34bc6621964b31547df6"
        );

        let hash_1 =
            DomainSeparatedHasher::<Blake2b<U32>, GenericHashDomain>::new_with_label("mynewtest").digest(b"rincewind");
        let hash_2 = DomainSeparatedHasher::<Blake2b<U32>, GenericHashDomain>::new_with_label("mynewtest")
            .chain(b"rincewind")
            .finalize();
        assert_eq!(hash_1.as_ref(), hash_2.as_ref());
    }

    #[test]
    fn digest_is_the_same_as_standard_api() {
        hash_domain!(MyDemoHasher, "com.macro.test");
        assert_eq!(MyDemoHasher::domain(), "com.macro.test");
        assert_eq!(MyDemoHasher::version(), 1);
        util::hash_test::<DomainSeparatedHasher<Blake2b<U32>, MyDemoHasher>>(
            &[0, 0, 0],
            "d4cbf5b6b97485a991973db8a6ce4d3fc660db5dff5f55f2b0cb363fca34b0a2",
        );

        let mut hasher = DomainSeparatedHasher::<Blake2b<U32>, MyDemoHasher>::new();
        hasher.update([0, 0, 0]);
        let hash = hasher.finalize();
        assert_eq!(
            to_hex(hash.as_ref()),
            "d4cbf5b6b97485a991973db8a6ce4d3fc660db5dff5f55f2b0cb363fca34b0a2"
        );

        let mut hasher = DomainSeparatedHasher::<Blake2b<U32>, MyDemoHasher>::new_with_label("");
        hasher.update([0, 0, 0]);
        let hash = hasher.finalize();
        assert_eq!(
            to_hex(hash.as_ref()),
            "d4cbf5b6b97485a991973db8a6ce4d3fc660db5dff5f55f2b0cb363fca34b0a2"
        );
    }

    /// Test that it can be used as a standard digest
    #[test]
    fn can_be_used_as_digest() {
        hash_domain!(MyDemoHasher, "com.macro.test");
        assert_eq!(MyDemoHasher::domain(), "com.macro.test");
        assert_eq!(MyDemoHasher::version(), 1);
        util::hash_test::<DomainSeparatedHasher<Blake2b<U32>, MyDemoHasher>>(
            &[0, 0, 0],
            "d4cbf5b6b97485a991973db8a6ce4d3fc660db5dff5f55f2b0cb363fca34b0a2",
        );

        hash_domain!(MyDemoHasher2, "com.macro.test", 2);
        assert_eq!(MyDemoHasher2::domain(), "com.macro.test");
        assert_eq!(MyDemoHasher2::version(), 2);
        util::hash_test::<DomainSeparatedHasher<Blake2b<U32>, MyDemoHasher2>>(
            &[0, 0, 0],
            "ce327b02271d035bad4dcc1e69bc292392ee4ee497f1f8467d54bf4b4c72639a",
        );

        hash_domain!(TariHasher, "com.tari.hasher");
        assert_eq!(TariHasher::domain(), "com.tari.hasher");
        assert_eq!(TariHasher::version(), 1);
        util::hash_test::<DomainSeparatedHasher<Blake2b<U32>, TariHasher>>(
            &[0, 0, 0],
            "ae359f05bb76c646c6767d25f53893fc38b0c7b56f8a74a1cbb008ea3ffc183f",
        );
    }

    /// Test hash to fixed bytes conversion
    #[test]
    fn hash_to_fixed_bytes_conversion() {
        hash_domain!(TestDomain, "com.tari.generic");
        let hash = DomainSeparatedHasher::<Blake2b<U32>, TestDomain>::new_with_label("mytest")
            .chain("some data")
            .finalize();
        let hash_to_bytes_7: [u8; 7] = hash.as_fixed_bytes().unwrap();
        assert_eq!(hash_to_bytes_7, hash.as_fixed_bytes().unwrap());
        let hash_to_bytes_23: [u8; 23] = hash.as_fixed_bytes().unwrap();
        assert_eq!(hash_to_bytes_23, hash.as_fixed_bytes().unwrap());
        let hash_to_bytes_32: [u8; 32] = hash.as_fixed_bytes().unwrap();
        assert_eq!(hash_to_bytes_32, hash.as_fixed_bytes().unwrap());
    }

    #[test]
    fn deconstruction() {
        hash_domain!(TestDomain, "com.tari.generic");
        // Illustrate exactly what gets hashed and how we try and avoid collisions
        let hash = DomainSeparatedHasher::<Blake2b<U32>, TestDomain>::new_with_label("mytest")
            .chain("rincewind")
            .chain("hex")
            .finalize();
        let expected = Blake2b::<U32>::new()
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
        let label = "turtles";
        let hash = DomainSeparatedHasher::<Blake2b<U32>, MyDemoHasher>::new_with_label(label).finalize();
        let expected = Blake2b::<U32>::default()
            .chain([Tag::DomainSeparator as u8])
            .chain((MyDemoHasher::domain().len() as u64).to_le_bytes())
            .chain(MyDemoHasher::domain())
            .chain([Tag::Version as u8])
            .chain([MyDemoHasher::version()])
            .chain([Tag::Label as u8])
            .chain((label.as_bytes().len() as u64).to_le_bytes())
            .chain(label.as_bytes())
            .finalize();
        assert_eq!(hash.as_ref(), expected.as_slice());
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
        let hash = DomainSeparatedHasher::<Blake2b<U64>, MyDemoHasher>::new_with_label("turtles")
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
        let mac = Mac::<Blake2b<U32>>::generate(key, "test message", "test");
        assert_eq!(
            to_hex(mac.as_ref()),
            "9bcfbe2bad73b14ac42f673ddca34e82ce03cbbac69d34526004f5d108dff061"
        )
    }
}
