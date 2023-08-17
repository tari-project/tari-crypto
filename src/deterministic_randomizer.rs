// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A deterministic randomizer with utility functions for operating on numbers and arrays in a reproducible and
//! platform-indepdent way.

use alloc::vec::Vec;
use core::convert::TryFrom;

use rand_core::{CryptoRng, RngCore, SeedableRng};

/// Error representing a failed shuffle
#[derive(Debug)]
pub struct RandomizerError;

/// A `DeterministicRandomizer` contains utility functions for working with pseudorandom number generators (PRNGs) where
/// reproducibility is important. While the `rand` crate has functionality for things like uniform sampling and
/// shuffling that can be used with PRNGs, there is no guarantee that these functions will always be implemented in the
/// same way across versions, which could lead to incompatibility or dependency troubles. This library has no specific
/// `rand` dependency, and implements deterministic sampling and shuffling that are implemented in straightforward ways
/// that will work identically across platforms. If you provide the same seed to the PRNG, you'll get the same results.
/// This can be useful for cases like consensus applications, when a set of clients need to agree on pseudorandom
/// results.
///
/// To avoid certain pitfalls, you need to choose a cryptographically-secure pseudorandom number generator (CSPRNG) that
/// implements `CryptoRng + RngCore + SeedableRng`; a good choice is something like `ChaCha12Rng` from the `rand_chacha`
/// crate (which happens to be the current `rand` default).
///
/// Once you instantiate the `DeterministicRandomizer` with your CSPRNG and a starting seed, you can start generating
/// bounded pseudorandom numbers or sampling or shuffling arrays deterministically. You can always reseed the randomizer
/// with a different seed, or reset it to the initial seed.
///
/// ```edition2018
/// # use tari_crypto::deterministic_randomizer::DeterministicRandomizer;
/// use rand_chacha::ChaCha12Rng;
///
/// // In consensus-type applications, the seed might come from a hash output whose input is some kind of state
/// // We'll just make one arbitrarily; it must be `[u8; N]` with `N <= 32`
/// let seed = [1u8; 32];
/// let mut randomizer = DeterministicRandomizer::<ChaCha12Rng>::new(seed);
///
/// // Generate bounded numbers in the range `[0, 1000)`
/// // Because it's deterministic, we know exactly what the results should be!
/// assert_eq!(randomizer.next_bounded_u64(1000).unwrap(), 573);
/// assert_eq!(randomizer.next_bounded_u64(1000).unwrap(), 786);
///
/// // Reset the generator, which uses the original seed we provided
/// randomizer.reset();
/// assert_eq!(randomizer.next_bounded_u64(1000).unwrap(), 573);
/// assert_eq!(randomizer.next_bounded_u64(1000).unwrap(), 786);
///
/// // We can also reseed using a new seed
/// // This has the same effect as creating a fresh `DeterministicRandomizer` with the new seed
/// let new_seed = [2u8; 32];
/// randomizer.reseed(new_seed);
///
/// // Shuffle an array in place (which may be of any type or length)
/// // Because it's still deterministic, we know exactly what the result should be!
/// let mut data = [0u32, 1u32, 2u32, 3u32, 4u32];
/// randomizer.shuffle(&mut data).unwrap();
/// assert_eq!(&data, &[2u32, 0u32, 4u32, 3u32, 1u32]);
///
/// // Get a shuffled sample of an array, leaving the original unchanged
/// let data = [0u32, 1u32, 2u32, 3u32, 4u32];
/// let sample = randomizer.sample(&data, 3).unwrap();
/// assert_eq!(&sample, &[3u32, 0u32, 4u32]);
/// ```
///
/// **WARNING**: While `DeterministicRandomizer` requires a cryptographically-secure pseudorandom number generator
/// (CSPRNG), it is _not_ suitable for non-deterministic use cases like key or nonce generation. If you aren't
/// absolutely sure that you need the functionality provided here, you should use a high-entropy non-deterministic
/// generator instead.
pub struct DeterministicRandomizer<R>
where R: SeedableRng
{
    prng: R,
    seed: <R as SeedableRng>::Seed,
}

impl<R> DeterministicRandomizer<R>
where
    R: CryptoRng + RngCore + SeedableRng,
    <R as SeedableRng>::Seed: Clone,
{
    /// Initialize the randomizer with a seed
    pub fn new(seed: <R as SeedableRng>::Seed) -> Self {
        Self {
            prng: R::from_seed(seed.clone()),
            seed,
        }
    }

    /// Reseed the randomizer with a new seed
    pub fn reseed(&mut self, seed: <R as SeedableRng>::Seed) {
        self.prng = R::from_seed(seed.clone());
        self.seed = seed;
    }

    /// Reset the randomizer using the seed last provided by either the constructor or reseeding
    pub fn reset(&mut self) {
        self.reseed(self.seed.clone());
    }

    /// Sample elements without replacement, shuffling their order
    pub fn sample<T>(&mut self, data: &[T], k: usize) -> Result<Vec<T>, RandomizerError>
    where T: Clone {
        // This currently reallocates; it could be made more efficient
        let mut result = data.to_vec();
        self.partial_shuffle(&mut result, k)?;

        Ok(result[(data.len() - k)..].to_vec())
    }

    /// Shuffle an array in place
    pub fn shuffle<T>(&mut self, data: &mut [T]) -> Result<(), RandomizerError> {
        self.partial_shuffle(data, data.len())?;

        Ok(())
    }

    /// Utility function for a partial in-place Fisher-Yates shuffle
    /// The last `n` items are fully shuffled, while the remaining items are not!
    #[allow(clippy::cast_possible_truncation)]
    fn partial_shuffle<T>(&mut self, data: &mut [T], n: usize) -> Result<(), RandomizerError> {
        if n > data.len() {
            return Err(RandomizerError);
        }
        let low = (data.len() - n) as u64;
        let high = data.len() as u64;

        // Perform the Durstenfeld variant of the Fisher-Yates shuffle
        for i in (low..high).rev() {
            // Note that we have to cast from `u64` to `usize`, so we need to ignore the truncation warning (we're fine
            // on 64-bit targets)
            let j = self.next_bounded_u64(i + 1).map(|j| j as usize)?;
            data.swap(i as usize, j);
        }

        Ok(())
    }

    /// Choose a random bounded 64-bit unsigned integer with exclusive upper bound
    pub fn next_bounded_u64(&mut self, upper: u64) -> Result<u64, RandomizerError> {
        // We can't get a `u128` directly from the generator
        let x = u128::from(self.prng.next_u64()) << 64 | u128::from(self.prng.next_u64());

        u64::try_from(x % u128::from(upper)).map_err(|_| RandomizerError)
    }
}

#[cfg(test)]
mod test {
    use rand_chacha::ChaCha12Rng;

    use super::DeterministicRandomizer;

    type R = DeterministicRandomizer<ChaCha12Rng>;

    #[test]
    fn test_shuffle() {
        let seed = [1u8; 32];
        let mut data = [0u8, 1u8, 2u8, 3u8];
        let mut randomizer = R::new(seed);

        randomizer.shuffle(&mut data).unwrap();
        assert_eq!(&data, &[0u8, 2u8, 3u8, 1u8]);
    }

    #[test]
    fn test_bounded_u64() {
        let seed = [1u8; 32];
        let mut randomizer = R::new(seed);

        assert_eq!(randomizer.next_bounded_u64(1000).unwrap(), 573);
        assert_eq!(randomizer.next_bounded_u64(1000).unwrap(), 786);
    }

    #[test]
    fn test_sample() {
        let seed = [1u8; 32];
        let data = [0u8, 1u8, 2u8, 3u8];
        let mut randomizer = R::new(seed);

        // Test a known sampling
        let sample = randomizer.sample(&data, 3).unwrap();
        assert_eq!(&sample, &[2u8, 3u8, 1u8]);

        // Test sampling from an empty array
        let empty: [u8; 0] = [];
        assert_eq!(&randomizer.sample(&empty, 0).unwrap(), &empty);
        assert!(randomizer.sample(&empty, 1).is_err());

        // Test sampling too many items from a non-empty array
        assert!(randomizer.sample(&data, data.len() + 1).is_err());

        // Test sampling an entire array
        let mut full = randomizer.sample(&data, data.len()).unwrap();
        full.sort();
        assert_eq!(full, data);
    }

    #[test]
    fn test_seeding() {
        let seed = [1u8; 32];
        let mut randomizer = R::new(seed);

        // Assert that resetting yields the same state
        let data = randomizer.next_bounded_u64(u64::MAX).unwrap();
        randomizer.reset();
        assert_eq!(randomizer.next_bounded_u64(u64::MAX).unwrap(), data);

        // Assert that reseeding yields a distinct state (with high probability)
        randomizer.reseed([2u8; 32]);
        assert_ne!(randomizer.next_bounded_u64(u64::MAX).unwrap(), data);
    }
}
