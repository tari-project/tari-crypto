use std::{fmt, ops::Deref};
use zeroize::Zeroize;

pub trait Guarded
where
    Self: Sized,
    Self: Deref<Target = GuardedSecret<Self::Secret>>,
{
    type Secret: Zeroize;
}

/// A "transparent" wrapper that doesn't allow to print value.
///
/// It doesn't implement `Deref` to avoid any
/// accidental usage of a protected value.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Default)]
pub struct GuardedSecret<T: Zeroize> {
    secret: T,
}

impl<T: Zeroize> GuardedSecret<T> {
    pub fn new(secret: T) -> Self {
        Self { secret }
    }
}

impl<T: Zeroize> Drop for GuardedSecret<T> {
    /// Clear the secret key value in memory when it goes out of scope
    fn drop(&mut self) {
        self.secret.zeroize()
    }
}

impl<T: Zeroize> GuardedSecret<T> {
    pub fn reveal(&self) -> &T {
        &self.secret
    }
}

impl<T: Zeroize> fmt::Debug for GuardedSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***")
    }
}
