use std::ops::Deref;
use std::fmt;
use zeroize::Zeroize;

/// A "transparent" wrapper that doesn't allow to print value.
///
/// It doesn't implement `Deref` to avoid any
/// accidental usage of a protected value.
pub struct GuardedSecret<T: Guarded> {
    inner: T::Secret,
}

impl<T: Guarded> Drop for GuardedSecret<T> {
    /// Clear the secret key value in memory when it goes out of scope
    fn drop(&mut self) {
        self.inner.zeroize()
    }
}

impl<T: Guarded> GuardedSecret<T> {
    pub fn reveal(&self) -> RevealedSecret<'_, T> {
        RevealedSecret {
            secret: &self.inner,
        }
    }
}

impl<T: Guarded> fmt::Debug for GuardedSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***")
    }
}

pub struct RevealedSecret<'a, T: Guarded> {
    secret: &'a T::Secret,
}

pub trait Guarded
where
    Self: Sized,
    Self: Deref<Target = GuardedSecret<Self>>
{
    type Secret: Zeroize;
}

impl<'a, T: Guarded> fmt::Debug for RevealedSecret<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
