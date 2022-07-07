use std::ops::Deref;
use std::cmp::Ordering;
use std::fmt;
use zeroize::Zeroize;

/// A "transparent" wrapper that doesn't allow to print value.
///
/// It doesn't implement `Deref` to avoid any
/// accidental usage of a protected value.
pub struct GuardedSecret<T: Guarded> {
    inner: T::Secret,
}

impl<T: Guarded> Default for GuardedSecret<T>
where
    T::Secret: Default,
{
    fn default() -> Self {
        Self {
            inner: T::Secret::default(),
        }
    }
}

impl<T: Guarded> Clone for GuardedSecret<T>
where
    T::Secret: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Guarded> PartialEq for GuardedSecret<T>
where
    T::Secret: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Guarded> Eq for GuardedSecret<T>
where
    T::Secret: Eq,
{}

impl<T: Guarded> PartialOrd for GuardedSecret<T>
where
    T::Secret: PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Ordering {
        self.inner.partial_cmp(&other.inner)
    }
}

impl<T: Guarded> Ord for GuardedSecret<T>
where
    T::Secret: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
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

pub trait Guarded
where
    Self: Sized,
    Self: Deref<Target = GuardedSecret<Self>>
{
    type Secret: Zeroize;
}

pub struct RevealedSecret<'a, T: Guarded> {
    secret: &'a T::Secret,
}

impl<T: Guarded> Deref for RevealedSecret<'_, T> {
    type Target = T::Secret;

    fn deref(&self) -> &Self::Target {
        &self.secret
    }
}

impl<'a, T: Guarded> fmt::Debug for RevealedSecret<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
