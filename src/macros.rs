// Copyright 2019 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

/// Adds some variations of `Add` given a definition for `Add` that takes references. i.e. assuming we have
/// ```ignore
///   impl<'a, 'b> Add<&'b Foo> for &'a Foo {
///       type Output = Foo;
///       fn add(self, rhs: &'b rhs) -> Foo {...}
///   }
/// ```
/// which allows `&foo1 + &foo2` This macro adds definitions for
/// * `&foo1 + foo2`
/// * `foo1 + &foo2`
/// * `foo1 + foo2`
macro_rules! define_add_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $out;

            fn add(self, rhs: &'b $rhs) -> $out {
                &self + rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $out;

            fn add(self, rhs: $rhs) -> $out {
                self + &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $out;

            fn add(self, rhs: $rhs) -> $out {
                &self + &rhs
            }
        }
    };
}

/// Add variations for `Sub` definitions, similar to those for `Add`
macro_rules! define_sub_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Sub<&'b $rhs> for $lhs {
            type Output = $out;

            fn sub(self, rhs: &'b $rhs) -> $out {
                &self - rhs
            }
        }

        impl<'a> Sub<$rhs> for &'a $lhs {
            type Output = $out;

            fn sub(self, rhs: $rhs) -> $out {
                self - &rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $out;

            fn sub(self, rhs: $rhs) -> $out {
                &self - &rhs
            }
        }
    };
}

/// Add variations for `Mul` definitions, similar to those for `Add`
macro_rules! define_mul_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Mul<&'b $rhs> for $lhs {
            type Output = $out;

            fn mul(self, rhs: &'b $rhs) -> $out {
                &self * rhs
            }
        }

        impl<'a> Mul<$rhs> for &'a $lhs {
            type Output = $out;

            fn mul(self, rhs: $rhs) -> $out {
                self * &rhs
            }
        }

        impl Mul<$rhs> for $lhs {
            type Output = $out;

            fn mul(self, rhs: $rhs) -> $out {
                &self * &rhs
            }
        }
    };
}
