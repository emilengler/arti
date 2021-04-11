//! This crate defines wrappers for primitive types. For example, milliseconds or percentages
//! which could be represented directly as a primitive such as i32, are instead their own type.
//! This helps avoid mistakes e.g. passing seconds to a function expecting milliseconds.
//!
//! This crate also provides macros for defining bounded types, for example, a particular
//! configuration parameter might be restricted to a subset of possible values. In the future,
//! Rust plans to implement 'const generics' which would allow this to be expressed as
//! a language feature. Instead, we use macros to generate equivalent code automatically.  
//!  macros for defining bounded types

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

extern crate derive_more;
use derive_more::{Add, Display, Div, From, FromStr, Mul};

/// This module provides macros for implementing bounded primitive types.
#[macro_use]
pub mod macros;

/// Errors returned by bounded types
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A passed value was below the lower bound for the type.
    BelowLowerBound,
    /// A passed value was above the upper bound for the type.
    AboveUpperBound,
    /// A passed value was could not be represented in the underlying data type
    Unrepresentable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BelowLowerBound => {
                write!(f, "Value was below the lower bound for this type")
            }
            Error::AboveUpperBound => {
                write!(f, "Value was above the upper bound for this type")
            }
            Error::Unrepresentable => {
                write!(f, "Value was unrepresentable for the underlying type")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A type to represent bandwidth weights.
#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
#[from(forward)]
pub struct BandwidthWeight(pub u32);

/// A type to represent cell window sizes.
#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
#[from(forward)]
pub struct CellWindowSize(pub u16);

#[cfg(test)]
mod tests {

    #[test]
    fn test_weight_wrapper() {
        let x = super::BandwidthWeight(50);
        let y = super::BandwidthWeight(27);
        let z: super::BandwidthWeight = super::BandwidthWeight::from(x) + y;
        assert!(z == super::BandwidthWeight(77));
    }
    #[test]
    fn test_weight() {
        let v: u32 = 4;
        let x: super::BandwidthWeight = v.into();
        let y = super::BandwidthWeight(17);
        assert!(x + y == super::BandwidthWeight(21));
        let super::BandwidthWeight(raw) = x + y;
        assert!(raw == 21);
        let k = "1234";
        let _k_bw: super::BandwidthWeight = k.parse().unwrap();
    }

    bounded_type! { pub struct TestFoo(u16, 1, 5) }
    set_default_for_bounded_type!(TestFoo, 4);

    bounded_type! { struct TestBar(i32, -45, 17) }
    set_default_for_bounded_type!(TestBar, 0);

    //make_parameter_type! {TestFoo(3,)}
    #[test]
    fn simple_test() {
        let _: TestFoo = "2".parse().unwrap();
        let _: TestBar = "-3".parse().unwrap();
    }

    #[test]
    fn saturate_works() {
        let x: TestFoo = TestFoo::saturating_from_str("1000").unwrap();
        let x_val: u16 = x.into();
        assert!(x_val == TestFoo::UPPER);
        let x: TestFoo = TestFoo::saturating_from_str("0").unwrap();
        let x_val: u16 = x.into();
        assert!(x_val == TestFoo::LOWER);
    }

    #[test]
    #[should_panic]
    fn checked_too_high() {
        let _: TestBar = "1000".parse().unwrap();
    }

    #[test]
    #[should_panic]
    fn checked_too_low() {
        let _: TestBar = "-46".parse().unwrap();
    }
}
