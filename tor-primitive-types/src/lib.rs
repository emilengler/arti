extern crate derive_more;
use derive_more::{Add, Deref, Display, Div, From, FromStr, Into, Mul};

#[macro_use]
pub mod macros;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    BelowLowerBound,
    AboveUpperBound,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BelowLowerBound => write!(f, "Value was below the lower bound for this type"),
            Error::AboveUpperBound => write!(f, "Value was above the upper bound for this type"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[from(forward)]
pub struct BandwidthWeight(pub u32);

#[derive(Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[from(forward)]
pub struct CellWindowSize(pub u32);

#[derive(Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[from(forward)]
pub struct Milliseconds(pub u32);

#[derive(Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq,Eq,Ord,PartialOrd)]
#[from(forward)]
pub struct Percentage(pub u8);

#[cfg(test)]
mod tests {

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
        let k_bw: super::BandwidthWeight = k.parse().unwrap();
    }

    bounded_type! {TestFoo(u16, 1, 5, test_foo_bounds) }
    make_default_type! { TestFoo(4, test_foo_default) }
    make_saturating_type! {TestFoo(u16)}

    bounded_type! { TestBar(i32, -45, 17, test_bar_bounds) }
    make_default_type! { TestBar(0, test_bar_default) }
    make_checked_type! {TestBar(i32)}

    //make_parameter_type! {TestFoo(3,)}
    #[test]
    fn simple_test() {
        let _: TestFoo = "2".parse().unwrap();
        let _: TestBar = "-3".parse().unwrap();
    }

    #[test]
    fn saturate_works() {
        let x: TestFoo = "1000".parse().unwrap();
        let x_val: u16 = x.into();
        assert!(x_val == TestFoo::UPPER);
        let x: TestFoo = "0".parse().unwrap();
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
