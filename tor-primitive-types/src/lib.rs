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

#[cfg(test)]
mod tests {
    bounded_type! { TestFoo(u16, 1, 4, 5, test_foo_bounds) }
    bounded_type! { TestBar(i32, -45, 0, 17, test_bar_bounds) }

    #[test]
    fn simple_test() {
        let x = TestFoo::checked_new(3).unwrap();
    }
}
