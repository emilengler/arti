/// This module provides macros helpful for defining a bounded primitive type.

/// This macro implements a bounded type. The data is represented as the specified underlying type.
/// It is impossible to construct an instance of this type outside the underlying bounds.
#[macro_export]
macro_rules! bounded_type {
    {
        $(#[$meta:meta])*
        $type_name:ident($underlying_type:ty,$lower:expr,$upper:expr,$test_name:ident)
    } => {

        #[cfg(test)]
        /// This is an automatically generated test which ensures that the bounds on the integer
        /// type make sense and that the default is within those bounds. It is possible to compile
        /// to create a type with invalid bounds, but running `cargo test` will show the failing
        /// test and type. Currently, the user has to provide a test name because macros are not
        /// allowed to generate new identifiers without using nightly.
        /// TODO - Mark functions for inlining and branches for expectation?s
        #[test]
        fn $test_name() {
            assert!($lower <= $upper);
        }
        /// The structure for the type, including the underlying value.
		#[derive(Debug, Clone)]
        pub struct $type_name {
            value : $underlying_type
        }

        #[allow(dead_code)]
        impl $type_name {
            /// An upper bound for values of this type.
            const UPPER : $underlying_type = $upper;
            /// A lower bound for values of this type
        	const LOWER : $underlying_type = $lower;
            /// Private constructor function for this type.
            fn new(value: $underlying_type) -> $type_name {
                $type_name { value }
            }
            /// Public getter for the underlying type.
            pub fn get(&self) -> $underlying_type {
            	self.value
            }
            /// This constructor returns a new value with type equal to the input value.
            /// If the value lies outside the maximum range of the type, it is clamped to the
            /// upper or lower bound as appropriate.
            pub fn saturating_new(val: $underlying_type) -> $type_name {
                $type_name::new($type_name::clamp(val))
            }
            /// This constructor returns a result containing the new value or else
            /// an error if the input lies outside the acceptable range.
            pub fn checked_new(val: $underlying_type) -> std::result::Result<$type_name, $crate::Error> {
                if val > $type_name::UPPER {
                    Err($crate::Error::AboveUpperBound)
                } else if val < $type_name::LOWER {
                    Err($crate::Error::BelowLowerBound)
                } else {
                    Ok($type_name::new(val))
                }
            }
            /// This private function clamps an input to the acceptable range.
            fn clamp(val: $underlying_type) -> $underlying_type {
                if val > $type_name::UPPER {
                    $type_name::UPPER
                } else if val < $type_name::LOWER {
                    $type_name::LOWER
                } else {
                    val
                }
            }
        }
        impl std::fmt::Display for $type_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.value)
            }
        }
        impl std::convert::From<$type_name> for $underlying_type {
            fn from(val: $type_name) -> $underlying_type {
                val.value
            }
        }
    }
}

/// This macro generates a default implementation for the type and a test to ensure
/// that the default value is within the correct bounds.
#[macro_export]
macro_rules! make_default_type {
    {
     $type_name:ident($def:expr,$test_name:ident)
    } => {

        #[cfg(test)]
        #[test]
        fn $test_name() {
            assert!($type_name::LOWER <= $def);
            assert!($def <= $type_name::UPPER);
        }

        impl Default for $type_name {
            fn default() -> Self {
                $type_name { value : $def }
            }
        }
    }
}

/// This macro implements From and FromStr traits to support parsing and conversion
/// from the underlying type. It uses the saturating constructor to clamp the underlying
/// values to be within the upper and lower bounds of the type.
#[macro_export]
macro_rules! make_saturating_type{
    {
     $type_name:ident($underlying_type:ty)
    } => {
        impl std::convert::From<$underlying_type> for $type_name {
            fn from(val: $underlying_type) -> $type_name {
                $type_name::saturating_new(val)
            }
        }

        impl std::str::FromStr for $type_name {
            //TODO Is this sufficiently general?
            type Err = std::num::ParseIntError;
            fn from_str(s: &str) ->  std::result::Result<Self, Self::Err>{
                Ok($type_name::saturating_new(s.parse()?))
            }
        }
    }
}

/// This macro instanties a checked type which returns an error if the passed value
/// lies outside the upper or lower bounds.
#[macro_export]
macro_rules! make_checked_type {
    {
     $type_name:ident($underlying_type:ty)
    } => {
        impl std::convert::TryFrom<$underlying_type> for $type_name {
            type Error = $crate::Error;
            fn try_from(val: $underlying_type) -> Result<Self,Self::Error> {
                $type_name::checked_new(val)
            }
        }

        impl std::str::FromStr for $type_name {
            type Err = Box<dyn std::error::Error>;
            fn from_str(s: &str) ->  std::result::Result<Self, Self::Err>{
                $type_name::checked_new(s.parse()?).map_err(|e| e.into())
            }
        }
    }
}
