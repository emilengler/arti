/// This macro implements a bounded type. The data is represented as the specified underlying type. It is impossible to construct an instance of this type outside the bounds.
//TODO Move the default outside entirely?

#[macro_export]
macro_rules! bounded_type {
    {
        $(#[$meta:meta])*
        $type_name:ident($underlying_type:ty,$lower:expr,$upper:expr,$test_name:ident)
    } => {

        #[cfg(test)]
        /// This is an automatically generated test which ensures that the bounds on the integer type make sense and that the default is within those bounds. It is possible to compile to create a type with invalid bounds, but running `cargo test` will show the failing test and type.
        // TODO - Currently, the user has to provide a test name because macros are not allowed to generate new identifiers without using nightly. (?)
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
            // TODO Should be inlined?
            fn new(value: $underlying_type) -> $type_name {
                $type_name { value }
            }

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
                    // TODO Can we annoate the expected branch?
                    Ok($type_name::new(val))
                }
            }
            /// This private function clamps an input to the acceptable range.
            // TODO Force inline? Mark expected branch?
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
        //TODO Do we want to use from/into or should we have a scarier name?
        impl std::convert::From<$type_name> for $underlying_type {
            fn from(val: $type_name) -> $underlying_type {
                val.value
            }
        }
    }
}

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
