/// This module provides macros helpful for defining a bounded primitive type.

/// This macro implements a bounded type. The data is represented as the specified underlying type.
/// It is impossible to construct an instance of this type outside the underlying bounds.
#[macro_export]
macro_rules! bounded_type {
    {
        $(#[$meta:meta])*
        $visibility:vis struct $type_name:ident($underlying_type:ty,$lower:expr,$upper:expr)
    } => {

        /// The structure for the type, including the underlying value.
        $(#[$meta])*
        $visibility struct $type_name {
            value : $underlying_type
        }

        #[allow(dead_code)]
        impl $type_name {
            /// An upper bound for values of this type.
            const UPPER : $underlying_type = $upper;
            /// A lower bound for values of this type
        	const LOWER : $underlying_type = $lower;
            /// Private constructor function for this type.
            fn unchecked_new(value: $underlying_type) -> $type_name {
                debug_assert!($type_name::LOWER <= $type_name::UPPER);
                $type_name { value }
            }
            //TODO - We use debug_assert! here because const_assert! from static_assertions is not yet ready. If support stabilizes, it would be preferable.

            /// Public getter for the underlying type.
            pub fn get(&self) -> $underlying_type {
            	self.value
            }
            /// This constructor returns a new value with type equal to the input value.
            /// If the value lies outside the maximum range of the type, it is clamped to the
            /// upper or lower bound as appropriate.
            pub fn saturating_new(val: $underlying_type) -> $type_name {
                $type_name::unchecked_new($type_name::clamp(val))
            }
            /// This constructor returns a result containing the new value or else
            /// an error if the input lies outside the acceptable range.
            pub fn checked_new(val: $underlying_type) -> std::result::Result<$type_name, $crate::Error> {
                if val > $type_name::UPPER {
                    Err($crate::Error::AboveUpperBound)
                } else if val < $type_name::LOWER {
                    Err($crate::Error::BelowLowerBound)
                } else {
                    Ok($type_name::unchecked_new(val))
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
            /// Convert from the underlying type, clamping to the upper or lower bound if needed.
            fn saturating_from(val: $underlying_type) -> $type_name {
                $type_name::unchecked_new($type_name::clamp(val))
            }
            /// Convert from a string, clamping to the upper or lower bound if needed.
            fn saturating_from_str(s: &str) ->  std::result::Result<Self, Box<dyn std::error::Error>> {
                let val : $underlying_type = s.parse()?;
                Ok($type_name::saturating_from(val))
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

/// This macro generates a default implementation for the type and a test to ensure
/// that the default value is within the correct bounds.
#[macro_export]
macro_rules! set_default_for_bounded_type {
    ($type_name:ident, $def:expr ) => {
        impl Default for $type_name {
            fn default() -> Self {
                debug_assert!($def <= $type_name::UPPER);
                debug_assert!($def >= $type_name::LOWER);
                $type_name::unchecked_new($def)
            }
        }
    };
}
