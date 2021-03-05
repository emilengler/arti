#[macro_export]
macro_rules! bounded_type {
    {
     $type_name:ident($underlying_type:ty,$lower:literal,$def:literal,$upper:literal,$test_name:ident)
    } => {
        //TODO It would be nice to automatically generate a test to check that lower <= def <= upper
        //Unfortunately, this seems to require a nightly macro or custom crate?
        #[cfg(test)]
        #[test]
        fn $test_name() {
            assert!($lower <= $upper);
            assert!($lower <= $def);
            assert!($def <= $upper);
        }
        pub struct $type_name {
            value : $underlying_type
        }

        impl $type_name {
            const UPPER : $underlying_type = $upper;
            const LOWER : $underlying_type = $lower;
            /// TODO Inline?
            fn new(value: $underlying_type) -> $type_name {
                $type_name { value }
            }
            /// This constructor returns a new value with type equal to the input value.
            /// If the value lies outside the maximum range of the type, it is clamped to the
            /// upper or lower bound.
            pub fn saturating_new(val: $underlying_type) -> $type_name {
                $type_name::new($type_name::clamp(val))
            }
            /// This constructor returns a result containing the new value or else
            /// an error if the input lies outside the acceptable range.
            /// TODO Can we annoate the expected branch?
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
            /// TODO Force inline?
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

        impl std::convert::From<$underlying_type> for $type_name {
            fn from(val: $underlying_type) -> $type_name {
                $type_name::saturating_new(val)
            }
        }
        impl std::fmt::Display for $type_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.value)
            }
        }

        impl Default for $type_name {
            fn default() -> Self {
                //TODO Is this idiomatic? Should we just construct a new struct here?
                $type_name { value : $def }
            }
        }

        impl std::str::FromStr for $type_name {
            type Err = std::num::ParseIntError;
            fn from_str(s: &str) ->  std::result::Result<Self, Self::Err>{
                Ok($type_name::saturating_new(s.parse()?))
            }
        }
    }
}
