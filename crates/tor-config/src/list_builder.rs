//! Lists in builders
//!
//! Use [`define_list_builder_helper`] and [`define_list_builder_accessors`] together when
//! a configuration (or other struct with a builder)
//! wants to contain a `Vec` of config sub-entries.
//!
//! ### How to use these macros
//!
//!  * For each kind of list, define a `ThingList` type alias for the validated form,
//!    and call [`define_list_builder_helper`] to define a `ThingListBuilder` helper
//!    type.  (Different lists with the same Rust type, but which ought to have a different
//!    default, are different "kinds" and should each have a separately named type alias.)
//!
// An alternative design would be declare the field on `Outer` as `Vec<Thing>`, and to provide
// a `VecBuilder`.  But:
//
//  (i) the `.build()` method would have to be from a trait (because it would be `VecBuilder<Item>`
//  which would have to contain some `ItemBuilder`, and for the benefit of `VecBuilder::build()`).
//  Although derive_builder` does not provide that trait now, this problem is not insuperable,
//  but it would mean us inventing a `Buildable` trait and a macro to generate it, or forking
//  derive_builder further.
//
//  (ii) `VecBuilder<Item>::build()` would have to have the same default list for every
//  type Item (an empty list).  So places where the default list is not empty would need special
//  handling.  The special handling would look quite like what we have here.
//
//!  * For each struct field containing a list, in a struct deriving `Builder`,
//!    decorate the field with `#[builder(sub_builder, setter(custom))]`
//!    to (i) get `derive_builder` call the appropriate build method,
//!    (ii) suppress the `derive_builder`-generated setter.
//!
// `ThingLisgtBuiler` exixsts for two reasons:
//
//  * derive_builder wants to call simply `build` on the builder struct field, and will
//    generate code for attaching the field name to any error which occurs.  We could
//    override the per-field build expression, but it would be quite a lot of typing and
//    would recapitulate the field name three times.
//
//  * The field accessors (which must be generated by a different macro_rules macros, at least
//    unless we soup up derive_builder some more) might need to do defaulting, too.  if
//    the builder field is its own type, that can be a method on that type.
//
//!  * For each struct containing lists, call [`define_list_builder_accessors`]
//!    to define the accessor methods.
//!
//! ### Example - list of structs with builders
//!
//! ```
//! use derive_builder::Builder;
//! use serde::{Deserialize, Serialize};
//! use tor_config::{define_list_builder_helper, define_list_builder_accessors, ConfigBuildError};
//!
//! #[derive(Builder, Debug, Eq, PartialEq)]
//! #[builder(build_fn(error = "ConfigBuildError"))]
//! #[builder(derive(Debug, Serialize, Deserialize))]
//! pub struct Thing { value: i32 }
//!
//! #[derive(Builder, Debug, Eq, PartialEq)]
//! #[builder(build_fn(error = "ConfigBuildError"))]
//! #[builder(derive(Debug, Serialize, Deserialize))]
//! pub struct Outer {
//!     /// List of things, being built as part of the configuration
//!     #[builder(sub_builder, setter(custom))]
//!     things: ThingList,
//! }
//!
//! define_list_builder_accessors! {
//!     struct OuterBuilder {
//!         pub things: [ThingBuilder],
//!     }
//! }
//!
//! /// Type alias for use by list builder macrology
//! type ThingList = Vec<Thing>;
//!
//! define_list_builder_helper! {
//!     pub(crate) struct ThingListBuilder {
//!         pub(crate) things: [ThingBuilder],
//!     }
//!     built: ThingList = things;
//!     default = vec![];
//! }
//!
//! let mut builder = OuterBuilder::default();
//! builder.things().push(ThingBuilder::default().value(42).clone());
//! assert_eq!{ builder.build().unwrap().things, &[Thing { value: 42 }] }
//!
//! builder.set_things(vec![ThingBuilder::default().value(38).clone()]);
//! assert_eq!{ builder.build().unwrap().things, &[Thing { value: 38 }] }
//! ```
//!
//! ### Example - list of trivial values
//!
//! ```
//! use derive_builder::Builder;
//! use serde::{Deserialize, Serialize};
//! use tor_config::{define_list_builder_helper, define_list_builder_accessors, ConfigBuildError};
//!
//! #[derive(Builder, Debug, Eq, PartialEq)]
//! #[builder(build_fn(error = "ConfigBuildError"))]
//! #[builder(derive(Debug, Serialize, Deserialize))]
//! pub struct Outer {
//!     /// List of values, being built as part of the configuration
//!     #[builder(sub_builder, setter(custom))]
//!     values: ValueList,
//! }
//!
//! define_list_builder_accessors! {
//!    struct OuterBuilder {
//!        pub values: [u32],
//!    }
//! }
//!
//! /// Type alias for use by list builder macrology
//! pub type ValueList = Vec<u32>;
//!
//! define_list_builder_helper! {
//!    pub(crate) struct ValueListBuilder {
//!        pub(crate) values: [u32],
//!    }
//!    built: ValueList = values;
//!    default = vec![27];
//!    item_build: |&value| Ok(value);
//! }
//!
//! let mut builder = OuterBuilder::default();
//! assert_eq!{ builder.build().unwrap().values, &[27] }
//!
//! builder.values().push(12);
//! assert_eq!{ builder.build().unwrap().values, &[27, 12] }
//! ```

/// Define a list builder struct for use with [`define_list_builder_accessors`]
///
/// Generates an builder struct that can be used with derive_builder
/// and [`define_list_builder_accessors`] to configure a list of some kind.
///
/// **See the [`list_builder` module documentation](crate::list_builder) for an overview.**
///
/// ### Generated struct
///
/// This macro-generated builder struct contains `Option<Vec<ThingBuilder>>`, to allow it to
/// distinguish "never set" from "has been adjusted or set, possibly to the empty list".
///
/// This struct is not exposed as part of the API for setting the configuration.
/// Generally the visibility (`$vis`) should be private,
/// but sometimes `pub(crate)` or `pub` is necessary,
/// for example if the list is to be included in a struct in another module or crate.
/// Usually `$field_vis` should be the same as `$vis`.
///
/// `#[derive(Default, Clone, Debug, Serialize, Deserialize)]`
///  will be applied to the generated builder,
/// but you can specify other attributes too.
/// There is no need to supply any documentation; this is an internal struct and
/// the macro will supply a suitable (bland) doc comment.
/// (If you do supply documentation, the autogenerated docs will be appended,
/// so start with a summary line.)
/// Documentation for the semantics and default value should be applied
/// to the field(s) in the containing struct(s).
///
/// `#[serde(transparent)]` will be applied to the generated `ThingBuilder` struct,
/// so that it deserializes just like `Option<Vec<Thing>>`.
///
/// ### Input to the macro
///
/// For the input syntax, refer to the docs autogenerated from the macro's matcher.
///
/// The `built` clause specifies the type of the built value, and how to construct it.
/// In the expression part, `things` (the field name) will be the default-resolved `Vec<Thing>`;
/// it should be consumed by the expression.
/// If the built value is simply a `Vec`, you can just write `built: ThingList = things;`.
///
/// The `default` clause must provide an expression evaluating to a `Vec<ThingBuilder>`.
///
/// The `item_build` clause, if supplied, provides a closure with type
/// `FnMut(&ThingBuilder) -> Result<Thing, ConfigBuildError>`;
/// the default is to call `thing_builder.build()`.
///
/// `[$generics]` are generics for `$ListBuilder`.
/// Inline bounds (`T: Debug`) are not supported; use a `where` clause instead.
/// Due to limitations of `macro_rules`, the parameters must be within `[ ]` rather than `< >`,
/// and an extraneous pair of `[ ]` must appear around any `$where_clauses`.
//
// This difficulty with macro_rules is not well documented.
// The upstream Rust bug tracker has this issue
//   https://github.com/rust-lang/rust/issues/73174
//   Matching function signature is nearly impossible in declarative macros (mbe)
// which is not precisely this problem but is very nearby.
// There's also the vapourware "declarative macros 2.0"
//   https://github.com/rust-lang/rust/issues/39412
#[macro_export]
macro_rules! define_list_builder_helper {
    {
        $(#[ $docs_and_attrs:meta ])*
        $vis:vis
        struct $ListBuilder:ident $( [ $($generics:tt)* ] )?
        $( where [ $($where_clauses:tt)* ] )?
        {
            $field_vis:vis $things:ident : [$EntryBuilder:ty] $(,)?
        }
        built: $Built:ty = $built:expr;
        default = $default:expr;
        $( item_build: $item_build:expr; )?
    } => {
        #[derive($crate::educe::Educe, Clone, Debug)]
        #[derive($crate::serde::Serialize, $crate::serde::Deserialize)]
        #[educe(Default)]
        #[serde(transparent)]
        $(#[ $docs_and_attrs ])*
        /// Wrapper struct to help derive_builder find the right types and methods
        ///
        /// This struct is not part of the configuration API.
        /// Refer to the containing structures for information on how to build the config.
        $vis struct $ListBuilder $( < $($generics)* > )?
        $( where $($where_clauses)* )?
        {
            /// The list, as overridden
            $field_vis $things: Option<Vec<$EntryBuilder>>,
        }

        impl $( < $($generics)* > )? $ListBuilder $( < $($generics)* > )?
        $( where $($where_clauses)* )?
        {
            /// Resolve this list to a list of built items.
            ///
            /// If the value is still the [`Default`],
            /// a built-in default list will be built and returned;
            /// otherwise each applicable item will be built,
            /// and the results collected into a single built list.
            $vis fn build(&self) -> Result<$Built, $crate::ConfigBuildError> {
                let default_buffer;
                let $things = match &self.$things {
                    Some($things) => $things,
                    None => {
                        default_buffer = Self::default_list();
                        &default_buffer
                    }
                };

                let $things = $things
                    .iter()
                    .map(
                        $crate::macro_first_nonempty!{
                            [ $( $item_build )? ],
                            [ |item| item.build() ],
                        }
                    )
                    .collect::<Result<_, $crate::ConfigBuildError>>()?;
                Ok($built)
            }

            /// The default list
            fn default_list() -> Vec<$EntryBuilder> {
                 $default
            }

            /// Resolve the list to the default if necessary and then return `&mut Vec`
            $vis fn access(&mut self) -> &mut Vec<$EntryBuilder> {
                self.$things.get_or_insert_with(Self::default_list)
            }

            /// Resolve the list to the default if necessary and then return `&mut Vec`
            $vis fn access_opt(&self) -> &Option<Vec<$EntryBuilder>> {
                &self.$things
            }

            /// Resolve the list to the default if necessary and then return `&mut Vec`
            $vis fn access_opt_mut(&mut self) -> &mut Option<Vec<$EntryBuilder>> {
                &mut self.$things
            }
        }
    }
}

/// Define accessor methods for a configuration item which is a list
///
/// **See the [`list_builder` module documentation](crate::list_builder) for an overview.**
///
/// Generates the following methods for each specified field:
///
/// ```skip
/// impl $OuterBuilder {
///     pub fn $things(&mut self) -> &mut Vec<$EntryBuilder> { .. }
///     pub fn set_$things(&mut self, list: Vec<$EntryBuilder>) { .. }
///     pub fn opt_$things(&self) -> &Option<Vec<$EntryBuilder>> { .. }
///     pub fn opt_$things_mut>](&mut self) -> &mut Option<Vec<$EntryBuilder>> { .. }
/// }
/// ```
///
/// Each `$EntryBuilder` should have been defined by [`define_list_builder_helper`];
/// the method bodies from this macro rely on facilities which will beprovided by that macro.
///
/// You can call `define_list_builder_accessors` once for a particular `$OuterBuilder`,
/// with any number of fields with possibly different entry (`$EntryBuilder`) types.
#[macro_export]
macro_rules! define_list_builder_accessors {
    {
        struct $OuterBuilder:ty {
            $(
                $vis:vis $things:ident: [$EntryBuilder:ty],
            )*
        }
    } => {
        impl $OuterBuilder { $( $crate::paste!{
            /// Access the being-built list (resolving default)
            ///
            /// If the field has not yet been set or accessed, the default list will be
            /// constructed and a mutable reference to the now-defaulted list of builders
            /// will be returned.
            $vis fn $things(&mut self) -> &mut Vec<$EntryBuilder> {
                self.$things.access()
            }

            /// Set the whole list (overriding the default)
            $vis fn [<set_ $things>](&mut self, list: Vec<$EntryBuilder>) {
                *self.$things.access_opt_mut() = Some(list)
            }

            /// Inspect the being-built list (with default unresolved)
            ///
            /// If the list has not yet been set, or accessed, `&None` is returned.
            $vis fn [<opt_ $things>](&self) -> &Option<Vec<$EntryBuilder>> {
                self.$things.access_opt()
            }

            /// Mutably access the being-built list (with default unresolved)
            ///
            /// If the list has not yet been set, or accessed, `&mut None` is returned.
            $vis fn [<opt_ $things _mut>](&mut self) -> &mut Option<Vec<$EntryBuilder>> {
                self.$things.access_opt_mut()
            }
        } )* }
    }
}

define_list_builder_helper! {
    /// List of `T`, a straightforward type, being built as part of the configuration
    ///
    /// The default is the empty list.
    ///
    /// ### Example
    ///
    /// ```
    /// use derive_builder::Builder;
    /// use serde::{Deserialize, Serialize};
    /// use tor_config::{ConfigBuildError};
    /// use tor_config::{define_list_builder_accessors, list_builder::VecBuilder};
    /// use std::net::SocketAddr;
    ///
    /// #[derive(Debug, Clone, Builder)]
    /// #[builder(build_fn(error = "ConfigBuildError"))]
    /// #[builder(derive(Debug, Serialize, Deserialize))]
    /// pub struct FallbackDir {
    ///     #[builder(sub_builder(fn_name = "build"), setter(custom))]
    ///     orports: Vec<SocketAddr>,
    /// }
    ///
    /// define_list_builder_accessors! {
    ///     struct FallbackDirBuilder {
    ///         pub orports: [SocketAddr],
    ///     }
    /// }
    ///
    /// let mut bld = FallbackDirBuilder::default();
    /// bld.orports().push("[2001:db8:0::42]:12".parse().unwrap());
    /// assert_eq!( bld.build().unwrap().orports[0].to_string(),
    ///             "[2001:db8::42]:12" );
    /// ```
    pub struct VecBuilder[T] where [T: Clone] {
        values: [T],
    }
    built: Vec<T> = values;
    default = vec![];
    item_build: |item| Ok(item.clone());
}

#[cfg(test)]
mod test {
    use derive_builder::Builder;
    use serde::{Deserialize, Serialize};

    #[test]
    fn nonempty_default() {
        #[derive(Eq, PartialEq, Builder, Serialize, Deserialize)]
        struct Outer {
            #[builder(sub_builder, setter(custom))]
            list: List,
        }

        define_list_builder_accessors! {
            struct OuterBuilder {
                list: [char],
            }
        }

        type List = Vec<char>;

        define_list_builder_helper! {
            struct ListBuilder {
                list: [char],
            }
            built: List = list;
            default = vec!['a'];
            item_build: |&c| Ok(c);
        }

        let mut b = OuterBuilder::default();
        assert!(b.opt_list().is_none());
        assert_eq! { (&b).build().expect("build failed").list, ['a'] };

        b.list().push('b');
        assert!(b.opt_list().is_some());
        assert_eq! { (&b).build().expect("build failed").list, ['a', 'b'] };

        for mut b in [b.clone(), OuterBuilder::default()] {
            b.set_list(vec!['x', 'y']);
            assert!(b.opt_list().is_some());
            assert_eq! { (&b).build().expect("build failed").list, ['x', 'y'] };
        }

        *b.opt_list_mut() = None;
        assert_eq! { (&b).build().expect("build failed").list, ['a'] };
    }
}
