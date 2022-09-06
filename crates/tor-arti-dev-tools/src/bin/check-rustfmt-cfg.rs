#![allow(unused_imports)]
#![allow(dead_code)]

//! XXX

use std::io::stdin;
use std::io::Read as _;

use itertools::Itertools;
use proc_macro2::{Delimiter, Group, Span, TokenStream, TokenTree};
use quote::ToTokens;

use TokenTree::*;

type TokeIterator = <TokenStream as IntoIterator>::IntoIter;

fn bad_input<T>(s: &str) -> T {
    panic!("bad input: {}", s);
}

pub fn main() {
    let mut s = String::new();
    stdin().read_to_string(&mut s).expect("read");
    let input: TokenStream = s.parse().expect("parse");

    let mut out = vec![];
    scan_stream(input, &mut out);
    let attr_sets = Itertools::group_by(out.into_iter(), |si| matches!(si, ScannedItem::Attr(_)));
    for set in attr_sets.into_iter().filter(|(k, _)| *k).map(|(_, set)| {
        set.map(|si| match si {
            ScannedItem::Attr(a) => a,
            _ => panic!(),
        })
        .collect_vec()
    }) {
        for attr in set {
            let meta = match syn::parse2(attr) {
                Ok(syn::Meta::List(ml)) => ml,
                _ => continue,
            };
            if !meta.path.is_ident("cfg_attr") {
                continue;
            }

            let mut meta = meta.nested.into_iter();
            let cond = match meta.next() {
                Some(cond) => cond,
                _ => continue,
            };
            let effects = meta;

            eprintln!("META {}", cond.to_token_stream());
            for effect in effects {
                eprintln!("COND {}", effect.to_token_stream());
            }
        }
    }
}

#[derive(Debug)]
enum ScannedItem {
    Attr(TokenStream),
    Other,
}

fn scan_stream(input: TokenStream, out: &mut Vec<ScannedItem>) {
    let mut input = input.into_iter();

    while let Some(tok) = input.next() {
        match tok {
            Punct(p) if p.as_char() == '#' => {}
            Group(g) => {
                scan_stream(g.stream(), out);
                continue;
            }
            _ => {
                out.push(ScannedItem::Other);
                continue;
            }
        };

        let tok = input.next().unwrap_or_else(|| bad_input("EOF after #"));
        let attr = match tok {
            Group(g) if g.delimiter() == Delimiter::Bracket => g.stream(),
            Group(g) => {
                scan_stream(g.stream(), out);
                continue;
            }
            _ => {
                out.push(ScannedItem::Other);
                continue;
            }
        };

        eprintln!("ATTR: {}", &attr);
        out.push(ScannedItem::Attr(attr))
    }
}
