use proc_macro::{TokenStream, TokenTree};

use litrs::StringLit;
use quote::quote;

fn get_str(input: TokenStream) -> String {
    let mut iter = input.into_iter();
    let Some(grp) = iter.next() else {
        panic!("Expected a bytes string literal");
    };

    let lit = match grp {
        TokenTree::Group(grp) => {
            let mut subiter = grp.stream().into_iter();
            let Some(tok) = subiter.next() else {
                panic!("Expected a bytes string literal");
            };
            let TokenTree::Literal(lit) = tok else {
                panic!("Expected a bytes string literal");
            };
            if let Some(_) = subiter.next() {
                panic!("Unexpected token after bytes string literal");
            }
            lit
        }
        TokenTree::Literal(lit) => lit,
        _ => {
            panic!("Expected a bytes string literal");
        }
    };

    let Ok(lit) = StringLit::try_from(lit) else {
        panic!("Expected a bytes string literal");
    };

    if let Some(_) = iter.next() {
        panic!("Unexpected token after bytes string literal");
    };

    lit.value().into()
}

/// Macro for creating arbitrarily sized byte arrays in hexadecimal string notation.
///
/// The argument to `bytes!` must be a string literal that contains hexadecimal
/// digits. The following characters will be ignored:
/// * whitespace, according to `char::is_whitespace`
/// * underscores (`_`)
/// * dashes (`-`)
/// * colons (`:`)
///
/// Additionally, comments are ignored. Comments beging with a hash (`#`) and
/// continue to the end of the line. Any other characters outside of a comment will
/// result in a compile time error. The returned value will be an array of bytes
/// (`[u8; _]`), usable in `const` or non-`const` contexts.
///
/// ## Example
/// ```
/// # use sniffle_bytes::bytes;
/// const MY_BYTES: &[u8] = &bytes!("
///     ## My Bytes Example:
///     01 02_03:04-05 # A comment!
///     abc de f
/// ");
/// assert_eq!(MY_BYTES, &[0x01, 0x02, 0x03, 0x04, 0x05, 0xab, 0xcd, 0xef]);
/// ```
#[proc_macro]
pub fn bytes(input: TokenStream) -> TokenStream {
    let mut b = Vec::new();
    let mut even = true;
    let mut curr = 0u8;
    let mut comment = false;
    for c in get_str(input).chars() {
        if comment {
            if c == '\n' {
                comment = false;
            }
            continue;
        }

        if c.is_whitespace() || c == '-' || c == ':' || c == '_' {
            continue;
        }

        if c == '#' {
            comment = true;
            continue;
        }

        let Some(digit) = c.to_digit(16) else {
            panic!("expected hexadecimal digit");
        };

        if even {
            curr = (digit << 4) as u8;
            even = false;
        } else {
            b.push(curr | (digit as u8));
            even = true;
        }
    }

    if !even {
        panic!("an odd number of hexadecimal digits is ambiguous");
    }

    quote! { [#(#b),*] }.into()
}
