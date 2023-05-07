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
