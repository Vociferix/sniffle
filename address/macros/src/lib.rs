use proc_macro::{TokenStream, TokenTree};

use litrs::StringLit;
use quote::quote;

use sniffle_address_parse::{
    parse_hw, parse_ipv4, parse_ipv4_subnet, parse_ipv6, parse_ipv6_subnet,
};

fn get_str(input: TokenStream) -> String {
    let mut iter = input.into_iter();
    let Some(grp) = iter.next() else {
        panic!("Expected an IPv4 address string literal");
    };

    let TokenTree::Group(grp) = grp  else {
        panic!("Expected an IPv4 address string literal");
    };

    let mut subiter = grp.stream().into_iter();
    let Some(tok) = subiter.next() else {
        panic!("Expected an IPv4 address string literal");
    };

    let TokenTree::Literal(lit) = tok else {
        panic!("Expected an IPv4 address string literal");
    };

    let Ok(lit) = StringLit::try_from(lit) else {
        panic!("Expected an IPv4 address string literal");
    };

    if let Some(_) = subiter.next() {
        panic!("Unexpected token after IPv4 address string literal");
    };

    if let Some(_) = iter.next() {
        panic!("Unexpected token after IPv4 address string literal");
    };

    lit.value().into()
}

#[proc_macro]
pub fn raw_mac(input: TokenStream) -> TokenStream {
    let mut addr = [0u8; 6];
    parse_hw(&get_str(input), &mut addr).unwrap();
    let [b0, b1, b2, b3, b4, b5] = addr;
    quote! { [#b0, #b1, #b2, #b3, #b4, #b5] }.into()
}

#[proc_macro]
pub fn raw_hw(input: TokenStream) -> TokenStream {
    let addr_str = get_str(input);
    let mut addr = vec![0u8; (addr_str.len() + 1) / 3];
    parse_hw(&addr_str, &mut addr).unwrap();
    quote! { [#(#addr),*] }.into()
}

#[proc_macro]
pub fn raw_ipv4(input: TokenStream) -> TokenStream {
    let [b0, b1, b2, b3] = parse_ipv4(&get_str(input)).unwrap();
    quote! { [#b0, #b1, #b2, #b3] }.into()
}

#[proc_macro]
pub fn raw_ipv4_subnet(input: TokenStream) -> TokenStream {
    let ([b0, b1, b2, b3], prefix_len) = parse_ipv4_subnet(&get_str(input)).unwrap();
    quote! { ([#b0, #b1, #b2, #b3], #prefix_len) }.into()
}

#[proc_macro]
pub fn raw_ipv6(input: TokenStream) -> TokenStream {
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15] =
        parse_ipv6(&get_str(input)).unwrap();
    quote! { [#b0, #b1, #b2, #b3, #b4, #b5, #b6, #b7, #b8, #b9, #b10, #b11, #b12, #b13, #b14, #b15] }.into()
}

#[proc_macro]
pub fn raw_ipv6_subnet(input: TokenStream) -> TokenStream {
    let ([b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15], prefix_len) =
        parse_ipv6_subnet(&get_str(input)).unwrap();
    quote! { ([#b0, #b1, #b2, #b3, #b4, #b5, #b6, #b7, #b8, #b9, #b10, #b11, #b12, #b13, #b14, #b15], #prefix_len) }.into()
}
