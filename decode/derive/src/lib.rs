use proc_macro::{Span, TokenStream};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Ident, Index, Meta,
};

#[proc_macro_derive(Decode, attributes(big, little, padding))]
pub fn decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let crate_name = match crate_name("sniffle") {
        Ok(name) => match name {
            FoundCrate::Itself => quote! { crate },
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site().into());
                quote! { #ident }
            }
        },
        Err(_) => match crate_name("sniffle-decode").unwrap() {
            FoundCrate::Itself => quote! { crate },
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site().into());
                quote! { ::#ident }
            }
        },
    };

    let name = input.ident;

    let mut generics = input.generics;
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(#crate_name::Decode));
        }
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let steps = match input.data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let mut is_be = false;
                    let mut is_le = false;
                    for attr in f.attrs.iter() {
                        match attr.meta {
                            Meta::Path(ref attr) => {
                                if let Some(attr) = attr.segments.first() {
                                    let attr_str = attr.ident.to_string();
                                    if attr_str == "big" {
                                        is_be = true;
                                    }
                                    if attr_str == "little" {
                                        is_le = true;
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                    if is_be && is_le {
                        panic!("field cannot be both big and little endian");
                    }
                    if is_be {
                        quote_spanned! {f.span()=>
                            #crate_name::DecodeBe::decode_be(&mut self.#name, __sniffle_decode_DecodeBuf_value)?;
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            #crate_name::DecodeLe::decode_le(&mut self.#name, __sniffle_decode_DecodeBuf_value)?;
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            #crate_name::Decode::decode(&mut self.#name, __sniffle_decode_DecodeBuf_value)?;
                        }
                    }
                });
                quote! {
                    #(#recurse)*
                    Ok(())
                }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    let mut is_be = false;
                    let mut is_le = false;
                    for attr in f.attrs.iter() {
                        match attr.meta {
                            Meta::Path(ref attr) => {
                                if let Some(attr) = attr.segments.first() {
                                    let attr_str = attr.ident.to_string();
                                    if attr_str == "big" {
                                        is_be = true;
                                    }
                                    if attr_str == "little" {
                                        is_le = true;
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                    if is_be && is_le {
                        panic!("field cannot be both big and little endian");
                    }
                    if is_be {
                        quote_spanned! {f.span()=>
                            #crate_name::DecodeBe::decode_be(&mut self.#index, __sniffle_decode_DecodeBuf_value)?;
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            #crate_name::DecodeLe::decode_le(&mut self.#index, __sniffle_decode_DecodeBuf_value)?;
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            #crate_name::Decode::decode(&mut self.#index, __sniffle_decode_DecodeBuf_value)?;
                        }
                    }
                });
                quote! {
                    #(#recurse)*
                    Ok(())
                }
            }
            Fields::Unit => {
                quote! {
                    Ok(())
                }
            }
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    };

    quote! {
        impl #impl_generics #crate_name::Decode for #name #ty_generics #where_clause {
            fn decode<__sniffle_decode_DecodeBuf_type: #crate_name::DecodeBuf>(&mut self, __sniffle_decode_DecodeBuf_value: &mut __sniffle_decode_DecodeBuf_type) -> ::std::result::Result<(), #crate_name::DecodeError> {
                #steps
            }
        }
    }.into()
}
