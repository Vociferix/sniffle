use proc_macro::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Index, Meta};

#[proc_macro_derive(Decode)]
pub fn decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;

    let mut generics = input.generics;
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(::sniffle_decode::Decode));
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
                        if let Meta::Path(ref attr) = attr.meta {
                            if let Some(attr) = attr.segments.first() {
                                let attr_str = attr.ident.to_string();
                                if attr_str == "big_endian" {
                                    is_be = true;
                                }
                                if attr_str == "little_endian" {
                                    is_le = true;
                                }
                            }
                        }
                    }
                    if is_be && is_le {
                        panic!("field cannot be both big and little endian");
                    }
                    if is_be {
                        quote_spanned! {f.span()=>
                            ::sniffle_decode::DecodeBe::decode_be(&mut self.#name, buf)?;
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            ::sniffle_decode::DecodeLe::decode_le(&mut self.#name, buf)?;
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            ::sniffle_decode::Decode::decode(&mut self.#name, buf)?;
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
                        if let Meta::Path(ref attr) = attr.meta {
                            if let Some(attr) = attr.segments.first() {
                                let attr_str = attr.ident.to_string();
                                if attr_str == "big_endian" {
                                    is_be = true;
                                }
                                if attr_str == "little_endian" {
                                    is_le = true;
                                }
                            }
                        }
                    }
                    if is_be && is_le {
                        panic!("field cannot be both big and little endian");
                    }
                    if is_be {
                        quote_spanned! {f.span()=>
                            ::sniffle_decode::DecodeBe::decode_be(&mut self.#index, buf)?;
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            ::sniffle_decode::DecodeLe::decode_le(&mut self.#index, buf)?;
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            ::sniffle_decode::Decode::decode(&mut self.#index, buf)?;
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
        impl #impl_generics ::sniffle_decode::Decode for #name #ty_generics #where_clause {
            fn decode<B: ::sniffle_decode::DecodeBuf>(&mut self, buf: &mut B) -> std::result::Result<(), ::sniffle_decode::DecodeError> {
                #steps
            }
        }
    }.into()
}
