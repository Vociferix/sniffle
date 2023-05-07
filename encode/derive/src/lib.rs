use proc_macro::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Index, Meta};

#[proc_macro_derive(Encode)]
pub fn encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;

    let mut encodable_generics = input.generics.clone();
    for param in &mut encodable_generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(::sniffle_encode::Encodable));
        }
    }

    let (encodable_impl_generics, encodable_ty_generics, encodable_where_clause) =
        encodable_generics.split_for_impl();

    let encodable_steps = match input.data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                        ::sniffle_encode::Encodable::encoded_size(&self.#name)
                    }
                });
                quote! {
                    0 #(+ #recurse)*
                }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        ::sniffle_encode::Encodable::encoded_size(&self.#index)
                    }
                });
                quote! {
                    0 #(+ #recurse)*
                    ()
                }
            }
            Fields::Unit => {
                quote! {
                    ()
                }
            }
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    };

    let mut encode_generics = input.generics;
    for param in &mut encode_generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(::sniffle_encode::Encode));
        }
    }

    let (encode_impl_generics, encode_ty_generics, encode_where_clause) =
        encode_generics.split_for_impl();

    let encode_steps = match input.data {
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
                            ::sniffle_encode::EncodeBe::encode_be(&self.#name, buf);
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            ::sniffle_encode::EncodeLe::encode_le(&self.#name, buf);
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            ::sniffle_encode::Encode::encode(&self.#name, buf);
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
                            ::sniffle_encode::EncodeBe::encode_be(&self.#index, buf);
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            ::sniffle_encode::EncodeLe::encode_le(&self.#index, buf);
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            ::sniffle_encode::Encode::encode(&self.#index, buf);
                        }
                    }
                });
                quote! {
                    #(#recurse)*
                    ()
                }
            }
            Fields::Unit => {
                quote! {
                    ()
                }
            }
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    };

    quote! {
        impl #encodable_impl_generics ::sniffle_encode::Encodable for #name #encodable_ty_generics #encodable_where_clause {
            fn encoded_sized(&self) -> usize {
                #encodable_steps
            }
        }

        impl #encode_impl_generics ::sniffle_encode::Encode for #name #encode_ty_generics #encode_where_clause {
            fn encode<B: ::sniffle_decode::DecodeBuf>(&self, buf: &mut B) {
                #encode_steps
            }
        }
    }.into()
}
