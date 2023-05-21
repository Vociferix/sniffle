use proc_macro::{Span, TokenStream};
use proc_macro_crate::{crate_name as pmc_crate_name, FoundCrate};
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Ident, Index, Meta,
};

fn crate_name() -> impl ToTokens {
    match pmc_crate_name("sniffle") {
        Ok(name) => match name {
            FoundCrate::Itself => quote! { crate },
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site().into());
                quote! { #ident }
            }
        },
        Err(_) => match pmc_crate_name("sniffle-ende").unwrap() {
            FoundCrate::Itself => quote! { crate },
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site().into());
                quote! { ::#ident }
            }
        },
    }
}

#[proc_macro_derive(Decode, attributes(big, little, padding))]
pub fn decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let crate_name = crate_name();

    let name = input.ident;

    let mut generics = input.generics;
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(#crate_name::decode::Decode));
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
                            #crate_name::decode::DecodeBe::decode_be(&mut self.#name, __sniffle_ende_decode_buf_value)?;
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            #crate_name::decode::DecodeLe::decode_le(&mut self.#name, __sniffle_ende_decode_buf_value)?;
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            #crate_name::decode::Decode::decode(&mut self.#name, __sniffle_ende_decode_buf_value)?;
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
                            #crate_name::decode::DecodeBe::decode_be(&mut self.#index, __sniffle_ende_decode_buf_value)?;
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            #crate_name::decode::DecodeLe::decode_le(&mut self.#index, __sniffle_ende_decode_buf_value)?;
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            #crate_name::decode::Decode::decode(&mut self.#index, __sniffle_ende_decode_buf_value)?;
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
        impl #impl_generics #crate_name::decode::Decode for #name #ty_generics #where_clause {
            fn decode<__sniffle_ende_decode_buf_type: #crate_name::decode::DecodeBuf>(&mut self, __sniffle_ende_decode_buf_value: &mut __sniffle_ende_decode_buf_type) -> ::std::result::Result<(), #crate_name::decode::DecodeError> {
                #steps
            }
        }
    }.into()
}

#[proc_macro_derive(Encode)]
pub fn encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let crate_name = crate_name();

    let name = input.ident;

    let mut encodable_generics = input.generics.clone();
    for param in &mut encodable_generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(#crate_name::encode::Encodable));
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
                        #crate_name::encode::Encodable::encoded_size(&self.#name)
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
                        #crate_name::encode::Encodable::encoded_size(&self.#index)
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
                .push(parse_quote!(#crate_name::encode::Encode));
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
                            #crate_name::encode::EncodeBe::encode_be(&self.#name, __sniffle_ende_encode_buf_value);
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            #crate_name::encode::EncodeLe::encode_le(&self.#name, __sniffle_ende_encode_buf_value);
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            #crate_name::encode::Encode::encode(&self.#name, __sniffle_ende_encode_buf_value);
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
                            #crate_name::encode::EncodeBe::encode_be(&self.#index, __sniffle_ende_encode_buf_value);
                        }
                    } else if is_le {
                        quote_spanned! {f.span()=>
                            #crate_name::encode::EncodeLe::encode_le(&self.#index, __sniffle_ende_encode_buf_value);
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            #crate_name::encode::Encode::encode(&self.#index, __sniffle_ende_encode_buf_value);
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
        impl #encodable_impl_generics #crate_name::encode::Encodable for #name #encodable_ty_generics #encodable_where_clause {
            fn encoded_sized(&self) -> usize {
                #encodable_steps
            }
        }

        impl #encode_impl_generics #crate_name::encode::Encode for #name #encode_ty_generics #encode_where_clause {
            fn encode<__sniffle_ende_encode_buf_type: #crate_name::encode::EncodeBuf>(&self, __sniffle_ende_encode_buf_value: &mut __sniffle_ende_encode_buf_type) {
                #encode_steps
            }
        }
    }.into()
}

#[proc_macro_derive(Pack)]
pub fn pack(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let crate_name = crate_name();

    let name = input.ident;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let (packed_type, pack_steps, unpack_steps) = match input.data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let types: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| {
                        let ty = &f.ty;
                        quote_spanned! {f.span()=>
                            #ty
                        }
                    })
                    .collect();
                let fields: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| {
                        let name = &f.ident;
                        quote_spanned! {f.span()=>
                            #name
                        }
                    })
                    .collect();
                (
                    quote! {
                        <(#(#types),*) as #crate_name::pack::Pack>::Packed
                    },
                    quote! {
                        let Self { #(#fields),* } = self;
                        (#(#fields),*).pack()
                    },
                    quote! {
                        let (#(#fields),*) = <(#(#types),*) as #crate_name::pack::Pack>::unpack_from(packed);
                        Self { #(#fields),* }
                    },
                )
            }
            Fields::Unnamed(ref fields) => {
                let types: Vec<_> = fields
                    .unnamed
                    .iter()
                    .map(|f| {
                        let ty = &f.ty;
                        quote_spanned! {f.span()=>
                            #ty
                        }
                    })
                    .collect();
                let tmp_names: Vec<_> = (0..(fields.unnamed.len()))
                    .map(|i| {
                        let tmp_name = Ident::new(&format!("__tmp_{i}"), Span::call_site().into());
                        quote! { #tmp_name }
                    })
                    .collect();
                (
                    quote! {
                        <(#(#types),*) as #crate_name::pack::Pack>::Packed
                    },
                    quote! {
                        let Self(#(#tmp_names),*) = self;
                        (#(#tmp_names),*).pack()
                    },
                    quote! {
                        let (#(#tmp_names),*) = <(#(#types),*) as #crate_name::pack::Pack>::unpack_from(packed);
                        Self(#(#tmp_names),*)
                    },
                )
            }
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    };

    quote! {
        impl #impl_generics #crate_name::pack::Pack for #name #ty_generics #where_clause {
            type Packed = #packed_type;

            fn pack(self) -> Self::Packed {
                #pack_steps
            }

            fn unpack_from(packed: Self::Packed) -> Self {
                #unpack_steps
            }
        }
    }
    .into()
}
