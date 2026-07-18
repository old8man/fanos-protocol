//! `#[derive(Wire)]` — generate a canonical [`fanos_wire::Wire`] codec from a struct definition.
//!
//! For a struct with named fields it emits `wire_encode`/`wire_decode` that process each field **in
//! declaration order**, so the byte layout is exactly the field layout and every field type's own
//! canonical encoding composes. This is the single-source-of-truth answer to wire-codec bifurcation
//! (audit A1/G2): one type definition yields one codec, so hand-rolled decoders can no longer drift.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Index, parse_macro_input};

/// Derive [`fanos_wire::Wire`] for a struct — named-field, tuple, or unit. Fields are encoded and
/// decoded in declaration order, so the byte layout is exactly the field layout.
#[proc_macro_derive(Wire)]
pub fn derive_wire(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => return compile_error(&name, "Wire can only be derived for a struct"),
    };

    let (encode_body, decode_body): (TokenStream2, TokenStream2) = match fields {
        Fields::Named(named) => {
            let idents: Vec<_> = named.named.iter().filter_map(|f| f.ident.clone()).collect();
            let enc = idents
                .iter()
                .map(|f| quote! { ::fanos_wire::__private::Wire::wire_encode(&self.#f, out); });
            let dec = idents
                .iter()
                .map(|f| quote! { #f: ::fanos_wire::__private::Wire::wire_decode(cur)?, });
            (quote! { #(#enc)* }, quote! { Self { #(#dec)* } })
        }
        Fields::Unnamed(unnamed) => {
            let indices: Vec<Index> = (0..unnamed.unnamed.len()).map(Index::from).collect();
            let enc = indices
                .iter()
                .map(|i| quote! { ::fanos_wire::__private::Wire::wire_encode(&self.#i, out); });
            let dec = indices
                .iter()
                .map(|_| quote! { ::fanos_wire::__private::Wire::wire_decode(cur)?, });
            (quote! { #(#enc)* }, quote! { Self( #(#dec)* ) })
        }
        Fields::Unit => (quote! {}, quote! { Self }),
    };

    quote! {
        impl #impl_generics ::fanos_wire::__private::Wire for #name #ty_generics #where_clause {
            fn wire_encode(&self, out: &mut ::fanos_wire::__private::Vec<u8>) {
                #encode_body
            }
            fn wire_decode(cur: &mut &[u8])
                -> ::fanos_wire::__private::Result<Self, ::fanos_wire::__private::WireError>
            {
                ::fanos_wire::__private::Result::Ok(#decode_body)
            }
        }
    }
    .into()
}

/// Emit a `compile_error!` at `name`'s span carrying `msg`.
fn compile_error(name: &syn::Ident, msg: &str) -> TokenStream {
    syn::Error::new(name.span(), msg).to_compile_error().into()
}
