//! `#[derive(Wire)]` — generate a canonical [`fanos_wire::Wire`] codec from a struct definition.
//!
//! For a struct with named fields it emits `wire_encode`/`wire_decode` that process each field **in
//! declaration order**, so the byte layout is exactly the field layout and every field type's own
//! canonical encoding composes. This is the single-source-of-truth answer to wire-codec bifurcation
//! (audit A1/G2): one type definition yields one codec, so hand-rolled decoders can no longer drift.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derive [`fanos_wire::Wire`] for a struct with named fields.
#[proc_macro_derive(Wire)]
pub fn derive_wire(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let idents: Vec<syn::Ident> = match input.data {
        Data::Struct(ref data) => match &data.fields {
            Fields::Named(named) => named.named.iter().filter_map(|f| f.ident.clone()).collect(),
            _ => {
                return compile_error(&name, "Wire can only be derived for a struct with named fields");
            }
        },
        _ => return compile_error(&name, "Wire can only be derived for a struct"),
    };

    let encodes = idents
        .iter()
        .map(|f| quote! { ::fanos_wire::__private::Wire::wire_encode(&self.#f, out); });
    let decodes = idents
        .iter()
        .map(|f| quote! { #f: ::fanos_wire::__private::Wire::wire_decode(cur)?, });

    quote! {
        impl #impl_generics ::fanos_wire::__private::Wire for #name #ty_generics #where_clause {
            fn wire_encode(&self, out: &mut ::fanos_wire::__private::Vec<u8>) {
                #(#encodes)*
            }
            fn wire_decode(cur: &mut &[u8])
                -> ::fanos_wire::__private::Result<Self, ::fanos_wire::__private::WireError>
            {
                ::fanos_wire::__private::Result::Ok(Self { #(#decodes)* })
            }
        }
    }
    .into()
}

/// Emit a `compile_error!` at `name`'s span carrying `msg`.
fn compile_error(name: &syn::Ident, msg: &str) -> TokenStream {
    syn::Error::new(name.span(), msg).to_compile_error().into()
}
