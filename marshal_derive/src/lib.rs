use proc_macro2::{TokenStream, Span};
use quote::{quote, quote_spanned};
use syn::{parse_macro_input, spanned::Spanned, Attribute, Data, DeriveInput, Fields, Ident, Index};

#[proc_macro_derive(Marshal)]
pub fn derive_tpm_marshal(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let marshal_text = get_marshal_body(&input.data, &input.attrs);
    let unmarshal_text = get_unmarshal_body(&input.data, &input.attrs);
    let field_list = get_field_list(&input.data);

    let expanded = quote! {
        // The generated impl.
        impl Marshalable for #name  {
            fn untry_marshal(buffer: &mut UnmarshalBuf) -> Result<Self, Tss2Rc> {
                #unmarshal_text;
                Ok(#name{#field_list})
                
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> Result<usize, Tss2Rc> {
                let mut written: usize = 0;
                #marshal_text;
                Ok(written)
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

fn get_marshal_body(data: &Data, _: &[Attribute]) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                        written += self.#name.try_marshal(&mut buffer[written..])?
                    }
                });
                quote! {
                    0 #(; #recurse)*
                }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        written += self.#index.try_marshal(&mut buffer[written..])?
                    }
                });
                quote! {
                    0 #(; #recurse)*
                }
            }
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(_) => unimplemented!("Marshal cannot be derived yet for enums"),
        Data::Union(_) => unimplemented!("Marshal cannot be derived yet for unions"),
    }
}


fn get_unmarshal_body(data: &Data, _: &[Attribute]) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let field_type = &f.ty;
                    quote_spanned! {f.span()=>
                        let #name = #field_type::untry_marshal(buffer)?;
                    }
                });
                quote! {
                    #(#recurse)*
                }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let var_name = Ident::new(&format!("f{}", i), Span::call_site());
                    let field_type = &f.ty;
                    quote_spanned! {f.span()=>
                        let (#var_name, added) = #field_type::untry_marshal(&buffer[read..])?;
                        read += added;
                    }
                });
                quote! {
                    #(#recurse)*
                }
            }
            Fields::Unit => unimplemented!("Marshal cannot be derived yet for unit fields"),
        },
        Data::Enum(_) => unimplemented!("Marshal cannot be derived yet for enums"),
        Data::Union(_) => unimplemented!("Marshal cannot be derived yet for unions"),
    }
}

fn get_field_list(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let list = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                        #name,
                    }
                });
                quote! {
                    #(#list)*
                }
            }
            Fields::Unnamed(ref fields) => {
                let list = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    let var_name = Ident::new(&format!("f{}", i), Span::call_site());
                    quote_spanned! {f.span()=>
                        #index: #var_name,
                    }
                });
                quote! {
                    #(#list)*
                }
            }
            Fields::Unit => unimplemented!("Marshal cannot be derived yet for unit fields"),
        },
        Data::Enum(_) => unimplemented!("Marshal cannot be derived yet for enums"),
        Data::Union(_) => unimplemented!("Marshal cannot be derived yet for unions"),
    }
}