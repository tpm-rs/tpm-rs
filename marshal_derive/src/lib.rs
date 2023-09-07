use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DeriveInput, Fields, Ident, Index, Path, Expr, Type, 
};

#[proc_macro_derive(Marshal, attributes(selector, length))]
pub fn derive_tpm_marshal(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let marshal_text = get_marshal_body(&input.data, &input.attrs);
    let unmarshal_text = get_unmarshal_body(&input.data, &input.attrs);
    let field_list = get_field_list(&input.data);

    let expanded = quote! {
        // The generated impl.
        impl Marshalable for #name  {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> Result<Self, Tss2Rc> {
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
                    match get_marshal_attr(&f.attrs) {
                       Some(MarshalAttr::Selector(selector)) => {
                        quote_spanned! {f.span()=>
                            written += self.#name.try_marshal(self.#selector, &mut buffer[written..])?;
                        }
                    }, 
                        Some(MarshalAttr::Length(length)) => {
                            quote_spanned! {f.span()=>
                                for i in 0..self.#length as usize {
                                    written += self.#name[i].try_marshal(&mut buffer[written..])?;
                                }
                            }
                    },
                        None => {
                        quote_spanned! {f.span()=>
                            written += self.#name.try_marshal(&mut buffer[written..])?;
                        }
                    }
                }
                });
                quote! {
                    #(; #recurse)*
                }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        written += self.#index.try_marshal(&mut buffer[written..])?;
                    }
                });
                quote! {
                    #(#recurse)*
                }
            }
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(_) => unimplemented!("Marshal cannot be derived yet for enums"),
        Data::Union(_) => unimplemented!("Marshal cannot be derived yet for unions"),
    }
}

enum MarshalAttr {
    Selector(Path),
    Length(Path),
}

fn get_marshal_attr(attrs: &[Attribute]) -> Option<MarshalAttr> {
    let mut marshal_attr = None;
    for attr in attrs {
        if attr.path().is_ident("selector") {
            let _ = attr.parse_nested_meta(|meta| {
                if marshal_attr.is_some() {
                    unimplemented!("Only one selector or length is permitted.");
                }
                marshal_attr = Some(MarshalAttr::Selector(meta.path));
                Ok(())
            });
        }
        if attr.path().is_ident("length") {
            let _ = attr.parse_nested_meta(|meta| {
                if marshal_attr.is_some() {
                    unimplemented!("Only one selector or length is permitted.");
                }
                marshal_attr = Some(MarshalAttr::Length(meta.path));
                Ok(())
            });
        }
    }
    marshal_attr
}

fn get_array_default(field_type: &Type) -> (&Expr, &Type) {
    if let Type::Array(array) = field_type {
       (&array.len, &*array.elem)
    } else {
        unimplemented!("length attribute is only permitted for array types")
    }
}

fn get_unmarshal_body(data: &Data, _: &[Attribute]) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let field_type = &f.ty;
                    match get_marshal_attr(&f.attrs) {
                        Some(MarshalAttr::Selector(selector)) => {
                            quote_spanned! {f.span()=>
                                let #name = #field_type::try_unmarshal(#selector, buffer)?;
                            }
                        },
                        Some(MarshalAttr::Length(length)) => {
                            let (max_size, entry_type) = get_array_default(field_type);
                            quote_spanned! {f.span()=>
                                let mut #name = [#entry_type::default(); #max_size];
                                for i in #name.iter_mut().take(#length as usize) {
                                    *i = #entry_type::try_unmarshal(buffer)?;
                                }
                            }
                        }
                        None => {
                            quote_spanned! {f.span()=>
                                let #name = #field_type::try_unmarshal(buffer)?;
                            }
                        }
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
                        let (#var_name, added) = #field_type::try_unmarshal(&buffer[read..])?;
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
