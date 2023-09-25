use std::collections::HashMap;

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DeriveInput, Expr, Fields, Ident, Index,
    Path, Type,
};

/// The Marshal derive macro generates an implementation of the Marshalable trait
/// for a struct by calling try_{un}marshal on each field in the struct. This
/// requires that the type of each field in the struct meets one of the
/// following conditions:
///  - The type implements zerocopy::AsBytes and zerocopy::FromBytes
///  - The type is a union type where the union field is tagged with the
///    #[selector($selector_field)] attribute, $selector_field is a field in the
///    struct appearing before the union field, and the union type implements
///    try_{un}marshal methods that accept the type of $selector_field as their
///    first parameter.
///  - The type is an array, the array entry type also meets these Marshal
///    conditions, and the array field is tagged with the #[length($length_field)]
///    attribute, where $length_field is a field in the struct appearing before
///    the array field that can be converted to usize. In this case, the
///    generated code will {un}marshal first N entries in the array, where N is
///    the value of $length_field.

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
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmResult<Self> {
                #unmarshal_text;
                Ok(#name{#field_list})

            }

            fn try_marshal(&self, buffer: &mut [u8]) -> TpmResult<usize> {
                let mut written: usize = 0;
                #marshal_text;
                Ok(written)
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

fn get_marshal_body(data: &Data, _: &[Attribute]) -> TokenStream {
    let mut basic_field_types = HashMap::new();
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
                            let usize_length = get_usize_length(&length, basic_field_types.get(length.get_ident().unwrap()));
                            quote_spanned! {f.span()=>
                                for i in 0..self.#usize_length {
                                    written += self.#name[i].try_marshal(&mut buffer[written..])?;
                                }
                            }
                    },
                        None => {
                            if let Some(ident) = name {
                                basic_field_types.insert(ident, f.ty.clone());
                            }
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
        Data::Union(_) => unimplemented!("Marshal cannot be derived for union types, which must implement Marshalable to provide selector->variant mappings"),
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

// Gets a token stream for the usize value of a var based on its type.
fn get_usize_length(path: &Path, field_type: Option<&Type>) -> TokenStream {
    if field_type.is_none() {
        unimplemented!("length field must appear before fields using it in a length attribute");
    }
    // Unlike other primitive ints, u8 doesn't have a separate big endian type.
    if let Some(Type::Path(x)) = field_type {
        if x.path.is_ident("u8") {
            return quote! {
                #path as usize
            };
        }
    }
    quote! {
        #path.get() as usize
    }
}

fn get_unmarshal_body(data: &Data, _: &[Attribute]) -> TokenStream {
    let mut basic_field_types = HashMap::new();
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
                        }
                        Some(MarshalAttr::Length(length)) => {
                            let (max_size, entry_type) = get_array_default(field_type);
                            let usize_length = get_usize_length(&length, basic_field_types.get(length.get_ident().unwrap()));
                            quote_spanned! {f.span()=>
                                if #usize_length > #max_size {
                                    return Err(TpmError::TPM2_RC_SIZE);
                                }
                                let mut #name = [#entry_type::default(); #max_size];
                                for i in #name.iter_mut().take(#usize_length) {
                                    *i = #entry_type::try_unmarshal(buffer)?;
                                }
                            }
                        }
                        None => {
                            if let Some(ident) = name {
                                basic_field_types.insert(ident, field_type.clone());
                            }
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
        Data::Union(_) => unimplemented!("Marshal cannot be derived for union types, which must implement Marshalable to provide selector->variant mappings"),
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
        Data::Union(_) => unimplemented!("Marshal cannot be derived for union types, which must implement Marshalable to provide selector->variant mappings"),
    }
}
