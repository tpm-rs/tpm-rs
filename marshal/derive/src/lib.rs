#![forbid(unsafe_code)]

use std::collections::HashMap;

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DeriveInput, Expr, Fields,
    Ident, Index, Path, Type,
};

/// The Marshal derive macro generates an implementation of the Marshalable trait
/// for a struct by calling try_{un}marshal on each field in the struct. This
/// requires that the type of each field in the struct meets one of the
/// following conditions:
///  - The type implements zerocopy::AsBytes and zerocopy::FromBytes
///  - The type is an array, the array entry type also meets these Marshal
///    conditions, and the array field is tagged with the #[length($length_field)]
///    attribute, where $length_field is a field in the struct appearing before
///    the array field that can be converted to usize. In this case, the
///    generated code will {un}marshal first N entries in the array, where N is
///    the value of $length_field.
///  - The type is an enum type with #[repr(C, $primitive)] representation. The
///    generated code will include a discriminant() implementation that returns
///    $primitive, try_{un}marshal routines that accept an external selector, and will
///    {un}marshal the discriminant in BE format prior to the variant.

#[proc_macro_derive(Marshal, attributes(length))]
pub fn derive_tpm_marshal(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let (marsh_text, unmarsh_text, pure_impl) = match input.data {
        Data::Struct(stru) => {
            let marshal_text = get_field_marshal_body(&stru.fields);
            let field_list = get_field_list(&stru.fields);
            let instantiation = if let Fields::Unnamed(_) = stru.fields {
                quote! {#name(#field_list)}
            } else {
                quote! {#name{#field_list}}
            };
            let field_unmarsh = get_field_unmarshal(&stru.fields);
            let unmarshal_text = quote! {
                #field_unmarsh
                Ok(#instantiation)
            };
            (marshal_text, unmarshal_text, TokenStream::new())
        }
        Data::Enum(enu) => {
            let marshal_text = get_enum_marshal_impl(&name, &input.attrs);
            let unmarshal_text = get_enum_unmarshal_impl(&name, &input.attrs);
            let pure_impl = get_enum_impl(&name, &enu, &input.attrs);
            (marshal_text, unmarshal_text, pure_impl)
        }
        Data::Union(_) => {
            unimplemented!("Marshal cannot be derived for union type {}", name);
        }
    };

    let expanded = quote! {
        #pure_impl
        // The generated impl.
        impl Marshalable for #name  {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> tpm2_rs_marshal::exports::errors::TpmRcResult<Self> {
                #unmarsh_text
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_marshal::exports::errors::TpmRcResult<usize> {
                let mut written: usize = 0;
                #marsh_text;
                Ok(written)
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

// Different enum representation attributes.
enum EnumRepr {
    // #[repr(C, $primitive)]
    CPrim(Path),
    // #[repr($primitive)]
    Prim(Path),
    None,
}

// Returns whether `path` is an unsigned primitive.
fn is_uprimitive(path: &Path) -> bool {
    path.is_ident("u8") || path.is_ident("u16") || path.is_ident("u32") || path.is_ident("u64")
}

// Gets the EnumRepr from `attrs`.
fn get_enum_repr(attrs: &[Attribute]) -> EnumRepr {
    let mut c_repr = false;
    let mut prim = Option::None;

    // Go find any `C` and/or unsigned primitive in a #repr attribute.
    for attr in attrs {
        if attr.path().is_ident("repr") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("C") {
                    c_repr = true;
                } else if is_uprimitive(&meta.path) {
                    prim = Some(meta.path);
                }
                Ok(())
            });
        }
    }

    // Construct the appropriate EnumRepr from the findings.
    if let Some(p) = prim {
        if c_repr {
            EnumRepr::CPrim(p)
        } else {
            EnumRepr::Prim(p)
        }
    } else {
        EnumRepr::None
    }
}

// Produces a `discriminant` and variant {un}marshal implementations for a #[repr(C, $primitive)] enum.
fn get_enum_impl(name: &Ident, data: &DataEnum, attrs: &[Attribute]) -> TokenStream {
    let marshal_text = get_enum_marshal_body(name, data);
    let unmarshal_text = get_enum_unmarshal_body(name, data);
    if let EnumRepr::CPrim(prim) = get_enum_repr(attrs) {
        let pure_impl = quote! {
            impl #name {
                // This is explicitly allowed for enums with primitive representation.
                // https://doc.rust-lang.org/std/mem/fn.discriminant.html#accessing-the-numeric-value-of-the-discriminant.
                fn discriminant(&self) -> #prim {
                    unsafe { *<*const _>::from(self).cast::<#prim>() }
                }
                fn try_marshal_variant(&self, buffer: &mut [u8]) -> tpm2_rs_marshal::exports::errors::TpmRcResult<usize> {
                    let mut written: usize = 0;
                    #marshal_text;
                    Ok(written)
                }
                fn try_unmarshal_variant(selector: #prim, buffer: &mut UnmarshalBuf) -> tpm2_rs_marshal::exports::errors::TpmRcResult<Self> {
                    #unmarshal_text
                }
            }
        };
        return pure_impl;
    }
    unimplemented!(
        "Marshal cannot be derived for enum {} without primitive discriminant representation",
        name
    );
}

fn get_field_marshal_body(all_fields: &Fields) -> TokenStream {
    let mut basic_field_types = HashMap::new();
    match all_fields {
        Fields::Named(ref fields) => {
            let recurse = fields.named.iter().map(|f| {
                let name = &f.ident;
                if let Some(length) = get_marshal_length(name, &f.attrs) {
                    let length_prim =
                        get_primitive(&length, basic_field_types.get(length.get_ident().unwrap()));
                    quote_spanned! {f.span()=>
                        for i in 0..self.#length_prim as usize {
                            written += self.#name[i].try_marshal(&mut buffer[written..])?;
                        }
                    }
                } else if let Type::Array(array) = &f.ty {
                    let max_size = &array.len;
                    quote_spanned! {f.span()=>
                        for i in 0..#max_size {
                            written += self.#name[i].try_marshal(&mut buffer[written..])?;
                        }
                    }
                } else {
                    if let Some(ident) = name {
                        basic_field_types.insert(ident, f.ty.clone());
                    }
                    quote_spanned! {f.span()=>
                        written += self.#name.try_marshal(&mut buffer[written..])?;
                    }
                }
            });
            quote! {
                #(#recurse)*
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
        Fields::Unit => TokenStream::new(),
    }
}

fn get_enum_marshal_impl(name: &Ident, attrs: &[Attribute]) -> TokenStream {
    if let EnumRepr::CPrim(_) = get_enum_repr(attrs) {
        return quote! {
            written += self.discriminant().try_marshal(&mut buffer[written..])?;
            written += self.try_marshal_variant(&mut buffer[written..])?;
        };
    }
    unimplemented!(
        "Enum {} does not have primitive representation for its discriminant",
        name
    );
}

fn get_enum_marshal_body(struct_name: &Ident, data: &DataEnum) -> TokenStream {
    let list = data.variants.iter().map(|v| {
        let var_name = &v.ident;
        let field_marshal;
        let variant_fields = get_field_list(&v.fields);
        if let Fields::Unnamed(x) = &v.fields {
            let recurse = x.unnamed.iter().enumerate().map(|(i, f)| {
                let var_name = Ident::new(&format!("f{}", i), Span::call_site());
                quote_spanned! {f.span()=>
                    written += #var_name.try_marshal(&mut buffer[written..])?;
                }
            });
            field_marshal = quote! {
                #(#recurse)*
            }
        } else {
            unimplemented!("Cannot marshal enum {} with named fields", struct_name);
        }

        quote_spanned! {v.span()=>
            #struct_name::#var_name(#variant_fields) => {
                #field_marshal
            }
        }
    });
    quote! {
        match self {
            #(#list)*
        }
    }
}

fn get_marshal_length(name: &Option<Ident>, attrs: &[Attribute]) -> Option<Path> {
    let mut marshal_attr = None;
    for attr in attrs {
        if attr.path().is_ident("length") {
            let _ = attr.parse_nested_meta(|meta| {
                if marshal_attr.is_some() {
                    unimplemented!("Only one length is permitted for field {:?}", name);
                }
                marshal_attr = Some(meta.path);
                Ok(())
            });
        }
    }
    marshal_attr
}

fn get_array_default<'a>(name: &Option<Ident>, field_type: &'a Type) -> (&'a Expr, &'a Type) {
    if let Type::Array(array) = field_type {
        (&array.len, &*array.elem)
    } else {
        unimplemented!(
            "length attribute is not permitted for non-array field {:?}",
            name
        )
    }
}

// Gets a token stream for the primitive value of a var based on its type.
fn get_primitive(path: &Path, field_type: Option<&Type>) -> TokenStream {
    if field_type.is_none() {
        unimplemented!(
            "length field must appear before field {:?} using it in a length attribute",
            path.get_ident()
        );
    }
    quote! {
        #path
    }
}

fn get_field_unmarshal(all_fields: &Fields) -> TokenStream {
    let mut basic_field_types = HashMap::new();
    match all_fields {
        Fields::Named(ref fields) => {
            let recurse = fields.named.iter().map(|f| {
                let name = &f.ident;
                let field_type = &f.ty;
                if let Some(length) = get_marshal_length(name, &f.attrs) {
                    let (max_size, entry_type) = get_array_default(name, field_type);
                    let length_prim =
                        get_primitive(&length, basic_field_types.get(length.get_ident().unwrap()));
                    quote_spanned! {f.span()=>
                        if #length_prim as usize > #max_size {
                            return Err(TpmRcError::Size.into());
                        }
                        let mut #name = [#entry_type::default(); #max_size];
                        for i in #name.iter_mut().take(#length_prim as usize) {
                            *i = #entry_type::try_unmarshal(buffer)?;
                        }
                    }
                } else if let Type::Array(array) = &f.ty {
                    let max_size = &array.len;
                    let entry_type = &*array.elem;
                    quote_spanned! { f.span()=>
                        let mut #name = [#entry_type::default(); #max_size];
                        for i in #name.iter_mut().take(#max_size) {
                            *i = #entry_type::try_unmarshal(buffer)?;
                        }
                    }
                } else {
                    if let Some(ident) = name {
                        basic_field_types.insert(ident, field_type.clone());
                    }
                    quote_spanned! {f.span()=>
                        let #name = <#field_type>::try_unmarshal(buffer)?;
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
                    let #var_name = <#field_type>::try_unmarshal(buffer)?;
                }
            });
            quote! {
                #(#recurse)*
            }
        }
        Fields::Unit => TokenStream::new(),
    }
}

fn get_selection<'a>(var_name: &Ident, disc: &'a Option<(syn::token::Eq, Expr)>) -> &'a Expr {
    if let Some((_, sel)) = disc {
        return sel;
    }
    unimplemented!("Enum variant {} must declare a selector", var_name);
}

fn get_enum_unmarshal_impl(struct_name: &Ident, attrs: &[Attribute]) -> TokenStream {
    if let EnumRepr::CPrim(prim) = get_enum_repr(attrs) {
        return quote! {
            let selector = #prim::try_unmarshal(buffer)?;
            #struct_name::try_unmarshal_variant(selector, buffer)
        };
    }
    unimplemented!(
        "Enum {} does not have primitive representation for its discriminant",
        struct_name
    )
}

fn get_enum_unmarshal_body(struct_name: &Ident, data: &DataEnum) -> TokenStream {
    let mut conditional_code = TokenStream::new();

    for v in &data.variants {
        let var_name = &v.ident;
        let variant_unmarshal = get_field_unmarshal(&v.fields);
        let variant_fields = get_field_list(&v.fields);
        let var_sel = get_selection(var_name, &v.discriminant);

        let variant_code = quote_spanned! {v.span()=>
            if selector == #var_sel {
                #variant_unmarshal
                return Ok(#struct_name::#var_name(#variant_fields));
            }
        };

        conditional_code.extend(variant_code);
    }

    let fallback_code = quote! {
        Err(TpmRcError::Selector.into())
    };

    conditional_code.extend(fallback_code);

    conditional_code
}

fn get_field_list(all_fields: &Fields) -> TokenStream {
    match all_fields {
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
                let var_name = Ident::new(&format!("f{}", i), Span::call_site());
                quote_spanned! {f.span()=>
                    #var_name
                }
            });
            quote! {
                #(#list),*
            }
        }
        Fields::Unit => TokenStream::new(),
    }
}
