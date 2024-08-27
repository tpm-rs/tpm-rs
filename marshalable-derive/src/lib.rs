#![forbid(unsafe_code)]

use std::collections::HashMap;

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DeriveInput, Error, Expr,
    Field, Fields, FieldsNamed, Ident, Index, MetaNameValue, Path, Result, Type,
};

/// The Marshalable derive macro generates an implementation of the Marshalable trait
/// for a struct by calling try_{un}marshal on each field in the struct. This
/// requires that the type of each field in the struct meets one of the
/// following conditions:
///  - The type implements zerocopy::AsBytes and zerocopy::FromBytes
///  - The type is an array, the array entry type also meets these Marshal
///    conditions, and the array field is tagged with the #[marshalable(length = $length_field)]
///    attribute, where $length_field is a field in the struct appearing before
///    the array field that can be converted to usize. In this case, the
///    generated code will {un}marshal first N entries in the array, where N is
///    the value of $length_field.
///  - The type is an enum type with #[repr(C, $primitive)] representation. The
///    generated code will include a discriminant() implementation that returns
///    $primitive, try_{un}marshal routines that accept an external selector, and will
///    {un}marshal the discriminant in BE format prior to the variant.

#[proc_macro_derive(Marshalable, attributes(marshalable))]
pub fn derive_tpm_marshal(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_tpm_marshal_inner(input) {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_tpm_marshal_inner(input: DeriveInput) -> Result<TokenStream> {
    let input_span = input.span();
    let name = input.ident;
    let (marsh_text, unmarsh_text, pure_impl) = match input.data {
        Data::Struct(stru) => {
            let marshal_text = get_field_marshal_body(&stru.fields)?;
            let field_list = get_field_list(&stru.fields);
            let instantiation = if let Fields::Unnamed(_) = stru.fields {
                quote! {#name(#field_list)}
            } else {
                quote! {#name{#field_list}}
            };
            let field_unmarsh = get_field_unmarshal(&stru.fields)?;
            let unmarshal_text = quote! {
                #field_unmarsh
                Ok(#instantiation)
            };
            (marshal_text, unmarshal_text, TokenStream::new())
        }
        Data::Enum(enu) => {
            let marshal_text = get_enum_marshal_impl();
            let unmarshal_text = get_enum_unmarshal_impl();
            let pure_impl = get_enum_impl(&name, &enu)?;
            (marshal_text, unmarshal_text, pure_impl)
        }
        Data::Union(_) => {
            return Err(Error::new(
                input_span.span(),
                "Marshalable cannot be derived for union type",
            ));
        }
    };
    let expanded = quote! {
        const _: () = {
            #pure_impl
            // The generated impl.
            impl Marshalable for #name  {
                fn try_unmarshal(buffer: &mut tpm2_rs_marshalable::UnmarshalBuf) -> tpm2_rs_marshalable::__private::TpmRcResult<Self> {
                    #unmarsh_text
                }

                fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::__private::TpmRcResult<usize> {
                    let mut written: usize = 0;
                    #marsh_text;
                    Ok(written)
                }
            }
        };
    };

    Ok(expanded)
}

/// Produces a variant {un}marshal implementations for an enum.
fn get_enum_impl(name: &Ident, data: &DataEnum) -> Result<TokenStream> {
    let marshal_text = get_enum_marshal_body(name, data)?;
    let unmarshal_text = get_enum_unmarshal_body(name, data)?;
    // TODO(#84): Move this to it's own derive proc-macro after cleaning up base.
    Ok(quote! {
        impl MarshalableVariant for #name {
            fn try_marshal_variant(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::__private::TpmRcResult<usize> {
                let mut written: usize = 0;
                #marshal_text;
                Ok(written)
            }

            fn try_unmarshal_variant(
                selector: <Self as safe_discriminant::Discriminant>::Repr,
                buffer: &mut tpm2_rs_marshalable::UnmarshalBuf) ->
                tpm2_rs_marshalable::__private::TpmRcResult<Self> {
                #unmarshal_text
            }
        }
    })
}

fn get_named_field_marshal<'a>(
    basic_field_types: &mut HashMap<&'a Ident, Type>,
    field: &'a Field,
) -> Result<TokenStream> {
    let name = &field.ident;
    if let Some(length) = get_marshal_attribute(&field.attrs, "length")? {
        let length_prim =
            get_primitive(&length, basic_field_types.get(length.get_ident().unwrap()))?;
        Ok(quote_spanned! {field.span()=>
            for i in 0..self.#length_prim as usize {
                written += self.#name[i].try_marshal(&mut buffer[written..])?;
            }
        })
    } else if let Type::Array(array) = &field.ty {
        let max_size = &array.len;
        Ok(quote_spanned! {field.span()=>
            for i in 0..#max_size {
                written += self.#name[i].try_marshal(&mut buffer[written..])?;
            }
        })
    } else {
        if let Some(ident) = name {
            basic_field_types.insert(ident, field.ty.clone());
        }
        Ok(quote_spanned! {field.span()=>
            written += self.#name.try_marshal(&mut buffer[written..])?;
        })
    }
}

fn get_named_fields_marshal<'a>(
    basic_field_types: &mut HashMap<&'a Ident, Type>,
    fields: &'a FieldsNamed,
) -> Result<TokenStream> {
    let mut errors = Vec::new();
    let mut recurse = Vec::new();
    for field in fields.named.iter() {
        match get_named_field_marshal(basic_field_types, field) {
            Ok(r) => recurse.push(r),
            Err(e) => errors.push(e),
        };
    }
    errors_to_error(errors.into_iter())?;
    Ok(quote! {
        #(#recurse)*
    })
}

fn get_field_marshal_body(all_fields: &Fields) -> Result<TokenStream> {
    let mut basic_field_types = HashMap::new();
    match all_fields {
        Fields::Named(ref fields) => get_named_fields_marshal(&mut basic_field_types, fields),
        Fields::Unnamed(ref fields) => {
            let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                let index = Index::from(i);
                quote_spanned! {f.span()=>
                    written += self.#index.try_marshal(&mut buffer[written..])?;
                }
            });
            Ok(quote! {
                #(#recurse)*
            })
        }
        Fields::Unit => Ok(TokenStream::new()),
    }
}

fn get_enum_marshal_impl() -> TokenStream {
    quote! {
        written += self.discriminant().try_marshal(&mut buffer[written..])?;
        written += self.try_marshal_variant(&mut buffer[written..])?;
    }
}

fn errors_to_error<I: Iterator<Item = Error>>(mut errors: I) -> Result<()> {
    let Some(mut e1) = errors.next() else {
        return Ok(());
    };
    for e in errors {
        e1.combine(e);
    }
    Err(e1)
}

fn get_enum_marshal_body(struct_name: &Ident, data: &DataEnum) -> Result<TokenStream> {
    let mut errors = Vec::new();
    let mut list = Vec::new();
    for v in &data.variants {
        let var_name = &v.ident;
        let variant_fields = get_field_list(&v.fields);
        let Fields::Unnamed(x) = &v.fields else {
            errors.push(Error::new(
                v.fields.span(),
                "Cannot marshal named field in an enum",
            ));
            continue;
        };
        let recurse = x.unnamed.iter().enumerate().map(|(i, f)| {
            let var_name = Ident::new(&format!("f{}", i), Span::call_site());
            quote_spanned! {f.span()=>
                written += #var_name.try_marshal(&mut buffer[written..])?;
            }
        });
        list.push(quote_spanned! {v.span()=>
            #struct_name::#var_name(#variant_fields) => {
                #(#recurse)*
            }
        })
    }
    errors_to_error(errors.into_iter())?;
    Ok(quote! {
        match self {
            #(#list)*
        }
    })
}

fn get_marshal_attribute(attrs: &[Attribute], key: &str) -> Result<Option<Path>> {
    let mut marshal_attr: Option<MetaNameValue> = None;
    for attr in attrs {
        if attr.path().is_ident("marshalable") {
            if marshal_attr.is_some() {
                return Err(Error::new(
                    attr.span(),
                    "Only one #[marshalable(...)] is permitted for field",
                ));
            }
            marshal_attr = Some(attr.parse_args()?);
        }
    }
    let Some(marshal_attr) = marshal_attr else {
        return Ok(None);
    };
    if !marshal_attr.path.is_ident(key) {
        return Err(Error::new(
            marshal_attr.path.span(),
            format!("Unknown attribute: Expected `{}`", key),
        ));
    };
    let Expr::Path(expr_path) = marshal_attr.value else {
        return Err(Error::new(
            marshal_attr.value.span(),
            "Unknown expression: Expected identifier",
        ));
    };
    if !expr_path.attrs.is_empty() {
        return Err(Error::new(
            expr_path.span(),
            "Attributes are not allowed here",
        ));
    };
    if expr_path.qself.is_some() {
        return Err(Error::new(
            expr_path.span(),
            "Explicit Self types are not allowed here",
        ));
    };
    Ok(Some(expr_path.path))
}

fn get_array_default<'a>(
    name: &Option<Ident>,
    field_type: &'a Type,
) -> Result<(&'a Expr, &'a Type)> {
    if let Type::Array(array) = field_type {
        Ok((&array.len, &*array.elem))
    } else {
        Err(Error::new(
            name.span(),
            "length attribute is not permitted for non-array field",
        ))
    }
}

// Gets a token stream for the primitive value of a var based on its type.
fn get_primitive(path: &Path, field_type: Option<&Type>) -> Result<TokenStream> {
    if field_type.is_none() {
        Err(Error::new(
            path.get_ident().span(),
            format!(
                "length field must appear before field {:?} using it in a length attribute",
                path.get_ident()
            ),
        ))
    } else {
        Ok(quote! {
            #path
        })
    }
}

fn get_named_field_unmarshal<'a>(
    basic_field_types: &mut HashMap<&'a Ident, Type>,
    field: &'a Field,
) -> Result<TokenStream> {
    let name = &field.ident;
    let field_type = &field.ty;
    if let Some(length) = get_marshal_attribute(&field.attrs, "length")? {
        let (max_size, entry_type) = get_array_default(name, field_type)?;
        let length_prim =
            get_primitive(&length, basic_field_types.get(length.get_ident().unwrap()))?;
        Ok(quote_spanned! {field.span()=>
            if #length_prim as usize > #max_size {
                return Err(TpmRcError::Size);
            }
            let mut #name = [#entry_type::default(); #max_size];
            for i in #name.iter_mut().take(#length_prim as usize) {
                *i = #entry_type::try_unmarshal(buffer)?;
            }
        })
    } else if let Type::Array(array) = &field.ty {
        let max_size = &array.len;
        let entry_type = &*array.elem;
        Ok(quote_spanned! { field.span()=>
            let mut #name = [#entry_type::default(); #max_size];
            for i in #name.iter_mut().take(#max_size) {
                *i = #entry_type::try_unmarshal(buffer)?;
            }
        })
    } else {
        if let Some(ident) = name {
            basic_field_types.insert(ident, field_type.clone());
        }
        Ok(quote_spanned! {field.span()=>
            let #name = <#field_type>::try_unmarshal(buffer)?;
        })
    }
}

fn get_named_fields_unmarshal<'a>(
    basic_field_types: &mut HashMap<&'a Ident, Type>,
    fields: &'a FieldsNamed,
) -> Result<TokenStream> {
    let mut errors = Vec::new();
    let mut recurse = Vec::new();
    for field in fields.named.iter() {
        match get_named_field_unmarshal(basic_field_types, field) {
            Ok(r) => recurse.push(r),
            Err(e) => errors.push(e),
        };
    }
    errors_to_error(errors.into_iter())?;
    Ok(quote! {
        #(#recurse)*
    })
}
fn get_field_unmarshal(all_fields: &Fields) -> Result<TokenStream> {
    let mut basic_field_types = HashMap::new();
    match all_fields {
        Fields::Named(ref fields) => get_named_fields_unmarshal(&mut basic_field_types, fields),
        Fields::Unnamed(ref fields) => {
            let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                let var_name = Ident::new(&format!("f{}", i), Span::call_site());
                let field_type = &f.ty;
                quote_spanned! {f.span()=>
                    let #var_name = <#field_type>::try_unmarshal(buffer)?;
                }
            });
            Ok(quote! {
                #(#recurse)*
            })
        }
        Fields::Unit => Ok(TokenStream::new()),
    }
}

fn get_selection<'a>(
    var_name: &Ident,
    disc: &'a Option<(syn::token::Eq, Expr)>,
) -> Result<&'a Expr> {
    match disc {
        Some((_, sel)) => Ok(sel),
        None => Err(Error::new(
            var_name.span(),
            "Enum variant must declare a selector",
        )),
    }
}

fn get_enum_unmarshal_impl() -> TokenStream {
    quote! {
        let selector =
            <Self as safe_discriminant::Discriminant>::
            Repr::try_unmarshal(buffer)?;
        Self::try_unmarshal_variant(selector, buffer)
    }
}

fn get_enum_unmarshal_body(struct_name: &Ident, data: &DataEnum) -> Result<TokenStream> {
    let mut conditional_code = TokenStream::new();
    let mut errors = Vec::new();
    for v in &data.variants {
        let var_name = &v.ident;
        let variant_unmarshal = match get_field_unmarshal(&v.fields) {
            Err(e) => {
                errors.push(e);
                continue;
            }
            Ok(v) => v,
        };
        let variant_fields = get_field_list(&v.fields);
        let var_sel = get_selection(var_name, &v.discriminant)?;

        let variant_code = quote_spanned! {v.span()=>
            if selector == #var_sel {
                #variant_unmarshal
                return Ok(#struct_name::#var_name(#variant_fields));
            }
        };

        conditional_code.extend(variant_code);
    }
    errors_to_error(errors.into_iter())?;
    let fallback_code = quote! {
        Err(TpmRcError::Selector.into())
    };

    conditional_code.extend(fallback_code);

    Ok(conditional_code)
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
