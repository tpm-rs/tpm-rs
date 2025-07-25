#![forbid(unsafe_code)]

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use std::collections::HashMap;
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DeriveInput, Error, Expr,
    ExprCall, ExprPath, Field, Fields, FieldsNamed, GenericArgument, Ident, Index, MetaNameValue,
    Path, PathArguments, Result, Type,
};

/// The Tpm2bStruct derive macro generates an implementation of the Tpm2bStruct trait
/// for a struct. This requires that the struct implements the Marshalable trait
/// as well, due to dependency to try_{un}marshal functions.
///
/// In order to generate the implementation of the trait, the derive mechanism requires
/// that the struct follows the following format:
///
/// pub struct Tpm2bNAME {
///     size: u16,
///     FIELD_NAME: [u8; SIZE_EXPRESSION],
/// }
///
/// The Tpm2bNAME is the name for the structure definition. The FIELD_NAME is the
/// name if the u8 array and the SIZE_EXPRESSION is a size_of::SOME_TYPE().
#[proc_macro_derive(Tpm2bStruct)]
pub fn derive_tpm_2b_struct(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_tpm_2b_struct_inner(input) {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_tpm_2b_struct_inner(input: DeriveInput) -> Result<TokenStream> {
    match &input.data {
        Data::Struct(data) => derive_tpm2b_struct(&input.ident, data),
        _ => Err(Error::new(
            input.span(),
            "The #[derive(Tpm2bStruct)] can only be applied to a struct.",
        )),
    }
}

fn derive_tpm2b_struct(
    tpm2b_outer_struct_name: &Ident,
    data_struct: &syn::DataStruct,
) -> Result<TokenStream> {
    const TPM2B_STRUCT_ERR_2ND_ELM: &str = "Second element in Tpm2b struct must define a u8 buffer using sizeof expression: <buffer name>: [u8, sizeof(<some struct>) ] when using #[derive(Tpm2bStruct)].";

    // Lets extracts the 2nd element u8 field name (&Ident) and its size expression (&Expr).
    let (field_name, size_expression) = derive_tpm2b_common(tpm2b_outer_struct_name, data_struct)?;

    // Lets extract the <some struct> name from tpm2b buffer definition <buffer name>: [u8, sizeof( <some struct>) ]
    // Extract the func, args.
    let Expr::Call(ExprCall { func, .. }) = size_expression else {
        return Err(Error::new(size_expression.span(), TPM2B_STRUCT_ERR_2ND_ELM));
    };

    // Check if the function being called is "sizeof"
    let Expr::Path(ExprPath { path, .. }) = &**func else {
        return Err(Error::new(func.span(), TPM2B_STRUCT_ERR_2ND_ELM));
    };

    // The path contains multiple elements, the first must be sizeof.
    let Some(segment) = path.segments.first() else {
        return Err(Error::new(func.span(), TPM2B_STRUCT_ERR_2ND_ELM));
    };
    if segment.ident != "size_of" {
        return Err(Error::new(path.segments.span(), TPM2B_STRUCT_ERR_2ND_ELM));
    };

    // Extract the size_of arguments.
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(Error::new(
            segment.arguments.span(),
            TPM2B_STRUCT_ERR_2ND_ELM,
        ));
    };

    let Some(struct_type) = arguments.args.first() else {
        return Err(Error::new(segment.span(), TPM2B_STRUCT_ERR_2ND_ELM));
    };

    let GenericArgument::Type(Type::Path(struct_path)) = struct_type else {
        return Err(Error::new(struct_type.span(), TPM2B_STRUCT_ERR_2ND_ELM));
    };

    let tpm2b_inner_struct_name = &struct_path.path;

    Ok(quote! {
        impl Tpm2bStruct for #tpm2b_outer_struct_name {
            type StructType = #tpm2b_inner_struct_name;

            fn from_struct(val: &Self::StructType) -> tpm2_rs_marshalable::Result<Self> {
                let mut x = Self::default();
                x.size = val.try_marshal(&mut x.#field_name)? as u16;
                Ok(x)
            }

            fn to_struct(&self) -> tpm2_rs_marshalable::Result<Self::StructType> {
                let mut buf = UnmarshalBuf::new(&self.as_ref());
                Self::StructType::try_unmarshal(&mut buf)
            }
        }
    })
}

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
    let has_tpm2b_simple = input
        .attrs
        .iter()
        .any(|attr| has_marshalable_attr(attr, "tpm2b_simple"));
    let has_tpm2b_struct = input
        .attrs
        .iter()
        .any(|attr| has_marshalable_attr(attr, "tpm2b_struct"));
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

            let pure_impl = if has_tpm2b_simple {
                derive_tpm2b_simple(&name, &stru)?
            } else {
                TokenStream::new()
            };

            (marshal_text, unmarshal_text, pure_impl)
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
    let expanded = if has_tpm2b_simple || has_tpm2b_struct {
        quote! {
            #pure_impl
        }
    } else {
        quote! {
            #pure_impl
            // The generated impl.
            impl Marshalable for #name  {
                fn try_unmarshal(buffer: &mut tpm2_rs_marshalable::UnmarshalBuf) -> tpm2_rs_marshalable::Result<Self> {
                    #unmarsh_text
                }

                fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::Result<usize> {
                    let mut written: usize = 0;
                    #marsh_text;
                    Ok(written)
                }
            }
        }
    };
    Ok(expanded)
}

fn derive_tpm2b_simple(
    tpm2b_outer_struct_name: &Ident,
    stru: &syn::DataStruct,
) -> Result<TokenStream> {
    // Lets extracts the 2nd element u8 field name (&Ident) and its size expression (&Expr).
    let (field_name, size_expression) = derive_tpm2b_common(tpm2b_outer_struct_name, stru)?;

    // First generate the actual code for structs marked with #[marshalable(tpm2b_simple)].
    let tpm2b_simple_code = quote! {
        // The generated impl.
        impl Tpm2bSimple for #tpm2b_outer_struct_name {
            const MAX_BUFFER_SIZE: usize = #size_expression;

            fn get_size(&self) -> u16 {
                self.size
            }

            fn get_buffer(&self) -> &[u8] {
                &self.#field_name[..self.get_size() as usize]
            }

            fn from_bytes(buffer: &[u8]) -> tpm2_rs_marshalable::Result<Self> {
                // Overflow check
                if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
                    return Err(tpm2_rs_marshalable::Error::ArrayLengthExceeded);
                }

                let mut dest: Self = Self {
                    size: buffer.len() as u16,
                    #field_name: [0; Self::MAX_BUFFER_SIZE],
                };
                dest.#field_name[..buffer.len()].copy_from_slice(buffer);
                Ok(dest)
            }
        }
        impl Default for #tpm2b_outer_struct_name {
            fn default() -> Self {
                Self {
                    size: 0,
                    #field_name: [0; Self::MAX_BUFFER_SIZE],
                }
            }
        }

        impl AsRef<[u8]> for #tpm2b_outer_struct_name {
            fn as_ref(&self) -> &[u8] {
                &self.#field_name[..self.size as usize]
            }
        }

        impl Marshalable for #tpm2b_outer_struct_name {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> tpm2_rs_marshalable::Result<Self> {
                let got_size = u16::try_unmarshal(buffer)?;
                // Ensure the buffer is large enough to fulfill the size indicated
                let sized_buffer = buffer.get(got_size as usize);
                if !sized_buffer.is_some() {
                    return Err(tpm2_rs_marshalable::Error::UnexpectedEndOfBuffer);
                }

                let mut dest: Self = Self {
                    size: got_size,
                    #field_name: [0; Self::MAX_BUFFER_SIZE],
                };

                // Make sure the size indicated isn't too large for the types buffer
                if sized_buffer.unwrap().len() > dest.#field_name.len() {
                    return Err(tpm2_rs_marshalable::Error::UnexpectedEndOfBuffer);
                }
                dest.#field_name[..got_size.into()].copy_from_slice(&sized_buffer.unwrap());

                Ok(dest)
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::Result<usize> {
                let used = self.size.try_marshal(buffer)?;
                let (_, rest) = buffer.split_at_mut(used);
                let buffer_marsh = self.get_size() as usize;
                if buffer_marsh > (core::cmp::max(Self::MAX_BUFFER_SIZE, rest.len())) {
                    return Err(tpm2_rs_marshalable::Error::UnexpectedEndOfBuffer);
                }
                rest[..buffer_marsh].copy_from_slice(&self.#field_name[..buffer_marsh]);
                Ok(used + buffer_marsh)
            }
        }
    };

    Ok(quote! { #tpm2b_simple_code })
}

// Extracts the 2nd element u8 field name (&Ident) and its size expression (&Expr).
// The size expression can both be a single value (usize) or a size_of::<SomeType>().
fn derive_tpm2b_common<'a>(
    tpm2b_outer_struct_name: &Ident,
    data_struct: &'a syn::DataStruct,
) -> Result<(&'a Ident, &'a Expr)> {
    const TPM2B_SIMPLE_ERR_GENERAL: &str =
        "A Tpm2b struct must contain just two elements, a u16 size and a buffer array";
    const TPM2B_SIMPLE_ERR_1ST_ELM: &str = "First element in Tpm2b struct must be a 'size: u16'";
    const TPM2B_SIMPLE_ERR_2ND_ELM: &str =
        "Second element in Tpm2b struct must be u8 buffer: <buffer name>: [u8, <buffer size>].";

    let Fields::Named(ref fields) = data_struct.fields else {
        return Err(Error::new(
            tpm2b_outer_struct_name.span(),
            TPM2B_SIMPLE_ERR_GENERAL,
        ));
    };

    let fields_vec: Vec<&Field> = fields.named.iter().collect();

    let (first, second) = match fields_vec.as_slice() {
        [first, second] => (first, second),
        _ => return Err(Error::new(fields.named.span(), TPM2B_SIMPLE_ERR_GENERAL)),
    };

    // Lets validate the first element is named size and has type u16.
    {
        let Some(field_name) = first.ident.as_ref() else {
            return Err(Error::new(first.ident.span(), TPM2B_SIMPLE_ERR_1ST_ELM));
        };
        let field_type = &first.ty;
        if field_name != "size"
            || !matches!(
                field_type,
                Type::Path(type_path) if type_path.path.is_ident("u16")
            )
        {
            return Err(Error::new(field_name.span(), TPM2B_SIMPLE_ERR_1ST_ELM));
        }
    }

    // Lets validate the second element in the Tpm2b structure and extract name and size expression.
    let field_name = second.ident.as_ref().unwrap();
    let field_type = &second.ty;

    // Expect array type.
    let Type::Array(type_array) = field_type else {
        return Err(Error::new(field_type.span(), TPM2B_SIMPLE_ERR_2ND_ELM));
    };

    // Extract the type used.
    let Type::Path(type_path) = &*type_array.elem else {
        return Err(Error::new(type_array.elem.span(), TPM2B_SIMPLE_ERR_2ND_ELM));
    };

    // Confirm it is an array of u8 elements.
    if !type_path.path.is_ident("u8") {
        return Err(Error::new(type_array.elem.span(), TPM2B_SIMPLE_ERR_2ND_ELM));
    };

    // Lets extract the size expression.
    Ok((field_name, &type_array.len))
}

fn has_marshalable_attr(attr: &Attribute, attribute: &str) -> bool {
    // Ensure the attribute path matches "Marshalable"
    if attr.path().is_ident("marshalable") {
        // Parse the arguments of the attribute
        attr.parse_args_with(|input: syn::parse::ParseStream| {
            // Look for the attribute given as input.
            while !input.is_empty() {
                let path: syn::Path = input.parse()?;
                if path.is_ident(attribute) {
                    return Ok(true);
                }
                // Skip over commas (if present) between arguments
                if input.peek(syn::Token![,]) {
                    let _comma: syn::Token![,] = input.parse()?;
                }
            }
            Ok(false)
        })
        .unwrap_or(false)
    } else {
        false
    }
}

/// Produces a variant {un}marshal implementations for an enum.
fn get_enum_impl(name: &Ident, data: &DataEnum) -> Result<TokenStream> {
    let marshal_text = get_enum_marshal_body(name, data)?;
    let unmarshal_text = get_enum_unmarshal_body(name, data)?;
    // TODO(#84): Move this to it's own derive proc-macro after cleaning up base.
    Ok(quote! {
        impl MarshalableVariant for #name {
            fn try_marshal_variant(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::Result<usize> {
                let mut written: usize = 0;
                #marshal_text;
                Ok(written)
            }

            fn try_unmarshal_variant(
                selector: <Self as safe_discriminant::Discriminant>::Repr,
                buffer: &mut tpm2_rs_marshalable::UnmarshalBuf) ->
                tpm2_rs_marshalable::Result<Self> {
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
    let span = Span::call_site().located_at(field.span());
    if let Some(length) = get_marshal_attribute(&field.attrs, "length")? {
        let length_prim =
            get_primitive(&length, basic_field_types.get(length.get_ident().unwrap()))?;
        Ok(quote_spanned! {span =>
            for i in 0..self.#length_prim as usize {
                written += self.#name[i].try_marshal(&mut buffer[written..])?;
            }
        })
    } else if let Type::Array(array) = &field.ty {
        let max_size = &array.len;
        Ok(quote_spanned! {span =>
            for i in 0..#max_size {
                written += self.#name[i].try_marshal(&mut buffer[written..])?;
            }
        })
    } else {
        if let Some(ident) = name {
            basic_field_types.insert(ident, field.ty.clone());
        }
        Ok(quote_spanned! {span =>
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
            let var_name = Ident::new(&format!("f{i}"), Span::call_site());
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
            format!("Unknown attribute: Expected `{key}`"),
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
    let span = Span::call_site().located_at(field.span());
    if let Some(length) = get_marshal_attribute(&field.attrs, "length")? {
        let (max_size, entry_type) = get_array_default(name, field_type)?;
        let length_prim =
            get_primitive(&length, basic_field_types.get(length.get_ident().unwrap()))?;
        Ok(quote_spanned! {span =>
            if #length_prim as usize > #max_size {
                return Err(tpm2_rs_marshalable::Error::ArrayLengthExceeded);
            }
            let mut #name = [#entry_type::default(); #max_size];
            for i in #name.iter_mut().take(#length_prim as usize) {
                *i = #entry_type::try_unmarshal(buffer)?;
            }
        })
    } else if let Type::Array(array) = &field.ty {
        let max_size = &array.len;
        let entry_type = &*array.elem;
        Ok(quote_spanned! { span =>
            let mut #name = [#entry_type::default(); #max_size];
            for i in #name.iter_mut().take(#max_size) {
                *i = #entry_type::try_unmarshal(buffer)?;
            }
        })
    } else {
        if let Some(ident) = name {
            basic_field_types.insert(ident, field_type.clone());
        }
        Ok(quote_spanned! {span =>
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
                let var_name = Ident::new(&format!("f{i}"), Span::call_site());
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
        Err(tpm2_rs_marshalable::Error::UnknownSelector)
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
                let var_name = Ident::new(&format!("f{i}"), Span::call_site());
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
