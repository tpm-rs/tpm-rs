#![forbid(unsafe_code)]

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, Error, Field, Fields, Ident,
    ItemEnum, Result, Token, Type, Variant, Visibility,
};

fn enum_fields_to_union_type(fields: Fields) -> Result<Option<Type>> {
    let fields_span = fields.span();
    let field_items = match fields {
        syn::Fields::Named(f) => f.named,
        syn::Fields::Unnamed(f) => f.unnamed,
        syn::Fields::Unit => {
            return Ok(None);
        }
    };
    if field_items.len() != 1 {
        // TODO maybe we should support that later.
        // The idea is to create a struct and put everything there,
        // but this struct will only be used by the union we build.
        return Err(Error::new(
            fields_span,
            "UnionSize is not derivable for enum variants containing more than one field",
        ));
    }
    // unwrap is safe here because we previusly checked that length of the
    // iterator is exactly 1
    let item = field_items.into_iter().next().unwrap();
    Ok(Some(item.ty))
}

/// converts enum variant to union field, we ignore all attributes there
/// we also ignore the discriminant, the general assumption is this is a
/// field in tagged enum, but if there is no tag, well it cannot be helped
/// but that will not stop us from gnerating equivalent union
/// we may return an error if enum_to_fields failed to do the conversion.
fn enum_variant_to_union_field(v: Variant) -> Result<Option<Field>> {
    let variant_ty = match enum_fields_to_union_type(v.fields)? {
        Some(ty) => ty,
        None => {
            return Ok(None);
        }
    };
    let field = Field {
        attrs: Vec::default(),
        vis: Visibility::Inherited,
        mutability: syn::FieldMutability::None,
        ident: Some(v.ident),
        colon_token: Some(Default::default()),
        ty: variant_ty,
    };
    Ok(Some(field))
}

/// combine an iterator of errors to single error.
/// Returns `Ok(())` if there is no errors to combine, other wise return `Err(t)` where t is the aggregate of all
/// errors in the iterator
fn errors_to_error<I: Iterator<Item = Error>>(mut errors: I) -> Result<()> {
    let Some(mut e1) = errors.next() else {
        return Ok(());
    };
    for e in errors {
        e1.combine(e);
    }
    Err(e1)
}

/// converts tagged enum to union
/// Returns error in on of those cases:
/// - If the enum is parametrized by any kind of generics
/// - The enum variant has more than one field
fn tagged_enum_to_union(tagged_enum: ItemEnum, union_name: &Ident) -> Result<TokenStream> {
    // so if there is any kind of generics, we product an error. Later we can handle
    // them if the need arises
    if !tagged_enum.generics.params.is_empty() {
        return Err(Error::new(
            tagged_enum.generics.span(),
            "UnionSize is only supported on enums without generics",
        ));
    }
    let (union_fields_vec, errors): (Vec<_>, Vec<_>) = tagged_enum
        .variants
        .into_iter()
        .map(enum_variant_to_union_field)
        .partition(Result::is_ok);
    errors_to_error(errors.into_iter().map(|e| e.err().unwrap()))?;
    let union_fields: Punctuated<Field, Token![,]> = union_fields_vec
        .into_iter()
        .filter_map(|t| t.unwrap())
        .collect();
    // we generated C like union, and we don't want the compiler to complain
    // about anything of the generated code
    let untagged_union = quote!(
        #[allow(warnings, unused)]
        #[repr(C)]
        union #union_name {
            #union_fields
        }
    );
    Ok(untagged_union)
}

/// build anonymous module containing the generated union, and trait implementation of
/// `UnionSize`
fn construct_module(tagged_enum: ItemEnum) -> Result<TokenStream> {
    let enum_ident = tagged_enum.ident.clone();
    let union_name = Ident::new("InnerUnion", Span::call_site());
    let union = tagged_enum_to_union(tagged_enum, &union_name)?;
    let module = quote! (
        const _ : () = {
            #union
            impl tpm2_rs_unionify::UnionSize for #enum_ident {
                const UNION_SIZE : usize = core::mem::size_of::<#union_name>();
            }
        };
    );
    Ok(module)
}

///top level macro
#[proc_macro_derive(UnionSize)]
pub fn derive_union_size(items: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let tagged_enum = parse_macro_input!(items as ItemEnum);
    match construct_module(tagged_enum) {
        Err(e) => e.to_compile_error().into(),
        Ok(s) => s.into(),
    }
}
