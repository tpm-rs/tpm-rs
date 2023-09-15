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
///  - The type is an enum type with #[repr(C, $primitive)] representation. The
///    generated code will include a discriminant() implementation, and will
///    {un}marshal the discriminant in BE format prior to the variant.

#[proc_macro_derive(Marshal, attributes(selector, length))]
pub fn derive_tpm_marshal(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let (marsh_text, unmarsh_text, disc_impl) = match input.data {
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
            let marshal_text = get_enum_marshal_body(&name, &enu, &input.attrs);
            let unmarshal_text = get_enum_unmarshal_body(&name, &enu, &input.attrs);
            let disc_text = get_enum_discriminant(&name, &input.attrs);
            (marshal_text, unmarshal_text, disc_text)
        }
        Data::Union(_) => {
            unimplemented!("Marshal cannot be derived for union types, which must implement Marshalable to provide selector->variant mappings");
        }
    };

    let expanded = quote! {
        #disc_impl
        // The generated impl.
        impl Marshalable for #name  {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> Result<Self, Tss2Rc> {
                #unmarsh_text
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> Result<usize, Tss2Rc> {
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
    let mut path = EnumRepr::None;
    for attr in attrs {
        if attr.path().is_ident("repr") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("C") {
                    c_repr = true;
                } else if is_uprimitive(&meta.path) {
                    if c_repr {
                        path = EnumRepr::CPrim(meta.path);
                    } else {
                        path = EnumRepr::Prim(meta.path);
                    }
                }
                Ok(())
            });
        }
    }
    path
}

// Produces a `discriminant` implementation for a #[repr(C, $primitive)] enum.
fn get_enum_discriminant(name: &Ident, attrs: &[Attribute]) -> TokenStream {
    if let EnumRepr::CPrim(prim) = get_enum_repr(attrs) {
        let disc = quote! {
            impl #name {
                // This is explicitly allowed for enums with primitive representation.
                // https://doc.rust-lang.org/std/mem/fn.discriminant.html#accessing-the-numeric-value-of-the-discriminant.
                fn discriminant(&self) -> #prim {
                    unsafe { *<*const _>::from(self).cast::<#prim>() }
                }
            }
        };
        return disc;
    }
    unimplemented!("Only enums with primitive discriminant representation may derive Marshal");
}

// Returns the BE type and whether using it requires a .get() call for `primitive`.
fn get_be_type_for(primitive: &Path) -> (TokenStream, bool) {
    if primitive.is_ident("u8") {
        return (quote! {#primitive}, false);
    } else if primitive.is_ident("u16") {
        return (quote! {U16}, true);
    } else if primitive.is_ident("u32") {
        return (quote! {U32}, true);
    } else if primitive.is_ident("u64") {
        return (quote! {U64}, true);
    }
    unimplemented!("Missing BE type mapping");
}

// Helper to get a BE discriminant for a #[repr(C, $primitive)] enum.
fn get_marshalable_discriminant(attrs: &[Attribute]) -> TokenStream {
    if let EnumRepr::CPrim(prim) = get_enum_repr(attrs) {
        let (be_type, needs_convert) = get_be_type_for(&prim);
        if needs_convert {
            return quote! {#be_type::new(self.discriminant())};
        } else {
            return quote! {self.discriminant()};
        }
    }
    unimplemented!("Enums with fields must have primitive representation for their discriminant");
}

// Helper to unmarshal a #[repr(C, $primitive)] discriminant.
fn get_enum_selector(attrs: &[Attribute]) -> (TokenStream, TokenStream) {
    if let EnumRepr::CPrim(prim) = get_enum_repr(attrs) {
        let (be_type, needs_get) = get_be_type_for(&prim);
        let unmarsh_selector = quote! {
            let selector = #be_type::try_unmarshal(buffer)?;
        };

        let get_selector = if needs_get {
            quote! {selector.get()}
        } else {
            quote! {selector}
        };
        return (unmarsh_selector, get_selector);
    }
    unimplemented!("Enums with fields must have primitive representation for their discriminant");
}

fn get_field_marshal_body(all_fields: &Fields) -> TokenStream {
    let mut basic_field_types = HashMap::new();
    match all_fields {
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
    }
}

fn get_enum_marshal_body(struct_name: &Ident, data: &DataEnum, attrs: &[Attribute]) -> TokenStream {
    let marsh_disc = get_marshalable_discriminant(attrs);
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
            unimplemented!("Enum fields cannot be named");
        }

        quote_spanned! {v.span()=>
            #struct_name::#var_name(#variant_fields) => {
                #field_marshal
            }
        }
    });
    quote! {
        written += #marsh_disc.try_marshal(buffer)?;
        match self {
            #(#list)*
        }
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

fn get_field_unmarshal(all_fields: &Fields) -> TokenStream {
    let mut basic_field_types = HashMap::new();
    match all_fields {
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
                        let usize_length = get_usize_length(
                            &length,
                            basic_field_types.get(length.get_ident().unwrap()),
                        );
                        quote_spanned! {f.span()=>
                            if #usize_length > #max_size {
                                return Err(TPM2_RC_SIZE);
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
                    let #var_name = #field_type::try_unmarshal(buffer)?;
                }
            });
            quote! {
                #(#recurse)*
            }
        }
        Fields::Unit => unimplemented!("Marshal cannot be derived yet for unit fields"),
    }
}

fn get_selection(disc: &Option<(syn::token::Eq, Expr)>) -> &Expr {
    if let Some((_, sel)) = disc {
        return sel;
    }
    unimplemented!("Enum variants must declare selectors");
}

fn get_enum_unmarshal_body(
    struct_name: &Ident,
    data: &DataEnum,
    attrs: &[Attribute],
) -> TokenStream {
    let (unmarsh_selector, get_selector) = get_enum_selector(attrs);
    let list = data.variants.iter().map(|v| {
        let var_name = &v.ident;
        let variant_unmarshal = get_field_unmarshal(&v.fields);
        let variant_fields = get_field_list(&v.fields);
        let var_sel = get_selection(&v.discriminant);
        quote_spanned! {v.span()=>
                #var_sel => {
                    #variant_unmarshal
                     Ok(#struct_name::#var_name(#variant_fields))
                }
        }
    });
    quote! {
        #unmarsh_selector
        match #get_selector {
            #(#list)*
            _ => Err(TPM2_RC_SELECTOR),
        }
    }
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
        Fields::Unit => unimplemented!("Marshal cannot be derived yet for unit fields"),
    }
}
