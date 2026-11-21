//! HEL-RUST-007: a constructor discards a decoded numeric tag that a sibling
//! method later decodes again and converts with a panicking fallible conversion.

use super::peel;
use crate::Rule;
use proc_macro2::{Span, TokenStream, TokenTree};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Block, Expr, ExprCall, ExprMethodCall, Ident, ImplItem, ImplItemFn, ItemImpl, Local, Member,
    Pat, Stmt,
};

pub(super) const RULE: Rule<'static> = Rule {
    id: "HEL-RUST-007",
    cwe: Some("CWE-20"),
    severity: "medium",
    confidence: "medium",
    explanation: "A constructor decodes a numeric tag from its input slice but never validates it before storing the slice. Another method of the same type decodes the stored tag again and converts it with a call that panics when the value is invalid.",
    remediation: "Convert the decoded tag with a fallible conversion in the constructor and return an error when it is invalid, so later accessors can rely on a validated value.",
};

pub(super) fn inspect(item: &ItemImpl) -> Option<Span> {
    let methods: Vec<&ImplItemFn> = item
        .items
        .iter()
        .filter_map(|member| match member {
            ImplItem::Fn(function) => Some(function),
            _ => None,
        })
        .collect();
    methods.iter().find_map(|constructor| {
        let (decoder, field, span) = discarded_tag(constructor)?;
        methods
            .iter()
            .any(|accessor| accessor_converts(accessor, &decoder, &field))
            .then_some(span)
    })
}

fn ident_of(expr: &Expr) -> Option<&Ident> {
    match peel(expr) {
        Expr::Path(path) if path.qself.is_none() => path.path.get_ident(),
        _ => None,
    }
}

fn path_names(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

// Strip `?` and adapter calls such as `map_err` or `expect` to reach the decoder call.
fn decode_call(expr: &Expr) -> Option<&ExprCall> {
    match peel(expr) {
        Expr::Call(call) => Some(call),
        Expr::Try(value) => decode_call(&value.expr),
        Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "map_err" | "expect" | "unwrap"
            ) =>
        {
            decode_call(&call.receiver)
        }
        _ => None,
    }
}

/// `let (tag, rest) = decoder(arg, ..)` yields the decoder path, its first argument and the tag pattern.
fn decoding(local: &Local) -> Option<(Vec<String>, &Expr, &Pat)> {
    let Pat::Tuple(pattern) = &local.pat else {
        return None;
    };
    if pattern.elems.len() != 2 {
        return None;
    }
    let call = decode_call(&local.init.as_ref()?.expr)?;
    let Expr::Path(func) = peel(&call.func) else {
        return None;
    };
    if func.qself.is_some() {
        return None;
    }
    Some((
        path_names(&func.path),
        call.args.first()?,
        pattern.elems.first()?,
    ))
}

fn has_param(function: &ImplItemFn, name: &Ident) -> bool {
    function.sig.inputs.iter().any(|input| {
        matches!(input, syn::FnArg::Typed(typed)
            if matches!(&*typed.pat, Pat::Ident(binding) if binding.ident == *name)
            && matches!(&*typed.ty, syn::Type::Reference(r) if matches!(&*r.elem, syn::Type::Slice(s) if matches!(&*s.elem, syn::Type::Path(t) if t.path.is_ident("u8")))))
    })
}

fn discarded_tag(function: &ImplItemFn) -> Option<(Vec<String>, Ident, Span)> {
    if function.sig.receiver().is_some() {
        return None;
    }
    for statement in &function.block.stmts {
        let Stmt::Local(local) = statement else {
            continue;
        };
        let Some((decoder, argument, tag)) = decoding(local) else {
            continue;
        };
        let Some(input) = ident_of(argument).filter(|name| has_param(function, name)) else {
            continue;
        };
        let unused = match tag {
            Pat::Wild(_) => true,
            Pat::Ident(binding) => {
                binding.subpat.is_none() && !is_used(&function.block, &binding.ident)
            }
            _ => false,
        };
        if !unused {
            continue;
        }
        if let Some(field) = stored_field(&function.block, input) {
            return Some((decoder, field, tag.span()));
        }
    }
    None
}

struct Uses<'a> {
    name: &'a Ident,
    found: bool,
}

impl<'ast> Visit<'ast> for Uses<'_> {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.qself.is_none() && path.path.is_ident(self.name) {
            self.found = true;
        }
        visit::visit_expr_path(self, path);
    }

    // Macro arguments are unparsed; treat any mention as a use to stay conservative.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mentions(mac.tokens.clone(), self.name) {
            self.found = true;
        }
    }
}

fn mentions(tokens: TokenStream, name: &Ident) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(ident) => ident == *name,
        TokenTree::Group(group) => mentions(group.stream(), name),
        _ => false,
    })
}

fn is_used(block: &Block, name: &Ident) -> bool {
    let mut uses = Uses { name, found: false };
    uses.visit_block(block);
    uses.found
}

fn stored_field(block: &Block, input: &Ident) -> Option<Ident> {
    let Stmt::Expr(Expr::Call(ok), None) = block.stmts.last()? else {
        return None;
    };
    if !matches!(peel(&ok.func), Expr::Path(p) if p.path.is_ident("Ok")) || ok.args.len() != 1 {
        return None;
    }
    let Expr::Struct(value) = peel(ok.args.first()?) else {
        return None;
    };
    if !value.path.is_ident("Self") {
        return None;
    }
    value.fields.iter().find_map(|field| match &field.member {
        Member::Named(name) if ident_of(&field.expr) == Some(input) => Some(name.clone()),
        _ => None,
    })
}

fn accessor_converts(function: &ImplItemFn, decoder: &[String], field: &Ident) -> bool {
    if function.sig.receiver().is_none() {
        return false;
    }
    function.block.stmts.iter().any(|statement| {
        let Stmt::Local(local) = statement else {
            return false;
        };
        let Some((names, argument, Pat::Ident(projected))) = decoding(local) else {
            return false;
        };
        let Expr::Field(access) = peel(argument) else {
            return false;
        };
        names == decoder
            && ident_of(&access.base).is_some_and(|base| base == "self")
            && matches!(&access.member, Member::Named(name) if name == field)
            && panicking_conversion(&function.block, &projected.ident)
    })
}

struct Conversion<'a> {
    value: &'a Ident,
    found: bool,
}

impl<'ast> Visit<'ast> for Conversion<'_> {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if panics_when_invalid(call) && self.converts(&call.receiver) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, call);
    }
}

impl Conversion<'_> {
    fn converts(&self, expr: &Expr) -> bool {
        match peel(expr) {
            Expr::Call(call) => {
                matches!(peel(&call.func), Expr::Path(path)
                    if path.path.segments.last().is_some_and(|last| last.ident == "try_from"))
                    && call
                        .args
                        .iter()
                        .any(|argument| ident_of(argument) == Some(self.value))
            }
            Expr::MethodCall(call) => {
                call.method == "try_into"
                    && call.args.is_empty()
                    && ident_of(&call.receiver) == Some(self.value)
            }
            _ => false,
        }
    }
}

fn panicking_conversion(block: &Block, value: &Ident) -> bool {
    let mut conversion = Conversion {
        value,
        found: false,
    };
    conversion.visit_block(block);
    conversion.found
}

fn panics_when_invalid(call: &ExprMethodCall) -> bool {
    match (call.method.to_string().as_str(), call.args.len()) {
        ("unwrap", 0) | ("expect", 1) => true,
        ("unwrap_or_else", 1) => matches!(
            call.args.first().map(peel),
            Some(Expr::Closure(closure)) if diverges(&closure.body)
        ),
        _ => false,
    }
}

fn diverges(expr: &Expr) -> bool {
    let is_panic = |mac: &syn::Macro| {
        mac.path.segments.last().is_some_and(|last| {
            matches!(
                last.ident.to_string().as_str(),
                "panic" | "unreachable" | "unimplemented" | "todo"
            )
        })
    };
    match peel(expr) {
        Expr::Macro(value) => is_panic(&value.mac),
        Expr::Block(value) => match value.block.stmts.last() {
            Some(Stmt::Expr(inner, _)) => diverges(inner),
            Some(Stmt::Macro(value)) => is_panic(&value.mac),
            _ => false,
        },
        _ => false,
    }
}
