use super::peel;
use crate::Rule;
use proc_macro2::Span;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::{Block, Expr, Ident, Lit, Pat, Signature, Stmt, Type};

pub(super) const RULE: Rule<'static> = Rule {
    id: "HEL-RUST-006",
    cwe: Some("CWE-22"),
    severity: "medium",
    confidence: "medium",
    explanation: "A string path is split on slash and each segment is pushed onto a base path. The checks reject parent-like and backslash-containing segments but leave Windows path prefixes unchecked.",
    remediation: "Validate each segment as a single normal path component under the target platform's path rules before appending it.",
};

fn name(expr: &Expr) -> Option<&Ident> {
    match peel(expr) {
        Expr::Path(path) => path.path.get_ident(),
        _ => None,
    }
}

fn binding(pat: &Pat) -> Option<&Ident> {
    match pat {
        Pat::Ident(p) if p.subpat.is_none() => Some(&p.ident),
        Pat::Type(p) => binding(&p.pat),
        _ => None,
    }
}

fn literal(expr: &Expr, expected: &str) -> bool {
    let Expr::Lit(lit) = peel(expr) else {
        return false;
    };
    match &lit.lit {
        Lit::Char(c) => expected.chars().count() == 1 && expected.starts_with(c.value()),
        Lit::Str(s) => s.value() == expected,
        _ => false,
    }
}

// Follow simple text-preserving operations from a string parameter. A call to
// an unknown validator or a successful match arm transforming the text breaks
// the trace. Percent decoding on its own provides no path-component guarantee.
fn text_origin(expr: &Expr, text: &HashSet<Ident>) -> bool {
    match peel(expr) {
        Expr::Path(_) => name(expr).is_some_and(|id| text.contains(id)),
        Expr::Try(e) => text_origin(&e.expr, text),
        Expr::Reference(e) => text_origin(&e.expr, text),
        Expr::Call(c) => {
            matches!(peel(&c.func), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident=="percent_decode" || s.ident=="percent_decode_str"))
                && c.args.len() == 1
                && text_origin(&c.args[0], text)
        }
        Expr::MethodCall(c) => {
            let preserving = (c.args.is_empty()
                && matches!(
                    c.method.to_string().as_str(),
                    "as_ref" | "as_bytes" | "decode_utf8" | "ok"
                ))
                || (c.method == "trim_start_matches"
                    && c.args.len() == 1
                    && literal(&c.args[0], "/"));
            preserving && text_origin(&c.receiver, text)
        }
        Expr::Match(m) => {
            m.arms.len() == 2
                && m.arms.iter().all(|arm| {
                    let Pat::TupleStruct(p) = &arm.pat else {
                        return false;
                    };
                    if arm.guard.is_some() || p.elems.len() != 1 {
                        return false;
                    }
                    if p.path.is_ident("Ok") {
                        binding(&p.elems[0]).is_some_and(|id| name(&arm.body) == Some(id))
                    } else {
                        p.path.is_ident("Err")
                            && matches!(peel(&arm.body),Expr::Block(b) if rejects(&b.block))
                    }
                })
                && text_origin(&m.expr, text)
        }
        _ => false,
    }
}

fn rejects(block: &Block) -> bool {
    matches!(
        block.stmts.last(),
        Some(Stmt::Expr(Expr::Return(_) | Expr::Continue(_), _))
    )
}

fn path_buffer(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::MethodCall(c) => c.method == "to_path_buf" && c.args.is_empty(),
        Expr::Call(c) => {
            let Expr::Path(p) = peel(&c.func) else {
                return false;
            };
            let mut tail = p.path.segments.iter().rev();
            c.args.len() == 1
                && tail.next().is_some_and(|s| s.ident == "from")
                && tail.next().is_some_and(|s| s.ident == "PathBuf")
        }
        _ => false,
    }
}

#[derive(Default)]
struct Rejections {
    parent: bool,
    separator: bool,
}

impl Rejections {
    fn record(&mut self, condition: &Expr, segment: &Ident) -> bool {
        match peel(condition) {
            Expr::Binary(b) if matches!(b.op, syn::BinOp::Or(_)) => {
                self.record(&b.left, segment) && self.record(&b.right, segment)
            }
            Expr::MethodCall(c) if name(&c.receiver) == Some(segment) && c.args.len() == 1 => {
                if c.method == "starts_with" && literal(&c.args[0], "..") {
                    self.parent = true;
                } else if c.method == "contains" && literal(&c.args[0], "\\") {
                    self.separator = true;
                } else {
                    return false;
                }
                true
            }
            _ => false,
        }
    }

    // Only follow fall-through after guards that reject a segment. Unknown
    // guards make the branch inconclusive, including platform-specific ones.
    fn sink(&mut self, expr: &Expr, segment: &Ident, buffer: &Ident) -> Option<Span> {
        match peel(expr) {
            Expr::If(i) if rejects(&i.then_branch) && self.record(&i.cond, segment) => {
                match &i.else_branch {
                    Some((_, alt)) => self.sink(alt, segment, buffer),
                    None => None,
                }
            }
            Expr::Block(b) if b.block.stmts.len() == 1 => {
                let Stmt::Expr(e, _) = &b.block.stmts[0] else {
                    return None;
                };
                self.sink(e, segment, buffer)
            }
            Expr::MethodCall(c)
                if c.method == "push"
                    && c.args.len() == 1
                    && name(&c.receiver) == Some(buffer)
                    && name(&c.args[0]) == Some(segment)
                    && self.parent
                    && self.separator =>
            {
                Some(c.span())
            }
            _ => None,
        }
    }
}

pub(super) fn inspect(sig: &Signature, body: &Block) -> Option<(Span, &'static str)> {
    let (last, before_return) = body.stmts.split_last()?;
    let Stmt::Expr(Expr::Call(returned), None) = last else {
        return None;
    };
    if !matches!(peel(&returned.func), Expr::Path(p) if p.path.is_ident("Some") || p.path.is_ident("Ok"))
        || returned.args.len() != 1
    {
        return None;
    }
    let buffer = name(&returned.args[0])?;
    let (loop_stmt, setup) = before_return.split_last()?;
    let Stmt::Expr(Expr::ForLoop(f), _) = loop_stmt else {
        return None;
    };
    let segment = binding(&f.pat)?;
    let Expr::MethodCall(split) = peel(&f.expr) else {
        return None;
    };
    if split.method != "split" || split.args.len() != 1 || !literal(&split.args[0], "/") {
        return None;
    }

    let mut text = HashSet::new();
    for arg in &sig.inputs {
        if let syn::FnArg::Typed(arg) = arg {
            if matches!(arg.ty.as_ref(),Type::Reference(r) if matches!(r.elem.as_ref(),Type::Path(p) if p.path.is_ident("str")))
            {
                if let Some(id) = binding(&arg.pat) {
                    text.insert(id.clone());
                }
            }
        }
    }
    let mut is_buffer = false;
    for stmt in setup {
        match stmt {
            Stmt::Local(local) => {
                let id = binding(&local.pat)?;
                let init = &local.init.as_ref()?.expr;
                let traced = text_origin(init, &text);
                text.remove(id);
                if traced {
                    text.insert(id.clone());
                }
                if id == buffer {
                    is_buffer = path_buffer(init);
                } else if !traced {
                    // A validation result can narrow the accepted path even if
                    // the loop does not read the value bound here.
                    return None;
                }
            }
            Stmt::Macro(m)
                if m.mac.path.segments.last().is_some_and(|s| {
                    matches!(s.ident.to_string().as_str(), "trace" | "debug" | "info")
                }) => {}
            _ => return None,
        }
    }
    if !is_buffer || !text_origin(&split.receiver, &text) {
        return None;
    }
    let (last, guards) = f.body.stmts.split_last()?;
    let mut rejected = Rejections::default();
    for stmt in guards {
        let Stmt::Expr(Expr::If(i), _) = stmt else {
            return None;
        };
        if i.else_branch.is_some() || !rejects(&i.then_branch) || !rejected.record(&i.cond, segment)
        {
            return None;
        }
    }
    let Stmt::Expr(e, _) = last else { return None };
    let span = rejected.sink(e, segment, buffer)?;
    Some((
        span,
        "Caller-supplied path segments reach the returned path buffer after only parent and separator rejection. Windows prefixes require a separate component check.",
    ))
}
