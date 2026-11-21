use super::{method, peel};
use crate::Rule;
use syn::{Block, Expr, ExprIf, Ident, Lit, Pat, Stmt, Type, UnOp};

pub(super) const RULE: Rule<'static> = Rule {
    id: "HEL-RUST-005",
    cwe: Some("CWE-88"),
    severity: "medium",
    confidence: "medium",
    explanation: "A shell-style quoting branch returns the original bytes when its character list does not match. The list omits a character that can affect argument boundaries.",
    remediation: "Prefer passing arguments directly. When shell quoting is required, use a maintained quoting implementation with an explicit policy for unquoted bytes.",
};

fn name(expr: &Expr) -> Option<&Ident> {
    let Expr::Path(path) = peel(expr) else {
        return None;
    };
    path.path.get_ident()
}

fn converted_input(block: &Block) -> Option<&Ident> {
    let [Stmt::Expr(expr, None)] = &block.stmts[..] else {
        return None;
    };
    let call = method(expr, "into")?;
    if !call.args.is_empty() {
        return None;
    }
    name(&call.receiver)
}

// Treat unknown or guarded patterns as inconclusive. A literal-only match with
// a final false wildcard lets us compute exactly which bytes trigger quoting.
fn quote_set(expr: &syn::ExprMatch) -> Option<[bool; 256]> {
    let (fallback, arms) = expr.arms.split_last()?;
    if !matches!(fallback.pat, Pat::Wild(_))
        || fallback.guard.is_some()
        || !matches!(peel(&fallback.body), Expr::Lit(l) if matches!(&l.lit, Lit::Bool(b) if !b.value))
    {
        return None;
    }
    let mut set = [false; 256];
    for arm in arms {
        if arm.guard.is_some()
            || !matches!(peel(&arm.body), Expr::Lit(l) if matches!(&l.lit, Lit::Bool(b) if b.value))
        {
            return None;
        }
        let pats = match &arm.pat {
            Pat::Or(p) => p.cases.iter().collect::<Vec<_>>(),
            p => vec![p],
        };
        for pat in pats {
            let Pat::Lit(l) = pat else { return None };
            let Lit::Char(c) = &l.lit else { return None };
            if let Ok(b) = u8::try_from(u32::from(c.value())) {
                set[usize::from(b)] = true
            }
        }
    }
    Some(set)
}

pub(super) fn omission(branch: &ExprIf) -> Option<&'static str> {
    let Expr::Block(other) = peel(&branch.else_branch.as_ref()?.1) else {
        return None;
    };
    let input = converted_input(&other.block)?;
    let any = method(&branch.cond, "any")?;
    let iter = method(&any.receiver, "iter")?;
    if !iter.args.is_empty() || name(&iter.receiver)? != input || any.args.len() != 1 {
        return None;
    }
    let Expr::Closure(predicate) = peel(any.args.first()?) else {
        return None;
    };
    let Pat::Ident(binding) = predicate.inputs.first()? else {
        return None;
    };
    let Expr::Match(m) = peel(&predicate.body) else {
        return None;
    };
    let Expr::Cast(cast) = peel(&m.expr) else {
        return None;
    };
    let Expr::Unary(deref) = peel(&cast.expr) else {
        return None;
    };
    if !matches!(cast.ty.as_ref(), Type::Path(t) if t.path.is_ident("char"))
        || !matches!(deref.op, UnOp::Deref(_))
        || name(&deref.expr)? != &binding.ident
    {
        return None;
    }
    let set = quote_set(m)?;
    // Require shell-specific delimiters plus an output buffer wrapped in quotes.
    if !b"$`|&;".iter().all(|b| set[usize::from(*b)]) {
        return None;
    }
    let (last, prefix) = branch.then_branch.stmts.split_last()?;
    let Stmt::Expr(result, None) = last else {
        return None;
    };
    let result = method(result, "into")?;
    let output = name(&result.receiver)?;
    let wrap = prefix.iter().filter(|stmt| {
        let Stmt::Expr(expr, _) = stmt else {return false};
        method(expr,"push").is_some_and(|c| name(&c.receiver)==Some(output)
            && matches!(c.args.first(),Some(Expr::Lit(l)) if matches!(&l.lit,Lit::Byte(b) if b.value()==b'"')))
    }).count();
    if wrap < 2 {
        return None;
    }
    match (set[usize::from(b'{')],set[0xa0]) {
        (false,false) => Some("The unmodified-input branch omits opening brace and non-breaking space from its quote predicate."),
        (false,true) => Some("The unmodified-input branch omits opening brace from its quote predicate."),
        (true,false) => Some("The unmodified-input branch omits non-breaking space from its quote predicate."),
        _ => None,
    }
}
