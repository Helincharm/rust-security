use super::peel;
use crate::Rule;
use proc_macro2::Span;
use std::collections::HashSet;
use syn::{Block, Expr, Ident, Pat, Signature, Stmt};

pub(super) const RULE: Rule<'static> = Rule {
    id: "HEL-RUST-009",
    cwe: Some("CWE-770"),
    severity: "medium",
    confidence: "medium",
    explanation: "A stream-error handler sends a reset for each reset-class error and returns success. Check whether the connection limits the cumulative number of locally generated resets.",
    remediation: "Charge locally generated error resets to a connection-wide budget and terminate the connection when the budget is exhausted.",
};

fn name(expr: &Expr) -> Option<&Ident> {
    match peel(expr) {
        Expr::Path(p) => p.path.get_ident(),
        _ => None,
    }
}

fn binding(pat: &Pat) -> Option<&Ident> {
    match pat {
        Pat::Ident(p) if p.subpat.is_none() => Some(&p.ident),
        _ => None,
    }
}

fn tuple_variant<'a>(pat: &'a Pat, variant: &str) -> Option<&'a syn::PatTupleStruct> {
    let Pat::TupleStruct(p) = pat else {
        return None;
    };
    p.path
        .segments
        .last()
        .is_some_and(|s| s.ident == variant)
        .then_some(p)
}

fn self_sender(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Field(f) => self_sender(&f.base),
        e => name(e).is_some_and(|n| n == "self"),
    }
}

fn ok_unit(expr: &Expr) -> bool {
    let Expr::Call(c) = peel(expr) else {
        return false;
    };
    matches!(peel(&c.func), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident=="Ok"))
        && matches!(c.args.first().map(peel), Some(Expr::Tuple(t)) if t.elems.is_empty())
        && c.args.len() == 1
}

// A same-file implementation with a compatible arity may enforce admission
// inside the sender. Without type resolution or a call graph, abstain for
// that arity even when another implementation is the actual target.
pub(super) fn visible_senders(items: &[syn::Item]) -> HashSet<usize> {
    fn collect(items: &[syn::Item], out: &mut HashSet<usize>) {
        for item in items {
            match item {
                syn::Item::Impl(i) => {
                    for entry in &i.items {
                        if let syn::ImplItem::Fn(f) = entry {
                            if f.sig.ident == "send_reset" && f.sig.receiver().is_some() {
                                out.insert(f.sig.inputs.len() - 1);
                            }
                        }
                    }
                }
                syn::Item::Mod(m) => {
                    if let Some((_, nested)) = &m.content {
                        collect(nested, out);
                    }
                }
                _ => {}
            }
        }
    }
    let mut arities = HashSet::new();
    collect(items, &mut arities);
    arities
}

pub(super) fn inspect(sig: &Signature, body: &Block, visible: &HashSet<usize>) -> Option<Span> {
    let [Stmt::Expr(Expr::If(branch), None)] = body.stmts.as_slice() else {
        return None;
    };
    let Expr::Let(test) = peel(&branch.cond) else {
        return None;
    };
    let result = name(&test.expr)?;
    if !sig
        .inputs
        .iter()
        .any(|a| matches!(a, syn::FnArg::Typed(p) if binding(&p.pat)==Some(result)))
    {
        return None;
    }
    let err = tuple_variant(&test.pat, "Err")?;
    let reset = tuple_variant(err.elems.first()?, "Reset")?;
    if err.elems.len() != 1 || reset.elems.len() != 3 {
        return None;
    }
    let reason = binding(&reset.elems[1])?;
    let initiator = binding(&reset.elems[2])?;
    let Expr::Block(other) = peel(&branch.else_branch.as_ref()?.1) else {
        return None;
    };
    if !matches!(other.block.stmts.as_slice(), [Stmt::Expr(e, None)] if name(e)==Some(result)) {
        return None;
    }

    // Only accept an unconditional reset followed by success. Any additional
    // executable statement might perform admission control or return an error.
    let (last, prefix) = branch.then_branch.stmts.split_last()?;
    if !matches!(last, Stmt::Expr(e, None) if ok_unit(e)) {
        return None;
    }
    let (send, before) = prefix.split_last()?;
    if !before
        .iter()
        .all(|s| matches!(s, Stmt::Macro(m) if m.mac.path.is_ident("debug_assert_eq")))
    {
        return None;
    }
    let Stmt::Expr(Expr::MethodCall(call), Some(_)) = send else {
        return None;
    };
    (call.method == "send_reset"
        && !visible.contains(&call.args.len())
        && self_sender(&call.receiver)
        && call.args.iter().any(|e| name(e) == Some(reason))
        && call.args.iter().any(|e| name(e) == Some(initiator)))
    .then(|| call.method.span())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn detected(branch: &str) -> bool {
        let item: syn::ImplItemFn = syn::parse_str(&format!(
            "fn handle(&mut self, event: Result<(), Fault>) -> Result<(), Fault> {{ if let Err(Fault::Reset(id, why, who)) = event {{ {branch} }} else {{event}} }}"
        )).unwrap();
        inspect(&item.sig, &item.block, &HashSet::new()).is_some()
    }
    #[test]
    fn compatible_visible_sender_can_enforce_its_own_budget() {
        let src = "struct Sender; impl Sender { fn send_reset(&mut self, reason: Why, initiator: Who) { if self.budget.try_reserve() { self.queue.push(reason, initiator); } } } impl Handler { fn receive(&mut self, event: Result<(), Fault>) -> Result<(), Fault> { if let Err(Fault::Reset(id, why, who)) = event { self.tx.send_reset(why, who); Ok(()) } else {event} } }";
        assert!(super::super::analyze_source("independent.rs", src)
            .iter()
            .all(|f| f.id != RULE.id));
    }
    #[test]
    fn matches_only_direct_error_to_reset_flow() {
        assert!(detected("self.tx.send_reset(why, who); Ok(())"));
        assert!(!detected(
            "self.check_budget()?; self.tx.send_reset(why, who); Ok(())"
        ));
        assert!(!detected(
            "if self.reserve() { self.tx.send_reset(why, who); } Ok(())"
        ));
        assert!(!detected("self.tx.send_reset(other, who); Ok(())"));
        assert!(!detected(
            "self.tx.send_reset(why, who); Err(Fault::Closed)"
        ));
    }
}
