use super::peel;
use crate::Rule;
use proc_macro2::Span;
use std::collections::{BTreeMap, BTreeSet};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Block, Expr, ExprMethodCall, ImplItem, ImplItemFn, ItemImpl, Pat, Stmt};

pub(super) const RULE: Rule<'static> = Rule {
    id: "HEL-RUST-008",
    cwe: Some("CWE-400"),
    severity: "medium",
    confidence: "medium",
    explanation: "A compiler dispatches repeated expressions through an output-size check. The empty-expression branch succeeds without updating the budget, so repeated compilation work can continue without making progress toward the limit.",
    remediation: "Charge the compilation budget for every expression processed, including empty expressions, or enforce a separate limit on compiler work.",
};

pub(super) fn inspect(item: &ItemImpl) -> Option<Span> {
    let methods: BTreeMap<_, _> = item
        .items
        .iter()
        .filter_map(|item| match item {
            ImplItem::Fn(method) => Some((method.sig.ident.to_string(), method)),
            _ => None,
        })
        .collect();
    methods.values().find_map(|dispatcher| {
        let (guard, empty, repeat) = dispatch(dispatcher)?;
        if !methods
            .get(&guard.method.to_string())
            .is_some_and(|guard| output_limit(guard))
        {
            return None;
        }
        let repeat = methods.get(&repeat.method.to_string())?;
        let mut inspected_consumers = BTreeSet::new();
        let mut repeats_dispatch = |method: &&ImplItemFn| {
            calls_in(&method.block).into_iter().any(|call| {
                call.args.len() == 1
                    && call.args.first().is_some_and(repeated_iterator)
                    && inspected_consumers.insert(call.method.to_string())
                    && methods
                        .get(&call.method.to_string())
                        .is_some_and(|consumer| loops_over_input(consumer, dispatcher))
            })
        };
        // A repetition can expand directly or dispatch again by repetition kind.
        let mut inspected_delegates = BTreeSet::new();
        (repeats_dispatch(repeat)
            || calls_in(&repeat.block).into_iter().any(|call| {
                let name = call.method.to_string();
                inspected_delegates.insert(name.clone())
                    && methods.get(&name).is_some_and(&mut repeats_dispatch)
            }))
        .then(|| empty.span())
    })
}

fn dispatch(method: &ImplItemFn) -> Option<(&ExprMethodCall, &Pat, &ExprMethodCall)> {
    let receiver = method.sig.receiver()?;
    receiver.reference.as_ref()?;
    receiver.mutability.as_ref()?;
    let input = single_input(method)?;
    let [imports @ .., Stmt::Expr(Expr::Try(check), _), Stmt::Expr(Expr::Match(branch), None)] =
        method.block.stmts.as_slice()
    else {
        return None;
    };
    if !imports_only(imports) {
        return None;
    }
    let guard = self_call(&check.expr)?;
    if !guard.args.is_empty() {
        return None;
    }
    let Expr::Unary(scrutinee) = peel(&branch.expr) else {
        return None;
    };
    let Expr::MethodCall(kind) = peel(&scrutinee.expr) else {
        return None;
    };
    if !matches!(scrutinee.op, syn::UnOp::Deref(_))
        || kind.method != "kind"
        || !kind.args.is_empty()
        || ident(&kind.receiver) != Some(input)
    {
        return None;
    }
    let empty = branch.arms.iter().find(|arm| {
        arm.guard.is_none()
            && variant(&arm.pat, "Empty")
            && wrapped_argument(&arm.body, "Ok").is_some_and(|expr| path_ends(expr, "None"))
    })?;
    let repeat = branch.arms.iter().find_map(|arm| {
        let Pat::TupleStruct(pattern) = &arm.pat else {
            return None;
        };
        if arm.guard.is_some()
            || !path_has_suffix(&pattern.path, "Repetition")
            || pattern.elems.len() != 1
        {
            return None;
        }
        let Pat::Ident(binding) = pattern.elems.first()? else {
            return None;
        };
        let call = self_call(&arm.body)?;
        (call.args.len() == 1 && ident(call.args.first()?) == Some(&binding.ident)).then_some(call)
    })?;
    Some((guard, &empty.pat, repeat))
}

fn output_limit(method: &ImplItemFn) -> bool {
    let Some(receiver) = method.sig.receiver() else {
        return false;
    };
    if receiver.reference.is_none() || receiver.mutability.is_some() {
        return false;
    }
    let [setup @ .., Stmt::Expr(Expr::If(branch), None)] = method.block.stmts.as_slice() else {
        return false;
    };
    let Expr::Binary(compare) = peel(&branch.cond) else {
        return false;
    };
    let (size, limit) = match compare.op {
        BinOp::Gt(_) | BinOp::Ge(_) => (&*compare.left, &*compare.right),
        BinOp::Lt(_) | BinOp::Le(_) => (&*compare.right, &*compare.left),
        _ => return false,
    };
    if !self_field(limit) {
        return false;
    }
    let [Stmt::Expr(error, _)] = branch.then_branch.stmts.as_slice() else {
        return false;
    };
    let Some((_, otherwise)) = &branch.else_branch else {
        return false;
    };
    let Expr::Block(success) = peel(otherwise) else {
        return false;
    };
    let [Stmt::Expr(success, None)] = success.block.stmts.as_slice() else {
        return false;
    };
    wrapped_argument(error, "Err").is_some()
        && matches!(wrapped_argument(success, "Ok").map(peel), Some(Expr::Tuple(tuple)) if tuple.elems.is_empty())
        && match setup.split_last() {
            Some((Stmt::Local(local), imports)) => {
                imports_only(imports)
                    && matches!(&local.pat, Pat::Ident(binding) if ident(size) == Some(&binding.ident))
                    && local
                        .init
                        .as_ref()
                        .is_some_and(|init| counts_output(&init.expr))
            }
            _ => imports_only(setup) && counts_output(size),
        }
}

fn imports_only(stmts: &[Stmt]) -> bool {
    stmts
        .iter()
        .all(|stmt| matches!(stmt, Stmt::Item(syn::Item::Use(_))))
}

fn counts_output(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Binary(binary) if matches!(binary.op, BinOp::Add(_) | BinOp::Mul(_)) => {
            counts_output(&binary.left) || counts_output(&binary.right)
        }
        Expr::MethodCall(call) => {
            call.method == "len" && call.args.is_empty() && self_field(&call.receiver)
        }
        _ => false,
    }
}

fn single_input(method: &ImplItemFn) -> Option<&syn::Ident> {
    if method.sig.inputs.len() != 2 {
        return None;
    }
    let syn::FnArg::Typed(input) = method.sig.inputs.last()? else {
        return None;
    };
    let Pat::Ident(binding) = &*input.pat else {
        return None;
    };
    Some(&binding.ident)
}

fn repeated_iterator(expr: &Expr) -> bool {
    let Expr::MethodCall(take) = peel(expr) else {
        return false;
    };
    let Expr::Call(repeat) = peel(&take.receiver) else {
        return false;
    };
    let Expr::Path(function) = peel(&repeat.func) else {
        return false;
    };
    let mut path = function.path.segments.iter().rev();
    take.method == "take"
        && take.args.len() == 1
        && take.args.first().and_then(ident).is_some()
        && function.qself.is_none()
        && path.next().is_some_and(|part| part.ident == "repeat")
        && path.next().is_some_and(|part| part.ident == "iter")
        && path
            .next()
            .is_none_or(|part| part.ident == "std" || part.ident == "core")
        && path.next().is_none()
        && repeat.args.len() == 1
}

fn loops_over_input(method: &ImplItemFn, dispatch: &ImplItemFn) -> bool {
    let Some(input) = single_input(method) else {
        return false;
    };
    method.block.stmts.iter().any(|stmt| {
        let Stmt::Expr(Expr::ForLoop(iteration), _) = stmt else {
            return false;
        };
        let Pat::Ident(element) = &*iteration.pat else {
            return false;
        };
        let Some(Stmt::Expr(first, _)) = iteration.body.stmts.first() else {
            return false;
        };
        let first = match peel(first) {
            Expr::If(branch) => match peel(&branch.cond) {
                Expr::Let(condition) => &*condition.expr,
                _ => return false,
            },
            expr => expr,
        };
        let Expr::Try(first) = peel(first) else {
            return false;
        };
        ident(&iteration.expr) == Some(input)
            && self_call(&first.expr).is_some_and(|call| {
                call.method == dispatch.sig.ident
                    && call.args.len() == 1
                    && call.args.first().and_then(ident) == Some(&element.ident)
            })
    })
}

fn calls_in(block: &Block) -> Vec<&ExprMethodCall> {
    #[derive(Default)]
    struct Calls<'ast>(Vec<&'ast ExprMethodCall>);
    impl<'ast> Visit<'ast> for Calls<'ast> {
        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if ident(&call.receiver).is_some_and(|name| name == "self") {
                self.0.push(call);
            }
            visit::visit_expr_method_call(self, call);
        }

        fn visit_item(&mut self, _: &'ast syn::Item) {}

        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    }
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls.0
}

fn self_call(expr: &Expr) -> Option<&ExprMethodCall> {
    let Expr::MethodCall(call) = peel(expr) else {
        return None;
    };
    ident(&call.receiver)
        .is_some_and(|name| name == "self")
        .then_some(call)
}

fn self_field(expr: &Expr) -> bool {
    matches!(peel(expr), Expr::Field(field) if ident(&field.base).is_some_and(|name| name == "self"))
}

fn ident(expr: &Expr) -> Option<&syn::Ident> {
    match peel(expr) {
        Expr::Path(path) if path.qself.is_none() => path.path.get_ident(),
        _ => None,
    }
}

fn path_ends(expr: &Expr, name: &str) -> bool {
    matches!(peel(expr), Expr::Path(path) if path.qself.is_none() && path_has_suffix(&path.path, name))
}

fn path_has_suffix(path: &syn::Path, name: &str) -> bool {
    path.segments.last().is_some_and(|part| part.ident == name)
}

fn variant(pattern: &Pat, name: &str) -> bool {
    match pattern {
        Pat::Ident(binding) => binding.ident == name,
        Pat::Path(path) => path.qself.is_none() && path_has_suffix(&path.path, name),
        _ => false,
    }
}

fn wrapped_argument<'a>(expr: &'a Expr, name: &str) -> Option<&'a Expr> {
    let Expr::Call(call) = peel(expr) else {
        return None;
    };
    if call.args.len() != 1 || !path_ends(&call.func, name) {
        return None;
    }
    call.args.first()
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPILER: &str = r#"
        impl Builder {
            fn emit(&mut self, node: &Node) -> Result<Option<Token>, Error> {
                self.within_budget()?;
                match *node.kind() {
                    NodeKind::Empty => Ok(None),
                    NodeKind::Repetition(ref parts) => self.expand(parts),
                    NodeKind::Leaf => self.emit_token(),
                }
            }

            fn within_budget(&self) -> Result<(), Error> {
                let bytes = self.extra + self.output.len() * size_of::<Token>();
                if bytes > self.limit { Err(Error::Budget) } else { Ok(()) }
            }

            fn expand(&mut self, parts: &Parts) -> Result<Option<Token>, Error> {
                self.combine(iter::repeat(&parts.child).take(parts_count))
            }

            fn combine(&mut self, nodes: Nodes) -> Result<Option<Token>, Error> {
                for node in nodes {
                    self.emit(node)?;
                }
                Ok(None)
            }
        }
    "#;

    fn finding(source: &str) -> Option<Span> {
        inspect(&syn::parse_str(source).expect("valid Rust syntax"))
    }

    #[test]
    fn detects_unaccounted_empty_branch_in_repetition() {
        assert!(finding(COMPILER).is_some());
    }

    #[test]
    fn skips_accounted_or_unconnected_repetition() {
        for (original, replacement) in [
            (
                "NodeKind::Empty => Ok(None)",
                "NodeKind::Empty => self.charge_empty()",
            ),
            (
                "self.within_budget()?;",
                "self.charge_work()?; self.within_budget()?;",
            ),
            ("self.emit(node)?;", "self.emit_token()?;"),
            (
                "self.emit(node)?;",
                "self.charge_work()?; self.emit(node)?;",
            ),
            ("let bytes =", "self.charge_work(); let bytes ="),
            (".take(parts_count)", ".take(2)"),
            ("iter::repeat", "local::repeat"),
            ("self.output.len() * size_of::<Token>()", "self.processed"),
        ] {
            assert!(
                finding(&COMPILER.replace(original, replacement)).is_none(),
                "{replacement}"
            );
        }
    }
}
