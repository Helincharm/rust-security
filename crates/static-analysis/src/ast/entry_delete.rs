use super::peel;
use crate::Rule;
use proc_macro2::Span;
use syn::{Block, Expr, Ident, Pat, Signature, Stmt};

pub(super) const RULE: Rule<'static> = Rule {
    id: "HEL-RUST-010",
    cwe: Some("CWE-367"),
    severity: "medium",
    confidence: "medium",
    explanation: "Deletion code checks a directory entry's type before recursively opening the child's pathname. A concurrent directory change can invalidate that check.",
    remediation: "Anchor traversal and deletion to open directory handles. Open child directories relative to their parent with no-follow semantics and validate the opened handle.",
};

fn variable(expr: &Expr) -> Option<&Ident> {
    match peel(expr) {
        Expr::Path(p) => p.path.get_ident(),
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

fn result_value(expr: &Expr) -> &Expr {
    match peel(expr) {
        Expr::Try(t) => peel(&t.expr),
        e => e,
    }
}

fn method_receiver<'a>(expr: &'a Expr, method: &str) -> Option<&'a Expr> {
    match result_value(expr) {
        Expr::MethodCall(c) if c.method == method && c.args.is_empty() => Some(&c.receiver),
        _ => None,
    }
}

fn is_directory(expr: &Expr, entry: &Ident) -> bool {
    method_receiver(expr, "is_dir")
        .and_then(|ft| method_receiver(ft, "file_type"))
        .and_then(result_variable)
        == Some(entry)
}

fn result_variable(e: &Expr) -> Option<&Ident> {
    variable(result_value(e))
}

fn enumerates(expr: &Expr, root: &Ident) -> bool {
    let expr = method_receiver(expr, "par_bridge").unwrap_or(expr);
    match result_value(expr) {
        Expr::MethodCall(c) => {
            c.method == "read_dir" && c.args.is_empty() && variable(&c.receiver) == Some(root)
        }
        Expr::Call(c) => {
            matches!(peel(&c.func), Expr::Path(p)
            if p.path.segments.last().is_some_and(|s| s.ident=="read_dir"))
                && c.args.len() == 1
                && variable(&c.args[0]) == Some(root)
        }
        _ => false,
    }
}

// Restrict the deletion search to direct calls, their result adapters and
// ordinary conditional branches. Stop at bindings that might shadow the
// path. Ignore nested closures, locally declared functions and match arms.
fn deletes_child(expr: &Expr, child: &Ident) -> bool {
    match result_value(expr) {
        Expr::If(i) if !matches!(peel(&i.cond), Expr::Let(_) | Expr::Binary(_)) => {
            block_deletes(&i.then_branch, child)
                || i.else_branch
                    .as_ref()
                    .is_some_and(|(_, e)| deletes_child(e, child))
        }
        Expr::Block(b) => block_deletes(&b.block, child),
        Expr::MethodCall(c) if c.method == "map_err" => deletes_child(&c.receiver, child),
        Expr::Call(c) => {
            let Expr::Path(p) = peel(&c.func) else {
                return false;
            };
            let segments = &p.path.segments;
            segments.len() >= 2
                && segments[segments.len() - 2].ident == "fs"
                && segments
                    .last()
                    .is_some_and(|s| s.ident == "remove_dir" || s.ident == "remove_file")
                && c.args.len() == 1
                && variable(&c.args[0]) == Some(child)
        }
        _ => false,
    }
}

fn block_deletes(block: &Block, child: &Ident) -> bool {
    statements_delete(&block.stmts, child)
}

fn statements_delete(stmts: &[Stmt], child: &Ident) -> bool {
    stmts
        .iter()
        .take_while(|s| !matches!(s, Stmt::Local(_) | Stmt::Item(_)))
        .any(|s| matches!(s, Stmt::Expr(e, _) if deletes_child(e, child)))
}

fn recursive_span(body: &Block, function: &Ident, child: &Ident) -> Option<Span> {
    let [Stmt::Expr(e, _)] = body.stmts.as_slice() else {
        return None;
    };
    let Expr::Call(call) = result_value(e) else {
        return None;
    };
    let name = variable(&call.func)?;
    (name == function && call.args.len() == 1 && variable(&call.args[0]) == Some(child))
        .then(|| name.span())
}

fn entry_body(body: &Block, function: &Ident, raw_entry: &Ident) -> Option<Span> {
    let mut entry = raw_entry;
    let mut directory = None;
    let mut child = None;

    for (i, stmt) in body.stmts.iter().enumerate() {
        match stmt {
            Stmt::Local(local) => {
                let id = binding(&local.pat)?;
                let expr = &local.init.as_ref()?.expr;
                if child == Some(id)
                    || directory == Some(id)
                    || (id == entry && result_variable(expr) != Some(entry))
                {
                    return None;
                }
                if result_variable(expr) == Some(entry) {
                    entry = id;
                } else if is_directory(expr, entry) {
                    directory = Some(id);
                } else if method_receiver(expr, "path").and_then(result_variable) == Some(entry) {
                    child = Some(id);
                } else if method_receiver(expr, "metadata").and_then(result_variable) != Some(entry)
                {
                    return None;
                }
            }
            Stmt::Expr(Expr::If(branch), _) if branch.else_branch.is_none() => {
                let child = child?;
                if !(is_directory(&branch.cond, entry)
                    || directory.is_some_and(|id| variable(&branch.cond) == Some(id)))
                {
                    return None;
                }
                let span = recursive_span(&branch.then_branch, function, child)?;
                return statements_delete(&body.stmts[i + 1..], child).then_some(span);
            }
            _ => return None,
        }
    }
    None
}

pub(super) fn inspect(sig: &Signature, body: &Block) -> Option<Span> {
    let syn::FnArg::Typed(param) = sig.inputs.first()? else {
        return None;
    };
    let root = binding(&param.pat)?;
    let mut iterator = None;
    for stmt in &body.stmts {
        if let Stmt::Local(local) = stmt {
            iterator = local
                .init
                .as_ref()
                .filter(|i| enumerates(&i.expr, root))
                .and_then(|_| binding(&local.pat));
        } else if let Stmt::Expr(expr, _) = stmt {
            match result_value(expr) {
                Expr::ForLoop(f) if enumerates(&f.expr, root) => {
                    return entry_body(&f.body, &sig.ident, binding(&f.pat)?);
                }
                Expr::MethodCall(c)
                    if c.method == "try_for_each"
                        && c.args.len() == 1
                        && (enumerates(&c.receiver, root)
                            || iterator.is_some_and(|id| variable(&c.receiver) == Some(id))) =>
                {
                    let Expr::Closure(cb) = peel(&c.args[0]) else {
                        return None;
                    };
                    let Expr::Block(b) = peel(&cb.body) else {
                        return None;
                    };
                    return entry_body(&b.block, &sig.ident, binding(cb.inputs.first()?)?);
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check(body: &str) -> bool {
        let f: syn::ItemFn = syn::parse_str(&format!(
            "fn walk(root: &Path) {{ for ent in root.read_dir()? {{ let ent=ent?; let dir=ent.file_type()?.is_dir(); let name=ent.path(); {body} }} }}"
        )).unwrap();
        inspect(&f.sig, &f.block).is_some()
    }
    #[test]
    fn verifies_entry_origin_recursive_lookup_and_deletion() {
        assert!(check("if dir { walk(&name)?; } fs::remove_dir(&name)?;"));
        assert!(!check(
            "if dir { walk(&name)?; } { let name = another(); fs::remove_dir(&name)?; }"
        ));
        assert!(!check("if dir { walk(&other)?; } fs::remove_dir(&name)?;"));
        assert!(!check("if dir { walk(&name)?; } inspect(&name);"));
        assert!(!check(
            "if dir { let handle = open_relative(&ent)?; walk(&handle)?; } fs::remove_dir(&name)?;"
        ));
        assert!(!check("if other { walk(&name)?; } fs::remove_dir(&name)?;"));
    }
}
