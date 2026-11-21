mod reset_budget;
mod entry_delete;
mod regex_budget;
mod decoded_tag;
mod windows_path;
mod scope;
mod shell_quote;

use self::scope::{Scopes, Value};
use crate::{Finding, Report, Rule, MAX_INPUT_BYTES};
use proc_macro2::{TokenStream, TokenTree};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprIndex, ExprMacro, ExprMethodCall, Lit, Token};

const MAX_TOKENS: usize = 100_000;
const MAX_NESTING: usize = 48;
const MAX_EXPRESSION_TOKENS: usize = 384;

const SQL: Rule<'static> = Rule {
    id: "HEL-RUST-001",
    cwe: Some("CWE-89"),
    severity: "medium",
    confidence: "medium",
    explanation: "A formatted string with a nonliteral input reaches a recognized SQL API. Review whether the value can alter SQL syntax.",
    remediation: "Use a constant statement with bound parameters for values. Map permitted SQL identifiers to a fixed set.",
};

const COMMAND: Rule<'static> = Rule {
    id: "HEL-RUST-002",
    cwe: Some("CWE-78"),
    severity: "medium",
    confidence: "medium",
    explanation: "An environment-derived value selects the program passed to the standard command builder. Review which callers may control the value.",
    remediation: "Select the executable from trusted configuration or a fixed allowlist and pass each argument separately.",
};

const PATH: Rule<'static> = Rule {
    id: "HEL-RUST-003",
    cwe: Some("CWE-22"),
    severity: "medium",
    confidence: "medium",
    explanation: "A path joined with an environment-derived value reaches a standard filesystem read. Review the intended directory boundary.",
    remediation: "Restrict the input to permitted path components and enforce the directory boundary when opening the file.",
};

const INPUT: Rule<'static> = Rule {
    id: "HEL-RUST-004",
    cwe: Some("CWE-20"),
    severity: "low",
    confidence: "medium",
    explanation: "Code indexes bytes from an environment-derived string without a recognized bounds check. A short value can cause a panic.",
    remediation: "Use a checked lookup and return a validation error when the required byte is absent.",
};

pub fn analyze_source(relative_path: &str, source: &str) -> Vec<Finding> {
    let mut report = Report::new(relative_path, source, "static-ast", "static");
    if source.len() > MAX_INPUT_BYTES {
        report.coverage(
            "HEL-AST-LIMIT",
            "The file exceeds the static parser size limit.",
        );
        return report.finish();
    }

    // A separate stack gives both syn and the AST visitor room within the token bounds.
    let scanned = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn_scoped(scope, || scan(&mut report))
            .map(|worker| worker.join().is_ok())
            .unwrap_or(false)
    });
    if !scanned {
        report.coverage(
            "HEL-AST-UNAVAILABLE",
            "The static parser could not complete this file.",
        );
    }
    report.finish()
}

fn scan(report: &mut Report<'_>) {
    // Keep a byte offset for spans in the original source after removing a BOM or shebang.
    let source = report
        .source
        .strip_prefix('\u{feff}')
        .unwrap_or(report.source);
    let (prefix, source) = match source.strip_prefix("#!") {
        Some(rest) if !inner_attribute_follows(rest) => {
            let end = source.find('\n').unwrap_or(source.len());
            (report.source.len() - source.len() + end, &source[end..])
        }
        _ => (report.source.len() - source.len(), source),
    };
    let Ok(tokens) = source.parse::<TokenStream>() else {
        report.coverage("HEL-AST-PARSE", "The file could not be tokenized as Rust.");
        return;
    };
    let mut token_budget = MAX_TOKENS;
    if !bounded(tokens.clone(), 0, 0, &mut token_budget) {
        report.coverage(
            "HEL-AST-LIMIT",
            "The file exceeds the static parser token or nesting limit.",
        );
        return;
    }
    let Ok(file) = syn::parse2::<syn::File>(tokens) else {
        report.coverage("HEL-AST-PARSE", "The file could not be parsed as Rust.");
        return;
    };
    Scanner {
        report,
        prefix,
        visible_reset_senders: reset_budget::visible_senders(&file.items),
        scopes: Scopes::default(),
        bounds: Vec::new(),
    }
    .visit_file(&file);
}

fn inner_attribute_follows(mut rest: &str) -> bool {
    loop {
        rest = rest.trim_start_matches(|ch: char| {
            ch.is_whitespace() || matches!(ch, '\u{200e}' | '\u{200f}')
        });
        if rest.starts_with('[') {
            return true;
        }
        // Documentation comments are tokens. Skip only ordinary comments.
        if rest.starts_with("//")
            && !rest.starts_with("//!")
            && (!rest.starts_with("///") || rest.starts_with("////"))
        {
            let Some(end) = rest.find('\n') else {
                return false;
            };
            rest = &rest[end + 1..];
        } else if let Some(after_comment) = rest.strip_prefix("/**/") {
            rest = after_comment;
        } else if rest.starts_with("/*")
            && !rest.starts_with("/*!")
            && (!rest.starts_with("/**") || rest.starts_with("/***"))
        {
            let Some(end) = block_comment_end(rest) else {
                return false;
            };
            rest = &rest[end..];
        } else {
            return false;
        }
    }
}

fn block_comment_end(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 1;
    let mut i = 2;
    while i + 1 < bytes.len() {
        match &bytes[i..i + 2] {
            b"/*" => {
                depth += 1;
                i += 2;
            }
            b"*/" => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

fn bounded(tokens: TokenStream, depth: usize, parent_cost: usize, remaining: &mut usize) -> bool {
    if depth > MAX_NESTING {
        return false;
    }
    let mut run = 0;
    let mut angles = 0usize;
    let mut arrow_prefix = None;
    let mut attribute_prefix = 0;
    let mut tokens = tokens.into_iter().peekable();
    while let Some(token) = tokens.next() {
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        run += 1;
        if parent_cost + run > MAX_EXPRESSION_TOKENS {
            return false;
        }
        match &token {
            TokenTree::Group(group) => {
                if !bounded(group.stream(), depth + 1, parent_cost + run, remaining) {
                    return false;
                }
                // Rust tokenizes each documentation line as a separate literal-valued
                // attribute. These top-level siblings consume tokens but add no
                // expression recursion. Preserve any run preceding the attribute.
                if depth == 0 && attribute_prefix > 0 && literal_doc_attribute(group) {
                    run -= attribute_prefix + 1;
                }
                // Blocks can end items and statements or continue as part of an expression.
                if group.delimiter() == proc_macro2::Delimiter::Brace {
                    let ends_expression = match tokens.peek() {
                        Some(TokenTree::Ident(name)) => name != "else" && name != "as",
                        Some(TokenTree::Punct(punct)) => punct.as_char() == '#',
                        Some(_) => false,
                        None => true,
                    };
                    if ends_expression {
                        run = 0;
                    }
                }
            }
            TokenTree::Punct(punct) => match punct.as_char() {
                '<' => {
                    angles += 1;
                    if angles > MAX_NESTING {
                        return false;
                    }
                }
                // A match arm's fat arrow ends its pattern and any comparison guard.
                '>' if arrow_prefix == Some('=') => angles = 0,
                '>' if arrow_prefix.is_none() => angles = angles.saturating_sub(1),
                ';' => {
                    angles = 0;
                    run = 0;
                }
                ',' => run = 0,
                _ => {}
            },
            _ => {}
        }
        attribute_prefix = match &token {
            TokenTree::Punct(punct) if punct.as_char() == '#' => 1,
            TokenTree::Punct(punct) if punct.as_char() == '!' && attribute_prefix == 1 => 2,
            _ => 0,
        };
        arrow_prefix = match token {
            TokenTree::Punct(punct)
                if matches!(punct.as_char(), '-' | '=')
                    && punct.spacing() == proc_macro2::Spacing::Joint =>
            {
                Some(punct.as_char())
            }
            _ => None,
        };
    }
    true
}

fn literal_doc_attribute(group: &proc_macro2::Group) -> bool {
    if group.delimiter() != proc_macro2::Delimiter::Bracket {
        return false;
    }
    let mut parts = group.stream().into_iter();
    matches!(parts.next(), Some(TokenTree::Ident(name)) if name == "doc")
        && matches!(parts.next(), Some(TokenTree::Punct(punct)) if punct.as_char() == '=')
        && matches!(parts.next(), Some(TokenTree::Literal(_)))
        && parts.next().is_none()
}

struct Scanner<'a, 'source> {
    report: &'a mut Report<'source>,
    prefix: usize,
    visible_reset_senders: std::collections::HashSet<usize>,
    scopes: Scopes,
    bounds: Vec<(usize, usize)>,
}

impl Scanner<'_, '_> {
    fn report(&mut self, rule: Rule<'_>, span: proc_macro2::Span, evidence: &str) {
        let range = span.byte_range();
        let offsets = (self.prefix + range.start)..(self.prefix + range.end);
        self.report.push(rule, Some(offsets), evidence.into());
    }

    fn api(&self, expr: &Expr) -> Option<String> {
        let Expr::Path(path) = peel(expr) else {
            return None;
        };
        if path.qself.is_some()
            || path
                .path
                .get_ident()
                .is_some_and(|name| self.scopes.local(&name.to_string()).is_some())
        {
            return None;
        }
        self.scopes.api_path(&path.path)
    }

    fn value(&self, expr: &Expr) -> Option<Value> {
        match peel(expr) {
            Expr::Path(path) if path.qself.is_none() => self
                .scopes
                .local(&path.path.get_ident()?.to_string())
                .flatten(),
            Expr::Call(call) if call.args.len() == 1 => {
                let api = self.api(&call.func)?;
                (api == "std::env::var")
                    .then(|| Value::EnvironmentResult(call.span().byte_range().start))
            }
            Expr::Try(value) => self.environment_string(&value.expr),
            Expr::MethodCall(call) => match (call.method.to_string().as_str(), call.args.len()) {
                ("unwrap", 0) | ("expect", 1) => self.environment_string(&call.receiver),
                ("as_bytes", 0) => match self.value(&call.receiver)? {
                    Value::EnvironmentString(origin) => Some(Value::EnvironmentBytes(origin)),
                    _ => None,
                },
                ("join", 1)
                    if matches!(
                        call.args.first().and_then(|argument| self.value(argument)),
                        Some(Value::EnvironmentString(_))
                    ) =>
                {
                    Some(Value::JoinedPath)
                }
                _ => None,
            },
            Expr::Macro(value) if self.dynamic_format(value) => Some(Value::FormattedSql),
            _ => None,
        }
    }

    fn environment_string(&self, expr: &Expr) -> Option<Value> {
        match self.value(expr)? {
            Value::EnvironmentResult(origin) => Some(Value::EnvironmentString(origin)),
            _ => None,
        }
    }

    fn string_length_origin(&self, expr: &Expr) -> Option<usize> {
        match self.value(expr)? {
            Value::EnvironmentString(origin) | Value::EnvironmentBytes(origin) => Some(origin),
            _ => None,
        }
    }

    fn assume_guard(&mut self, expr: &Expr, truth: bool) {
        match peel(expr) {
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) => {
                self.assume_guard(&unary.expr, !truth);
            }
            Expr::Binary(binary) => {
                use syn::BinOp::*;
                match (&binary.op, truth) {
                    (And(_), true) | (Or(_), false) => {
                        self.assume_guard(&binary.left, truth);
                        self.assume_guard(&binary.right, truth);
                    }
                    (Ge(_), true) | (Lt(_), false) => {
                        self.assume_comparison(&binary.left, &binary.right, 0);
                    }
                    (Eq(_), true) => {
                        self.assume_comparison(&binary.left, &binary.right, 0);
                        self.assume_comparison(&binary.right, &binary.left, 0);
                    }
                    (Ne(_), true) | (Eq(_), false) => {
                        if integer(&binary.right) == Some(0) {
                            self.assume_comparison(&binary.left, &binary.right, 1);
                        }
                        if integer(&binary.left) == Some(0) {
                            self.assume_comparison(&binary.right, &binary.left, 1);
                        }
                    }
                    (Gt(_), true) | (Le(_), false) => {
                        self.assume_comparison(&binary.left, &binary.right, 1);
                    }
                    (Le(_), true) | (Gt(_), false) => {
                        self.assume_comparison(&binary.right, &binary.left, 0);
                    }
                    (Lt(_), true) | (Ge(_), false) => {
                        self.assume_comparison(&binary.right, &binary.left, 1);
                    }
                    _ => {}
                }
            }
            Expr::MethodCall(call)
                if !truth && call.method == "is_empty" && call.args.is_empty() =>
            {
                if let Some(origin) = self.string_length_origin(&call.receiver) {
                    self.bounds.push((origin, 1));
                }
            }
            _ => {}
        }
    }

    fn assume_comparison(&mut self, length: &Expr, minimum: &Expr, extra: usize) {
        if let Some(call) = method(length, "len").filter(|call| call.args.is_empty()) {
            if let (Some(origin), Some(minimum)) =
                (self.string_length_origin(&call.receiver), integer(minimum))
            {
                if let Some(bound) = minimum.checked_add(extra) {
                    self.bounds.push((origin, bound));
                }
            }
        }
    }

    fn visit_guarded_branch(
        &mut self,
        condition: &Expr,
        truth: bool,
        branch: impl FnOnce(&mut Self),
    ) {
        let previous = self.bounds.len();
        self.assume_guard(condition, truth);
        branch(self);
        self.bounds.truncate(previous);
    }

    fn visit_function(&mut self, signature: &syn::Signature, body: &syn::Block) {
        if let Some(span) = reset_budget::inspect(signature, body, &self.visible_reset_senders) {
            self.report(reset_budget::RULE, span, "The reset-class error forwards its reason and initiator to the reset sender, then returns success without a local budget check.");
        }
        if let Some(span) = entry_delete::inspect(signature, body) {
            self.report(entry_delete::RULE, span, "The directory check and child pathname come from the same enumerated entry. The guarded recursive call resolves that pathname again, and the traversal deletes entries by pathname.");
        }
        if let Some((span, evidence)) = windows_path::inspect(signature, body) {
            self.report(windows_path::RULE, span, evidence);
        }
        let bounds = std::mem::take(&mut self.bounds);
        self.scopes.push(std::iter::empty(), false);
        self.scopes.shadow_generics(&signature.generics);
        for input in &signature.inputs {
            if let syn::FnArg::Typed(input) = input {
                self.scopes.bind(&input.pat, None);
            }
        }
        self.visit_block(body);
        self.scopes.pop();
        self.bounds = bounds;
    }
}

impl<'ast> Visit<'ast> for Scanner<'_, '_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.scopes.push(file.items.iter(), false);
        visit::visit_file(self, file);
        self.scopes.pop();
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if let Some((_, items)) = &module.content {
            // Modules have their own imports. Textual macro_rules definitions can
            // still be in scope in an inline child module.
            self.scopes.enter_module(items.iter());
            for item in items {
                self.visit_item(item);
            }
            self.scopes.pop();
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let bounds = self.bounds.len();
        let items = block.stmts.iter().filter_map(|statement| match statement {
            syn::Stmt::Item(item) => Some(item),
            _ => None,
        });
        self.scopes.push(items, true);
        for statement in &block.stmts {
            self.visit_stmt(statement);
            if let syn::Stmt::Expr(Expr::If(value), _) = statement {
                if value.else_branch.is_none() && returns(&value.then_branch) {
                    self.assume_guard(&value.cond, false);
                }
            }
        }
        self.scopes.pop();
        self.bounds.truncate(bounds);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        let value = local.init.as_ref().and_then(|init| self.value(&init.expr));
        self.scopes.bind(&local.pat, value);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if item.mac.path.is_ident("macro_rules") {
            if let Some(name) = &item.ident {
                self.scopes.macro_definition(name.to_string());
            }
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.visit_function(&item.sig, &item.block);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.visit_function(&item.sig, &item.block);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        self.scopes.push(std::iter::empty(), false);
        self.scopes.shadow_generics(&item.generics);
        if let Some(span) = regex_budget::inspect(item) {
            self.report(regex_budget::RULE, span, "The empty-expression branch returns without updating the compilation budget checked by the same dispatcher.");
        }
        if let Some(span) = decoded_tag::inspect(item) {
            self.report(decoded_tag::RULE, span, "The constructor discards a decoded tag and retains the original bytes. A method of the same type assumes conversion of that tag succeeds.");
        }
        visit::visit_item_impl(self, item);
        self.scopes.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.scopes.push(std::iter::empty(), false);
        self.scopes.shadow_generics(&item.generics);
        visit::visit_item_trait(self, item);
        self.scopes.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if let Some(body) = &item.default {
            self.visit_function(&item.sig, body);
        }
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.scopes.push(std::iter::empty(), true);
        for input in &closure.inputs {
            self.scopes.bind(input, None);
        }
        self.visit_expr(&closure.body);
        self.scopes.pop();
    }

    fn visit_expr_if(&mut self, expr: &'ast syn::ExprIf) {
        if let Some(evidence) = shell_quote::omission(expr) {
            self.report(shell_quote::RULE, expr.cond.span(), evidence);
        }
        self.visit_condition_and_block(&expr.cond, &expr.then_branch);
        if let Some((_, otherwise)) = &expr.else_branch {
            self.visit_guarded_branch(&expr.cond, false, |scanner| scanner.visit_expr(otherwise));
        }
    }

    fn visit_expr_while(&mut self, expr: &'ast syn::ExprWhile) {
        self.visit_condition_and_block(&expr.cond, &expr.body);
    }

    fn visit_expr_for_loop(&mut self, expr: &'ast syn::ExprForLoop) {
        self.visit_expr(&expr.expr);
        self.scopes.push(std::iter::empty(), true);
        self.scopes.bind(&expr.pat, None);
        self.visit_block(&expr.body);
        self.scopes.pop();
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        self.scopes.push(std::iter::empty(), true);
        self.scopes.bind(&arm.pat, None);
        if let Some((_, guard)) = &arm.guard {
            self.visit_expr(guard);
            self.visit_guarded_branch(guard, true, |scanner| scanner.visit_expr(&arm.body));
        } else {
            self.visit_expr(&arm.body);
        }
        self.scopes.pop();
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let (Some(path), Some(first)) = (self.api(&call.func), call.args.first()) {
            match (path.as_str(), self.value(first)) {
                (
                    "sqlx::query" | "sqlx::query_as" | "sqlx::query_scalar",
                    Some(Value::FormattedSql),
                ) => {
                    self.report(
                        SQL,
                        call.span(),
                        "SQL API receives a formatted statement with a nonliteral value",
                    );
                }
                ("std::process::Command::new", Some(Value::EnvironmentString(_))) => {
                    self.report(
                        COMMAND,
                        call.span(),
                        "std::process::Command::new receives an environment-derived program",
                    );
                }
                (
                    "std::fs::read" | "std::fs::read_to_string" | "std::fs::File::open",
                    Some(Value::JoinedPath),
                ) => {
                    self.report(
                        PATH,
                        call.span(),
                        "Filesystem read receives a path joined with an environment value",
                    );
                }
                _ => {}
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_index(&mut self, index: &'ast ExprIndex) {
        if let (Some(position), Some(Value::EnvironmentBytes(origin))) =
            (integer(&index.index), self.value(&index.expr))
        {
            if !self
                .bounds
                .iter()
                .rev()
                .any(|&(guarded, minimum)| origin == guarded && minimum > position)
            {
                self.report(
                    INPUT,
                    index.span(),
                    "Direct byte indexing on an environment-derived string without a recognized length guard",
                );
            }
        }
        visit::visit_expr_index(self, index);
    }
}

impl Scanner<'_, '_> {
    fn visit_condition_and_block(&mut self, condition: &Expr, block: &syn::Block) {
        let previous = self.bounds.len();
        self.scopes.push(std::iter::empty(), true);
        self.visit_true_condition(condition);
        self.visit_block(block);
        self.scopes.pop();
        self.bounds.truncate(previous);
    }

    fn visit_true_condition(&mut self, condition: &Expr) {
        match peel(condition) {
            Expr::Let(value) => {
                self.visit_expr(&value.expr);
                self.scopes.bind(&value.pat, None);
            }
            Expr::Binary(binary) if matches!(binary.op, syn::BinOp::And(_)) => {
                self.visit_true_condition(&binary.left);
                self.visit_true_condition(&binary.right);
            }
            other => {
                self.visit_expr(other);
                self.assume_guard(other, true);
            }
        }
    }

    fn dynamic_format(&self, expr: &ExprMacro) -> bool {
        if !matches!(
            self.scopes.macro_path(&expr.mac.path).as_deref(),
            Some("format" | "std::format" | "alloc::format")
        ) {
            return false;
        }
        let Ok(args) =
            Punctuated::<Expr, Token![,]>::parse_terminated.parse2(expr.mac.tokens.clone())
        else {
            return false;
        };
        let Some(Expr::Lit(pattern)) = args.first().map(peel) else {
            return false;
        };
        let Lit::Str(pattern) = &pattern.lit else {
            return false;
        };
        if !format_placeholder(&pattern.value()) {
            return false;
        }
        // Implicit format captures have no argument nodes.
        args.len() == 1
            || args.iter().skip(1).any(|arg| {
                let value = match peel(arg) {
                    Expr::Assign(named) => &*named.right,
                    other => other,
                };
                !matches!(peel(value), Expr::Lit(_))
            })
    }
}

fn peel(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Paren(value) => &value.expr,
            Expr::Group(value) => &value.expr,
            Expr::Reference(value) if value.mutability.is_none() => &value.expr,
            _ => return expr,
        };
    }
}

fn integer(expr: &Expr) -> Option<usize> {
    let Expr::Lit(value) = peel(expr) else {
        return None;
    };
    let Lit::Int(value) = &value.lit else {
        return None;
    };
    value.base10_parse().ok()
}

fn returns(block: &syn::Block) -> bool {
    matches!(
        block.stmts.last(),
        Some(syn::Stmt::Expr(expr, _)) if matches!(peel(expr), Expr::Return(_))
    )
}

fn method<'a>(expr: &'a Expr, name: &str) -> Option<&'a ExprMethodCall> {
    match peel(expr) {
        Expr::MethodCall(call) if call.method == name => Some(call),
        _ => None,
    }
}

fn format_placeholder(pattern: &str) -> bool {
    let mut bytes = pattern.bytes().peekable();
    while let Some(value) = bytes.next() {
        if value == b'{' {
            if bytes.peek() != Some(&b'{') {
                return true;
            }
            bytes.next();
        }
    }
    false
}
