use std::collections::{HashMap, HashSet};
use syn::visit::{self, Visit};
use syn::{GenericParam, Generics, Item, Pat, PatIdent, Path, UseTree};

#[derive(Clone, Copy)]
pub(super) enum Value {
    EnvironmentResult(usize),
    EnvironmentString(usize),
    EnvironmentBytes(usize),
    JoinedPath,
    FormattedSql,
}

#[derive(Default)]
struct Scope {
    names: HashMap<String, Option<String>>,
    imports: HashSet<String>,
    locals: HashMap<String, Option<Value>>,
    macros: HashSet<String>,
    captures: bool,
    module: bool,
}

#[derive(Default)]
pub(super) struct Scopes(Vec<Scope>);

impl Scopes {
    pub(super) fn push<'a>(&mut self, items: impl Iterator<Item = &'a Item>, captures: bool) {
        let mut scope = Scope {
            captures,
            ..Scope::default()
        };
        for item in items {
            match item {
                Item::Use(item) => {
                    scope.import(&mut Vec::new(), &item.tree, item.leading_colon.is_some())
                }
                Item::ExternCrate(item) => {
                    let source = item.ident.to_string();
                    let target = item.rename.as_ref().map_or(&item.ident, |(_, name)| name);
                    scope.names.insert(
                        target.to_string(),
                        canonical_root(&source).then(|| format!("::{source}")),
                    );
                }
                other => {
                    if let Some(name) = item_name(other) {
                        scope.names.insert(name.to_string(), None);
                    }
                }
            }
        }
        self.0.push(scope);
    }

    pub(super) fn pop(&mut self) {
        self.0.pop();
    }

    pub(super) fn shadow_generics(&mut self, generics: &Generics) {
        let scope = self.0.last_mut().expect("active scope");
        for param in &generics.params {
            match param {
                GenericParam::Type(param) => {
                    scope.names.insert(param.ident.to_string(), None);
                }
                GenericParam::Const(param) => {
                    scope.names.insert(param.ident.to_string(), None);
                }
                GenericParam::Lifetime(_) => {}
            }
        }
    }

    pub(super) fn enter_module<'a>(&mut self, items: impl Iterator<Item = &'a Item>) {
        self.push(items, false);
        self.0.last_mut().expect("active scope").module = true;
    }

    pub(super) fn bind(&mut self, pattern: &Pat, value: Option<Value>) {
        let locals = &mut self.0.last_mut().expect("active scope").locals;
        PatternNames(locals).visit_pat(pattern);
        let pattern = match pattern {
            Pat::Type(typed) => &*typed.pat,
            other => other,
        };
        if let Pat::Ident(binding) = pattern {
            if binding.mutability.is_none() && binding.by_ref.is_none() && binding.subpat.is_none()
            {
                locals.insert(binding.ident.to_string(), value);
            }
        }
    }

    pub(super) fn local(&self, name: &str) -> Option<Option<Value>> {
        for scope in self.0.iter().rev() {
            if let Some(value) = scope.locals.get(name) {
                return Some(*value);
            }
            if scope.names.contains_key(name) || !scope.captures {
                break;
            }
        }
        None
    }

    pub(super) fn macro_definition(&mut self, name: String) {
        self.0.last_mut().expect("active scope").macros.insert(name);
    }

    pub(super) fn macro_path(&self, path: &Path) -> Option<String> {
        if let Some(ident) = path.get_ident() {
            let name = ident.to_string();
            if self
                .0
                .iter()
                .rev()
                .any(|scope| scope.macros.contains(&name))
            {
                return None;
            }
            if name == "format"
                && !self
                    .items_in_scope()
                    .any(|scope| scope.imports.contains(&name))
            {
                return Some(name);
            }
        }
        self.api_path(path)
    }

    pub(super) fn api_path(&self, path: &Path) -> Option<String> {
        let mut segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string());
        let root = segments.next()?;
        let mut resolved = if path.leading_colon.is_some() {
            canonical_root(&root).then_some(root)?
        } else {
            let mut scopes = self.items_in_scope();
            match scopes.find_map(|scope| scope.names.get(&root).map(|alias| (scope, alias))) {
                Some((scope, alias)) => {
                    let alias = alias.as_ref()?;
                    if let Some(absolute) = alias.strip_prefix("::") {
                        absolute.to_owned()
                    } else {
                        let alias_root = alias.split("::").next()?;
                        let root_binding = scope
                            .names
                            .get(alias_root)
                            .or_else(|| scopes.find_map(|scope| scope.names.get(alias_root)));
                        if root_binding.is_some_and(|binding| {
                            binding.as_deref().map(|path| path.trim_start_matches("::"))
                                != Some(alias_root)
                        }) {
                            return None;
                        }
                        alias.clone()
                    }
                }
                None => canonical_root(&root).then_some(root)?,
            }
        };
        for part in segments {
            resolved.push_str("::");
            resolved.push_str(&part);
        }
        Some(resolved)
    }

    fn items_in_scope(&self) -> impl Iterator<Item = &Scope> {
        let module = self.0.iter().rposition(|scope| scope.module).unwrap_or(0);
        self.0[module..].iter().rev()
    }
}

impl Scope {
    fn import(&mut self, prefix: &mut Vec<String>, tree: &UseTree, absolute: bool) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.import(prefix, &path.tree, absolute);
                prefix.pop();
            }
            UseTree::Group(group) => {
                for tree in &group.items {
                    self.import(prefix, tree, absolute);
                }
            }
            UseTree::Name(name) => {
                let target = if name.ident == "self" {
                    let Some(last) = prefix.last() else { return };
                    last.clone()
                } else {
                    name.ident.to_string()
                };
                self.import_name(prefix, &name.ident.to_string(), target, absolute);
            }
            UseTree::Rename(rename) => {
                self.import_name(
                    prefix,
                    &rename.ident.to_string(),
                    rename.rename.to_string(),
                    absolute,
                );
            }
            UseTree::Glob(_) => {}
        }
    }

    fn import_name(&mut self, prefix: &[String], name: &str, target: String, absolute: bool) {
        let mut parts = prefix.to_vec();
        if name != "self" {
            parts.push(name.to_string());
        }
        // Retain relative roots so local declarations can shadow external crate names.
        let path = parts.first().filter(|root| canonical_root(root)).map(|_| {
            if absolute {
                format!("::{}", parts.join("::"))
            } else {
                parts.join("::")
            }
        });
        self.imports.insert(target.clone());
        self.names.insert(target, path);
    }
}

fn item_name(item: &Item) -> Option<&syn::Ident> {
    Some(match item {
        Item::Const(item) => &item.ident,
        Item::Enum(item) => &item.ident,
        Item::Fn(item) => &item.sig.ident,
        Item::Mod(item) => &item.ident,
        Item::Static(item) => &item.ident,
        Item::Struct(item) => &item.ident,
        Item::Trait(item) => &item.ident,
        Item::TraitAlias(item) => &item.ident,
        Item::Type(item) => &item.ident,
        Item::Union(item) => &item.ident,
        _ => return None,
    })
}

fn canonical_root(name: &str) -> bool {
    matches!(name, "std" | "sqlx" | "alloc")
}

struct PatternNames<'a>(&'a mut HashMap<String, Option<Value>>);

impl<'ast> Visit<'ast> for PatternNames<'_> {
    fn visit_pat_ident(&mut self, pattern: &'ast PatIdent) {
        self.0.insert(pattern.ident.to_string(), None);
        visit::visit_pat_ident(self, pattern);
    }
}
