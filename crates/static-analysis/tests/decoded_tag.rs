use static_analysis::analyze_source;

const METHODS: &str = r#"
impl<'a, Registry: TryFrom<u64>> Frame<'a, Registry> {
    pub fn parse_octets(raw: &'a [u8]) -> Result<Self, Error> {
        let (tag, rest) = decoder::u64(&raw).map_err(|_| Error::Bad)?;
        let (size, body) = decoder::u64(&rest).map_err(|_| Error::Bad)?;
        if body.len() as u64 != size { return Err(Error::Bad); }
        Ok(Self { payload: raw, marker: PhantomData })
    }
    pub fn kind(&self) -> Registry {
        let (id, rest) = decoder::u64(&self.payload).expect("checked");
        Registry::try_from(id).unwrap_or_else(|_| panic!("unexpected identifier"))
    }
}
"#;

fn findings(source: &str) -> usize {
    analyze_source("input.rs", source)
        .into_iter()
        .filter(|f| f.id == "HEL-RUST-007")
        .count()
}

#[test]
fn correlates_the_constructor_and_reader_without_project_identifiers() {
    assert_eq!(findings(METHODS), 1);
    assert_eq!(findings(&METHODS.replace("(tag, rest)", "(_, rest)")), 1);
    let checked = METHODS.replace(
        "let (size,",
        "Registry::try_from(tag).map_err(|_| Error::Bad)?; let (size,",
    );
    assert_eq!(findings(&checked), 0);
    assert_eq!(
        findings(&METHODS.replace("&self.payload", "&self.other")),
        0
    );
    assert_eq!(
        findings(&METHODS.replace("payload: raw", "payload: body")),
        0
    );
    assert_eq!(
        findings(&METHODS.replace(
            "Registry::try_from(id).unwrap_or_else(|_| panic!(\"unexpected identifier\"))",
            "Registry::try_from(id).unwrap_or_default()"
        )),
        0
    );
}
