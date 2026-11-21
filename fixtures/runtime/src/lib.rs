#[test]
fn fixture_arithmetic() {
    assert_eq!(u8::checked_add(17, 25), Some(42));
    assert_eq!(u8::checked_add(u8::MAX, 1), None);
}
