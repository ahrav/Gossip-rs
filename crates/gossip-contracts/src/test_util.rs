/// Returns a [`proptest::test_runner::Config`] tuned for the current environment.
///
/// Under Miri, disables file-based failure persistence (filesystem I/O is
/// blocked by Miri's default isolation mode) and reduces cases from the
/// proptest default of 256 to 32, since Miri interpretation is far slower
/// than native execution.
pub(crate) fn miri_proptest_config() -> proptest::test_runner::Config {
    if cfg!(miri) {
        proptest::test_runner::Config {
            failure_persistence: None,
            cases: 32,
            ..Default::default()
        }
    } else {
        proptest::test_runner::Config::default()
    }
}
