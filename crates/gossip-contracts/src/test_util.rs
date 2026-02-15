/// Returns a [`proptest::test_runner::Config`] tuned for the current environment.
///
/// Under Miri, disables file-based failure persistence (requires `getcwd`,
/// blocked by isolation) and reduces cases from 256 to 32.
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
