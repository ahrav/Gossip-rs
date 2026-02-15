/// Returns a [`proptest::test_runner::Config`] tuned for the current environment.
///
/// Under Miri, disables file-based failure persistence (requires `getcwd`,
/// blocked by isolation) and reduces cases from 256 to 32.
#[allow(unused_mut)]
pub(crate) fn miri_proptest_config() -> proptest::test_runner::Config {
    let mut config = proptest::test_runner::Config::default();
    #[cfg(miri)]
    {
        config.failure_persistence = None;
        config.cases = 32;
    }
    config
}
