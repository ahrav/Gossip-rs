//! Shared PostgreSQL test-support helpers for persistence crates.
//!
//! The module provisions one maintenance endpoint per test binary, either from
//! `GOSSIP_POSTGRES_TEST_URL` or from a `postgres:16-alpine` testcontainer,
//! then creates a fresh database per test for isolation.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use postgres::{Client, NoTls};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, ContainerRequest, GenericImage, ImageExt};

/// Monotonic suffix for unique per-test database names.
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Nanosecond-resolution nonce seeded once at process start. Combined with
/// `DB_COUNTER` and PID, this prevents name collisions when an external
/// PostgreSQL instance retains databases across test runs.
static RUN_NONCE: OnceLock<u64> = OnceLock::new();

/// Base PostgreSQL endpoint used to provision fresh test databases.
struct PgEndpoint {
    /// Connection string pointing at the maintenance database.
    url: String,
    /// Held alive so the shared testcontainer is not reaped mid-test.
    _container: Option<Container<GenericImage>>,
}

static SHARED_PG: OnceLock<PgEndpoint> = OnceLock::new();

/// Build the shared PostgreSQL container image definition.
fn pg_image() -> ContainerRequest<GenericImage> {
    GenericImage::new("postgres", "16-alpine")
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "postgres")
}

/// Start or reuse the shared PostgreSQL endpoint.
///
/// Resolution order:
/// 1. `GOSSIP_POSTGRES_TEST_URL`, if present and non-empty.
/// 2. A `postgres:16-alpine` container managed by testcontainers.
fn shared_endpoint() -> &'static PgEndpoint {
    SHARED_PG.get_or_init(|| {
        if let Some(url) = external_url() {
            return PgEndpoint {
                url,
                _container: None,
            };
        }

        let container = pg_image()
            .start()
            .expect("failed to start postgres container; ensure Docker is available");

        let host = container
            .get_host()
            .expect("failed to resolve container host");
        let port = container
            .get_host_port_ipv4(5432)
            .expect("failed to resolve mapped postgres port");

        let url =
            format!("host={host} port={port} user=postgres password=postgres dbname=postgres");

        // PostgreSQL emits the ready log message twice during startup. Retry
        // the first connection so tests do not race the early message.
        let mut last_err = None;
        for attempt in 0..5 {
            match Client::connect(&url, NoTls) {
                Ok(client) => {
                    drop(client);
                    last_err = None;
                    break;
                }
                Err(error) => {
                    last_err = Some(error);
                    std::thread::sleep(std::time::Duration::from_millis(500 * (attempt + 1)));
                }
            }
        }
        if let Some(error) = last_err {
            panic!("postgres container not accepting connections after retries: {error}");
        }

        PgEndpoint {
            url,
            _container: Some(container),
        }
    })
}

/// Read `GOSSIP_POSTGRES_TEST_URL` when it is set to a non-empty value.
fn external_url() -> Option<String> {
    std::env::var("GOSSIP_POSTGRES_TEST_URL")
        .ok()
        .map(|raw| raw.trim().to_owned())
        .filter(|raw| !raw.is_empty())
}

/// Generate a unique test database name.
///
/// Includes a nanosecond-resolution nonce so that names remain unique across
/// test runs sharing a persistent external PostgreSQL instance.
fn unique_db_name() -> String {
    let pid = std::process::id();
    let nonce = *RUN_NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos() as u64
    });
    let seq = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("test_{pid}_{nonce:x}_{seq}")
}

/// Create a fresh isolated database and return a connection string for it.
pub fn create_test_db() -> String {
    let endpoint = shared_endpoint();
    let db_name = unique_db_name();
    let mut admin = Client::connect(&endpoint.url, NoTls)
        .expect("failed to connect to postgres maintenance database");
    admin
        .batch_execute(&format!("CREATE DATABASE \"{db_name}\""))
        .expect("failed to create fresh test database");
    connection_string_for_db(&endpoint.url, &db_name)
}

/// Create a fresh test database without applying migrations.
pub fn test_client_bare() -> Client {
    let url = create_test_db();
    Client::connect(&url, NoTls).expect("failed to connect to bare test database")
}

/// Create a fresh test database and run caller-provided migration logic.
pub fn test_client_with<F>(migrate: F) -> Client
where
    F: FnOnce(&mut Client),
{
    let mut client = test_client_bare();
    migrate(&mut client);
    client
}

/// Build a connection string for a freshly-created database.
///
/// Detects the format by checking for a `postgresql://` or `postgres://`
/// scheme prefix rather than scanning for `://` anywhere in the string,
/// which avoids misrouting keyword-value strings whose parameter values
/// happen to contain that substring.
fn connection_string_for_db(base_url: &str, db_name: &str) -> String {
    if base_url.starts_with("postgresql://") || base_url.starts_with("postgres://") {
        rewrite_uri_connection_string(base_url, db_name)
    } else {
        rewrite_keyword_connection_string(base_url, db_name)
    }
}

/// Replace or append the `dbname` setting in a libpq keyword-value string.
///
/// Handles both compact (`dbname=postgres`) and spaced (`dbname = postgres`)
/// forms. Uses quote-aware tokenization so that `dbname=` fragments embedded
/// inside single-quoted parameter values are not falsely matched.
fn rewrite_keyword_connection_string(base_url: &str, db_name: &str) -> String {
    let pairs = keyword_value_pairs(base_url);
    if pairs.iter().any(|(key, _)| *key == "dbname") {
        pairs
            .into_iter()
            .map(|(key, value)| {
                if key == "dbname" {
                    format!("dbname={db_name}")
                } else {
                    format!("{key}={value}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        format!("{base_url} dbname={db_name}")
    }
}

/// Parse a libpq keyword-value connection string into `(key, value)` pairs.
///
/// Supports optional whitespace around `=` (for example `dbname = postgres`)
/// and single-quoted values with libpq backslash escaping (`\'`, `\\`).
fn keyword_value_pairs(input: &str) -> Vec<(&str, &str)> {
    let mut pairs = Vec::new();
    let bytes = input.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }

        let key_start = index;
        while index < bytes.len() && bytes[index] != b'=' && !bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let key = &input[key_start..index];

        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        if index >= bytes.len() || bytes[index] != b'=' {
            pairs.push((key, ""));
            continue;
        }
        index += 1;

        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        let value_start = index;
        if index < bytes.len() && bytes[index] == b'\'' {
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == b'\'' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
        } else {
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
        }
        pairs.push((key, &input[value_start..index]));
    }

    pairs
}

/// Replace the database component in a libpq connection URI.
fn rewrite_uri_connection_string(base_url: &str, db_name: &str) -> String {
    let (without_query, query) = match base_url.split_once('?') {
        Some((head, tail)) => (head, Some(tail)),
        None => (base_url, None),
    };
    let rewritten_path = rewrite_uri_path(without_query, db_name);

    match query {
        Some(query) => format!(
            "{rewritten_path}?{}",
            rewrite_uri_query_dbname(query, db_name)
        ),
        None => rewritten_path,
    }
}

/// Replace the database path segment in a connection URI.
fn rewrite_uri_path(base_url: &str, db_name: &str) -> String {
    let scheme_sep = base_url
        .find("://")
        .expect("URI connection strings must include a scheme separator");
    let authority_start = scheme_sep + 3;

    match base_url[authority_start..].find('/') {
        Some(path_offset) => {
            let path_start = authority_start + path_offset;
            format!("{}/{db_name}", &base_url[..path_start])
        }
        None => format!("{base_url}/{db_name}"),
    }
}

/// Replace a `dbname=` query parameter when present, leaving other parameters
/// untouched.
fn rewrite_uri_query_dbname(query: &str, db_name: &str) -> String {
    query
        .split('&')
        .map(|part| {
            if part.starts_with("dbname=") {
                format!("dbname={db_name}")
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::{
        connection_string_for_db, rewrite_keyword_connection_string, rewrite_uri_connection_string,
        rewrite_uri_path, rewrite_uri_query_dbname,
    };

    #[test]
    fn keyword_connection_string_replaces_existing_dbname() {
        let input = "host=127.0.0.1 port=5432 user=postgres password=postgres dbname=postgres";
        let rewritten = rewrite_keyword_connection_string(input, "test_1");
        assert_eq!(
            rewritten,
            "host=127.0.0.1 port=5432 user=postgres password=postgres dbname=test_1"
        );
    }

    #[test]
    fn keyword_connection_string_appends_missing_dbname() {
        let input = "host=127.0.0.1 port=5432 user=postgres password=postgres";
        let rewritten = rewrite_keyword_connection_string(input, "test_2");
        assert_eq!(
            rewritten,
            "host=127.0.0.1 port=5432 user=postgres password=postgres dbname=test_2"
        );
    }

    #[test]
    fn uri_connection_string_rewrites_database_path() {
        let input = "postgresql://postgres:postgres@localhost:5432/postgres";
        let rewritten = rewrite_uri_connection_string(input, "test_3");
        assert_eq!(
            rewritten,
            "postgresql://postgres:postgres@localhost:5432/test_3"
        );
    }

    #[test]
    fn uri_connection_string_rewrites_dbname_query_parameter() {
        let input = "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable&dbname=postgres";
        let rewritten = rewrite_uri_connection_string(input, "test_4");
        assert_eq!(
            rewritten,
            "postgresql://postgres:postgres@localhost:5432/test_4?sslmode=disable&dbname=test_4"
        );
    }

    #[test]
    fn uri_path_rewrite_appends_database_when_path_is_missing() {
        let input = "postgresql://postgres:postgres@localhost:5432";
        let rewritten = rewrite_uri_path(input, "test_5");
        assert_eq!(
            rewritten,
            "postgresql://postgres:postgres@localhost:5432/test_5"
        );
    }

    #[test]
    fn uri_query_rewrite_leaves_non_dbname_parameters_untouched() {
        let input = "sslmode=disable&connect_timeout=5";
        let rewritten = rewrite_uri_query_dbname(input, "test_6");
        assert_eq!(rewritten, input);
    }

    #[test]
    fn keyword_connection_string_with_quoted_value_containing_dbname() {
        let input = "host=127.0.0.1 password='secret dbname=dummy' dbname=postgres";
        let rewritten = rewrite_keyword_connection_string(input, "test_quoted");
        assert_eq!(
            rewritten, "host=127.0.0.1 password='secret dbname=dummy' dbname=test_quoted",
            "quoted values containing dbname= must not be rewritten"
        );
    }

    #[test]
    fn keyword_connection_string_with_backslash_escaped_quote() {
        let input = r"host=127.0.0.1 password='it\'s complex dbname=dummy' dbname=postgres";
        let rewritten = rewrite_keyword_connection_string(input, "test_bs");
        assert_eq!(
            rewritten, r"host=127.0.0.1 password='it\'s complex dbname=dummy' dbname=test_bs",
            "backslash-escaped quotes inside values must not break tokenization"
        );
    }

    #[test]
    fn keyword_connection_string_with_spaces_around_equals() {
        let input = "host=127.0.0.1 dbname = postgres";
        let rewritten = rewrite_keyword_connection_string(input, "test_sp");
        assert!(
            !rewritten.contains("dbname = postgres"),
            "existing dbname must be replaced even when spaces surround '='"
        );
        assert!(
            rewritten.contains("dbname=test_sp"),
            "rewritten string must contain the new dbname"
        );
    }

    #[test]
    fn keyword_connection_string_dangling_backslash_does_not_panic() {
        let input = "host=127.0.0.1 password='trailing\\";
        let rewritten = rewrite_keyword_connection_string(input, "test_dbs");
        assert!(
            rewritten.contains("dbname=test_dbs"),
            "function must still append dbname even with malformed input"
        );
    }

    #[test]
    fn keyword_connection_strings_with_uri_like_values_stay_in_keyword_mode() {
        let input = "host=127.0.0.1 options='service://cache' dbname=postgres";
        let rewritten = connection_string_for_db(input, "test_conninfo");
        assert_eq!(
            rewritten,
            "host=127.0.0.1 options='service://cache' dbname=test_conninfo"
        );
    }
}
