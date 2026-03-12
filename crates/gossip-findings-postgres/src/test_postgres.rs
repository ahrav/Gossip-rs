//! Testcontainers-based PostgreSQL lifecycle management for findings
//! integration tests.
//!
//! Provides [`test_client`] and [`test_client_bare`] helpers backed by either:
//!
//! - an auto-provisioned Docker container, or
//! - an external PostgreSQL from `GOSSIP_POSTGRES_TEST_URL`.
//!
//! A single PostgreSQL instance is shared across the test binary, while each
//! test gets a freshly created database for isolation.

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

        PgEndpoint {
            url: format!("host={host} port={port} user=postgres password=postgres dbname=postgres"),
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

/// Replace or append the `dbname=` component in a libpq keyword-value string.
///
/// Uses quote-aware tokenization so that `dbname=` fragments embedded inside
/// single-quoted parameter values (e.g. `password='secret dbname=dummy'`) are
/// not falsely matched.
fn rewrite_keyword_connection_string(base_url: &str, db_name: &str) -> String {
    let tokens = keyword_value_tokens(base_url);
    if tokens.iter().any(|t| t.starts_with("dbname=")) {
        tokens
            .into_iter()
            .map(|t| {
                if t.starts_with("dbname=") {
                    format!("dbname={db_name}")
                } else {
                    t.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        format!("{base_url} dbname={db_name}")
    }
}

/// Split a libpq keyword-value connection string into tokens, respecting
/// single-quoted values that may contain whitespace.
///
/// libpq uses backslash escaping inside quoted values: `\'` is a literal
/// single-quote, `\\` is a literal backslash. The tokenizer consumes
/// characters inside a quoted section until an unescaped closing `'`.
fn keyword_value_tokens(input: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            if bytes[i] == b'\'' {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        // Backslash escape — skip the next character.
                        i += 2;
                    } else if bytes[i] == b'\'' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            } else {
                i += 1;
            }
        }
        tokens.push(&input[start..i]);
    }
    tokens
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

/// Create a fresh isolated database and return a connection string for it.
pub(crate) fn create_test_db() -> String {
    let endpoint = shared_endpoint();
    let db_name = unique_db_name();
    let mut admin = Client::connect(&endpoint.url, NoTls)
        .expect("failed to connect to postgres maintenance database");
    admin
        .batch_execute(&format!("CREATE DATABASE {db_name}"))
        .expect("failed to create fresh test database");
    connection_string_for_db(&endpoint.url, &db_name)
}

/// Create a fresh test database and apply the crate migrations.
pub(crate) fn test_client() -> Client {
    let url = create_test_db();
    let mut client = Client::connect(&url, NoTls).expect("failed to connect to test database");
    crate::apply_all_migrations(&mut client).expect("failed to apply findings migrations");
    client
}

/// Create a fresh test database without applying migrations.
pub(crate) fn test_client_bare() -> Client {
    let url = create_test_db();
    Client::connect(&url, NoTls).expect("failed to connect to bare test database")
}

#[cfg(test)]
mod tests {
    use super::{
        rewrite_keyword_connection_string, rewrite_uri_connection_string, rewrite_uri_path,
        rewrite_uri_query_dbname,
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
        // libpq keyword-value format supports single-quoted values. If a
        // quoted value contains "dbname=", split_whitespace breaks the token
        // boundary and the starts_with("dbname=") check falsely matches.
        let input = "host=127.0.0.1 password='secret dbname=dummy' dbname=postgres";
        let rewritten = rewrite_keyword_connection_string(input, "test_quoted");
        // Correct behavior: only the real dbname= key is replaced.
        assert_eq!(
            rewritten, "host=127.0.0.1 password='secret dbname=dummy' dbname=test_quoted",
            "quoted values containing dbname= must not be rewritten"
        );
    }

    #[test]
    fn keyword_connection_string_with_backslash_escaped_quote() {
        // libpq uses backslash escaping inside single-quoted values:
        // \' is an escaped quote, \\ is an escaped backslash.
        let input = r"host=127.0.0.1 password='it\'s complex dbname=dummy' dbname=postgres";
        let rewritten = rewrite_keyword_connection_string(input, "test_bs");
        assert_eq!(
            rewritten, r"host=127.0.0.1 password='it\'s complex dbname=dummy' dbname=test_bs",
            "backslash-escaped quotes inside values must not break tokenization"
        );
    }
}
