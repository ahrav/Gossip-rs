use std::env;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig};

const ETCD_IMAGE: &str = "quay.io/coreos/etcd:v3.5.15";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const STARTUP_POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComposeCli {
    DockerPlugin,
    DockerCompose,
}

pub struct DockerComposeEtcd {
    compose_cli: ComposeCli,
    workdir: PathBuf,
    compose_file: PathBuf,
    project_name: String,
    endpoint: String,
}

impl DockerComposeEtcd {
    pub fn new() -> Self {
        let compose_cli = detect_compose_cli();
        let host_port = reserve_free_port();
        let project_name = unique_name("gossip-etcd");
        let workdir = unique_temp_dir(&project_name);
        let compose_file = workdir.join("compose.yml");
        write_compose_file(&compose_file, host_port);

        let suite = Self {
            compose_cli,
            workdir,
            compose_file,
            project_name,
            endpoint: format!("http://127.0.0.1:{host_port}"),
        };

        suite.compose(&["up", "-d"]);
        suite.wait_until_ready();
        suite
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn backend(&self, namespace_suffix: &str) -> EtcdCoordinator {
        let namespace = format!(
            "/gossip/test/{}/{}",
            sanitize_segment(namespace_suffix),
            unique_name("ns")
        );
        let config = EtcdCoordinatorConfig::new([self.endpoint().to_owned()], namespace, 60, 8, 8)
            .expect("test etcd config must be valid");
        EtcdCoordinator::connect(config).expect("test etcd backend must connect")
    }

    fn wait_until_ready(&self) {
        let start = std::time::Instant::now();
        while start.elapsed() < STARTUP_TIMEOUT {
            let config = EtcdCoordinatorConfig::new(
                [self.endpoint.clone()],
                format!("/gossip/health/{}", unique_name("probe")),
                60,
                8,
                8,
            )
            .expect("health config must be valid");
            if EtcdCoordinator::connect(config).is_ok() {
                return;
            }
            sleep(STARTUP_POLL);
        }

        let logs = self.compose_capture(&["logs", "--no-color"]);
        panic!(
            "timed out waiting for etcd at {}\nstdout:\n{}\nstderr:\n{}",
            self.endpoint,
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr),
        );
    }

    fn compose(&self, args: &[&str]) {
        let output = self.compose_capture(args);
        if output.status.success() {
            return;
        }
        panic!(
            "docker compose {:?} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn compose_capture(&self, args: &[&str]) -> Output {
        let mut cmd = match self.compose_cli {
            ComposeCli::DockerPlugin => {
                let mut cmd = Command::new("docker");
                cmd.arg("compose");
                cmd
            }
            ComposeCli::DockerCompose => Command::new("docker-compose"),
        };
        cmd.arg("-p")
            .arg(&self.project_name)
            .arg("-f")
            .arg(&self.compose_file)
            .args(args)
            .current_dir(&self.workdir);
        cmd.output()
            .unwrap_or_else(|err| panic!("failed to execute docker compose {:?}: {err}", args))
    }
}

impl Drop for DockerComposeEtcd {
    fn drop(&mut self) {
        let _ = self.compose_capture(&["down", "-v", "--remove-orphans"]);
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

fn detect_compose_cli() -> ComposeCli {
    let plugin_ok = Command::new("docker")
        .arg("compose")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if plugin_ok {
        return ComposeCli::DockerPlugin;
    }

    let standalone_ok = Command::new("docker-compose")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if standalone_ok {
        return ComposeCli::DockerCompose;
    }

    panic!(
        "B5 etcd integration tests require either `docker compose` or `docker-compose` in PATH"
    );
}

fn reserve_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral localhost port");
    let port = listener
        .local_addr()
        .expect("ephemeral listener local_addr")
        .port();
    drop(listener);
    port
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let dir = env::temp_dir().join(unique_name(prefix));
    fs::create_dir_all(&dir).expect("create temporary compose directory");
    dir
}

fn unique_name(prefix: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    format!("{prefix}-{}-{now}", std::process::id())
}

fn sanitize_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        out.push_str("default");
    }
    out
}

fn write_compose_file(path: &Path, host_port: u16) {
    let yaml = format!(
        "services:\n  etcd:\n    image: {image}\n    command:\n      - /usr/local/bin/etcd\n      - --name=etcd0\n      - --listen-client-urls=http://0.0.0.0:2379\n      - --advertise-client-urls=http://127.0.0.1:2379\n      - --listen-peer-urls=http://0.0.0.0:2380\n      - --initial-advertise-peer-urls=http://127.0.0.1:2380\n      - --initial-cluster=etcd0=http://127.0.0.1:2380\n      - --initial-cluster-state=new\n      - --initial-cluster-token=gossip-etcd-tests\n    ports:\n      - \"{host_port}:2379\"\n",
        image = ETCD_IMAGE,
        host_port = host_port,
    );
    fs::write(path, yaml).expect("write docker compose file");
}
