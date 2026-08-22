use super::*;

#[test]
fn every_rate_and_capacity_dimension_rejects_both_bounds() {
    let mut fixture = Fixture::new();
    let base = fixture.source.clone();
    for field in ["profile", "provider", "caller", "host"] {
        let line = base
            .lines()
            .find(|line| line.starts_with(&format!("{field} = ")))
            .unwrap_or_else(|| panic!("capacity marker"));
        fixture.assert_invalid(base.replacen(line, &format!("{field} = 0"), 1));
        fixture.assert_invalid(base.replacen(line, &format!("{field} = 1000001"), 1));
    }
    for section in [
        "[failed_authentication_rate]",
        "[controllers.rate_limits.acquire]",
        "[controllers.rate_limits.readiness]",
        "[controllers.rate_limits.principal_mismatch]",
    ] {
        let start = base.find(section).unwrap_or_else(|| panic!("rate marker"));
        let mut lines = base[start..].lines();
        let header = lines.next().unwrap_or_else(|| panic!("rate header"));
        let refill = lines.next().unwrap_or_else(|| panic!("refill"));
        let burst = lines.next().unwrap_or_else(|| panic!("burst"));
        let block = format!("{header}\n{refill}\n{burst}");
        for invalid in ["0", "100001"] {
            fixture.assert_invalid(base.replacen(
                &block,
                &format!("{header}\nrefill_per_minute = {invalid}\n{burst}"),
                1,
            ));
            fixture.assert_invalid(base.replacen(
                &block,
                &format!("{header}\n{refill}\nburst = {invalid}"),
                1,
            ));
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_development_requires_ack_and_local_scope() {
    let mut fixture = Fixture::new();
    let base = fixture.source.clone();
    for source in [
        base.replace("acknowledged = true", "acknowledged = false"),
        base.replace("acknowledged = true", ""),
        base.replace("local-development", "production"),
    ] {
        fixture.assert_invalid(source);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_executable_and_cgroup_policy_fail_closed() {
    let mut fixture = Fixture::new();
    let base = fixture.source.clone();
    let temporary = fixture
        .paths
        .config_dir
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap_or_else(|| panic!("fixture root"))
        .to_path_buf();
    let executable = temporary.join("trusted-controller");
    let path = executable.display().to_string();
    fixture.assert_invalid(base.replace(
        "cgroup_v2_path = \"/system.slice/controller.service\"",
        "cgroup_v2_path = \"/system.slice/../controller.service\"",
    ));
    fixture.assert_invalid(base.replace(
        "cgroup_v2_path = \"/system.slice/controller.service\"",
        "cgroup_v2_path = \"/system.slice/other.service\"",
    ));
    fixture.assert_invalid(base.replace(
        "executable_sha256 = \"sha256:",
        "executable_sha256 = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" # ",
    ));

    set_mode(&executable, 0o755);
    fixture.assert_invalid(base.clone());
    set_mode(&executable, 0o755);
    fs::write(&executable, b"#!/bin/sh\nexit 0\n")
        .unwrap_or_else(|error| panic!("script fixture: {error}"));
    set_mode(&executable, 0o555);
    fixture.assert_invalid(base.clone());

    let link = temporary.join("controller-link");
    symlink(&executable, &link).unwrap_or_else(|error| panic!("executable symlink: {error}"));
    fixture.assert_invalid(base.replace(&path, &link.display().to_string()));
    let repository_executable =
        std::env::current_exe().unwrap_or_else(|error| panic!("repository executable: {error}"));
    fixture.assert_invalid(base.replace(&path, &repository_executable.display().to_string()));
}
