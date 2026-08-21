#![forbid(unsafe_code)]

use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use secrecy::ExposeSecret;

const RECORD_FILE: &str = "native-vendor-record.json";
const STATIC_SECRET_CANARY: &str = "ctxlane-native-fixture-static-secret-v1";
const SYNTHETIC_SETUP_TOKEN: &str =
    "opaque-fixture:Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~Ab9_-xY2~";

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("fake vendor failed: {error}");
            std::process::exit(2);
        }
    }
}

fn run() -> io::Result<i32> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [OsStr::new("prompt-setup-token")] {
        return Ok(prompt_setup_token());
    }
    if arguments.as_slice() == [OsStr::new("--version")] {
        return version();
    }
    if matches_arguments(&arguments, &["auth", "status", "--json"]) {
        return claude_auth_status();
    }
    if matches_arguments(&arguments, &["login", "status"]) {
        return Ok(i32::from(state_marker("login-unavailable").exists()));
    }
    if arguments.first().is_some_and(|value| value == "login")
        && arguments
            .get(1)
            .is_some_and(|value| value == "--with-api-key" || value == "--with-access-token")
    {
        let mut credential = String::new();
        io::stdin()
            .take(1024 * 1024 + 1)
            .read_to_string(&mut credential)?;
        if credential != format!("{STATIC_SECRET_CANARY}\n") {
            return Ok(2);
        }
        if state_marker("static-login-fail").exists() {
            return Ok(31);
        }
        fs::write(state_marker("static-login-present"), b"present")?;
        return Ok(0);
    }
    if arguments.as_slice() == [OsStr::new("logout")] {
        if state_marker("logout-fail").exists() {
            return Ok(37);
        }
        match fs::remove_file(state_marker("static-login-present")) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        return Ok(0);
    }

    write_record(&arguments)?;
    if arguments.as_slice() == [OsStr::new("setup-token")]
        && env::current_exe()?
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("setup-token-exit-23"))
    {
        return Ok(23);
    }
    Ok(
        if arguments
            .first()
            .is_some_and(|argument| argument == "exit-23")
        {
            23
        } else {
            0
        },
    )
}

fn prompt_setup_token() -> i32 {
    match ctxlane::secret::prompt_claude_setup_token("Synthetic Claude setup-token", false) {
        Ok(secret) if secret.expose_secret() == SYNTHETIC_SETUP_TOKEN => {
            println!("synthetic setup-token accepted");
            0
        }
        Ok(_) => {
            eprintln!("synthetic setup-token did not match");
            3
        }
        Err(error) => {
            eprintln!("{}", error.render_for_terminal());
            i32::from(error.exit_code())
        }
    }
}

fn version() -> io::Result<i32> {
    let executable = env::current_exe()?;
    let name = executable
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if name.contains("version-fail") {
        return Ok(9);
    }
    if name.contains("version-large") {
        io::stdout().write_all(&vec![b'x'; 64 * 1024 + 1])?;
        return Ok(0);
    }
    if name.contains("version-control") {
        println!("fake-vendor\u{1b}[31m");
        return Ok(0);
    }
    println!("ctxlane-test-vendor 1.0");
    Ok(0)
}

fn claude_auth_status() -> io::Result<i32> {
    if state_marker("auth-exit-fail").exists() {
        return Ok(9);
    }
    if state_marker("auth-oversized").exists() {
        io::stdout().write_all(&vec![b'x'; 64 * 1024 + 1])?;
        return Ok(0);
    }
    if state_marker("auth-invalid-json").exists() {
        println!("not-json");
        return Ok(0);
    }
    let selected_method = match (
        env::var("CLAUDE_CODE_OAUTH_TOKEN"),
        env::var("ANTHROPIC_API_KEY"),
    ) {
        (Ok(secret), Err(_)) if secret == STATIC_SECRET_CANARY => "oauth_token",
        (Err(_), Ok(secret)) if secret == STATIC_SECRET_CANARY => "api_key",
        (Err(_), Err(_)) => "none",
        _ => return Ok(8),
    };
    let method = if state_marker("auth-wrong-method").exists() {
        "wrong_method"
    } else {
        selected_method
    };
    let logged_in = selected_method != "none" && !state_marker("auth-logged-out").exists();
    let output = serde_json::json!({
        "loggedIn": logged_in,
        "authMethod": method,
        "apiProvider": "firstParty",
        "orgId": "organization-test"
    });
    println!("{output}");
    Ok(0)
}

fn write_record(arguments: &[OsString]) -> io::Result<()> {
    let provider = if env::var_os("CLAUDE_CONFIG_DIR").is_some() {
        "claude"
    } else if env::var_os("CODEX_HOME").is_some() {
        "codex"
    } else {
        "unknown"
    };
    for key in ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"] {
        if let Ok(secret) = env::var(key)
            && secret != STATIC_SECRET_CANARY
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{key} did not match the synthetic fixture canary"),
            ));
        }
    }
    let record = serde_json::json!({
        "provider": provider,
        "args": arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        "has_anthropic_api_key": env::var_os("ANTHROPIC_API_KEY").is_some(),
        "has_claude_oauth_token": env::var_os("CLAUDE_CODE_OAUTH_TOKEN").is_some(),
        "has_openai_api_key": env::var_os("OPENAI_API_KEY").is_some(),
        "anthropic_organization_id": env::var_os("ANTHROPIC_ORGANIZATION_ID")
            .map(|value| value.to_string_lossy().into_owned()),
        "anthropic_federation_rule_id": env::var_os("ANTHROPIC_FEDERATION_RULE_ID")
            .map(|value| value.to_string_lossy().into_owned()),
        "anthropic_identity_token_file": env::var_os("ANTHROPIC_IDENTITY_TOKEN_FILE")
            .map(|value| value.to_string_lossy().into_owned()),
        "ctxlane_profile": env::var_os("CTXLANE_PROFILE")
            .map(|value| value.to_string_lossy().into_owned()),
        "ctxlane_context": env::var_os("CTXLANE_CONTEXT")
            .map(|value| value.to_string_lossy().into_owned()),
    });
    fs::write(state_directory().join(RECORD_FILE), record.to_string())
}

fn state_directory() -> PathBuf {
    env::var_os("CLAUDE_CONFIG_DIR")
        .or_else(|| env::var_os("CODEX_HOME"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

fn state_marker(name: &str) -> PathBuf {
    state_directory().join(format!("native-vendor-{name}"))
}

fn matches_arguments(arguments: &[OsString], expected: &[&str]) -> bool {
    arguments.len() == expected.len()
        && arguments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == OsStr::new(expected))
}
