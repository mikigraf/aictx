use std::{env, ffi::OsString, path::Path};

use crate::{
    Error, Result,
    model::{Config, MutableState, Name, Profile, ProfileId, Provider},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionSource {
    ExplicitProfile,
    ExplicitContext,
    DirectoryBinding,
    ActiveContext,
    DefaultContext,
}

impl ResolutionSource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExplicitProfile => "explicit profile",
            Self::ExplicitContext => "explicit context",
            Self::DirectoryBinding => "directory binding",
            Self::ActiveContext => "active context",
            Self::DefaultContext => "default context",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedContext {
    pub name: Name,
    pub source: ResolutionSource,
}

#[derive(Clone, Debug)]
pub struct ResolvedProfile {
    pub id: ProfileId,
    pub profile: Profile,
    pub context: Option<Name>,
    pub source: ResolutionSource,
}

pub fn resolve_profile(
    config: &Config,
    state: &MutableState,
    cwd: &Path,
    provider: Provider,
    explicit_context: Option<&Name>,
    explicit_profile: Option<&ProfileId>,
) -> Result<ResolvedProfile> {
    if let Some(profile_id) = explicit_profile {
        if profile_id.provider() != provider {
            return Err(Error::InvalidInput(format!(
                "profile `{profile_id}` cannot be used for provider `{provider}`"
            )));
        }
        let profile = config
            .profiles
            .get(profile_id)
            .ok_or_else(|| profile_not_found(config, profile_id))?;
        return Ok(ResolvedProfile {
            id: profile_id.clone(),
            profile: profile.clone(),
            context: None,
            source: ResolutionSource::ExplicitProfile,
        });
    }

    let resolved_context = resolve_context(config, state, cwd, explicit_context)?;
    let context = config
        .contexts
        .get(&resolved_context.name)
        .ok_or_else(|| Error::ContextNotFound(resolved_context.name.to_string()))?;
    let profile_id = context.profile(provider).ok_or_else(|| {
        Error::ProfileNotFound(format!(
            "context `{}` has no {provider} profile",
            resolved_context.name
        ))
    })?;
    let profile = config
        .profiles
        .get(profile_id)
        .ok_or_else(|| profile_not_found(config, profile_id))?;

    Ok(ResolvedProfile {
        id: profile_id.clone(),
        profile: profile.clone(),
        context: Some(resolved_context.name),
        source: resolved_context.source,
    })
}

pub fn resolve_context(
    config: &Config,
    state: &MutableState,
    cwd: &Path,
    explicit: Option<&Name>,
) -> Result<ResolvedContext> {
    if let Some(name) = explicit {
        ensure_context_exists(config, name)?;
        return Ok(ResolvedContext {
            name: name.clone(),
            source: ResolutionSource::ExplicitContext,
        });
    }

    let canonical_cwd = cwd.canonicalize().map_err(|source| Error::ReadFile {
        path: cwd.to_path_buf(),
        source,
    })?;
    resolve_context_at_canonical_directory(config, state, &canonical_cwd)
}

/// Resolve an implicit context for a directory path that the caller already canonicalized.
///
/// Keeping filesystem work outside metadata write locks lets activation create a receipt
/// from one consistent metadata snapshot without holding a lock across I/O.
pub(crate) fn resolve_context_at_canonical_directory(
    config: &Config,
    state: &MutableState,
    canonical_cwd: &Path,
) -> Result<ResolvedContext> {
    if let Some(binding) = config
        .bindings
        .iter()
        .filter(|binding| canonical_cwd.starts_with(&binding.path))
        .max_by_key(|binding| binding.path.components().count())
    {
        return Ok(ResolvedContext {
            name: binding.context.clone(),
            source: ResolutionSource::DirectoryBinding,
        });
    }

    if let Some(name) = &state.current_context {
        ensure_context_exists(config, name)?;
        return Ok(ResolvedContext {
            name: name.clone(),
            source: ResolutionSource::ActiveContext,
        });
    }

    if let Some(name) = &config.default_context {
        ensure_context_exists(config, name)?;
        return Ok(ResolvedContext {
            name: name.clone(),
            source: ResolutionSource::DefaultContext,
        });
    }

    Err(Error::ContextNotFound(
        "no explicit, bound, active, or default context is configured".to_owned(),
    ))
}

pub fn current_directory() -> Result<std::path::PathBuf> {
    env::current_dir().map_err(|source| Error::ReadFile {
        path: std::path::PathBuf::from("."),
        source,
    })
}

pub fn canonical_directory(path: &Path) -> Result<std::path::PathBuf> {
    let path = path.canonicalize().map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            Error::InvalidInput(format!(
                "binding target {} does not exist; create it first",
                path.display()
            ))
        } else {
            Error::ReadFile {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    let metadata = path.metadata().map_err(|source| Error::ReadFile {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(Error::InvalidInput(format!(
            "binding target {} is not a directory",
            path.display()
        )));
    }
    Ok(path)
}

/// Resolve a binding path for removal, including when its final components no longer exist.
pub fn binding_lookup_path(path: &Path) -> Result<std::path::PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            canonicalize_with_missing(path)
        }
        Err(source) => Err(Error::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn canonicalize_with_missing(path: &Path) -> Result<std::path::PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_directory()?.join(path)
    };
    if absolute
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(Error::InvalidInput(format!(
            "cannot resolve missing binding path {} while it contains `..`; use the absolute path shown by `ctxlane bindings`",
            path.display()
        )));
    }

    let mut cursor = absolute.as_path();
    let mut missing = Vec::<OsString>::new();
    loop {
        match cursor.canonicalize() {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or_else(|| Error::ReadFile {
                    path: absolute.clone(),
                    source,
                })?;
                missing.push(name.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "could not resolve binding path {}",
                        path.display()
                    ))
                })?;
            }
            Err(source) => {
                return Err(Error::ReadFile {
                    path: cursor.to_path_buf(),
                    source,
                });
            }
        }
    }
}

fn ensure_context_exists(config: &Config, name: &Name) -> Result<()> {
    if config.contexts.contains_key(name) {
        Ok(())
    } else {
        Err(context_not_found(config, name))
    }
}

#[must_use]
pub fn context_not_found(config: &Config, requested: &Name) -> Error {
    let candidates = config.contexts.keys().map(ToString::to_string);
    Error::ContextNotFound(with_suggestion(requested.as_str(), candidates))
}

#[must_use]
pub fn profile_not_found(config: &Config, requested: &ProfileId) -> Error {
    let candidates = config
        .profiles
        .keys()
        .filter(|candidate| candidate.provider() == requested.provider())
        .map(ToString::to_string);
    Error::ProfileNotFound(with_suggestion(&requested.to_string(), candidates))
}

fn with_suggestion(requested: &str, candidates: impl Iterator<Item = String>) -> String {
    let requested_folded = requested.to_ascii_lowercase();
    let maximum_distance = if requested.chars().count() <= 4 { 1 } else { 2 };
    let suggestion = candidates
        .map(|candidate| {
            let distance = levenshtein(&requested_folded, &candidate.to_ascii_lowercase());
            (distance, candidate)
        })
        .filter(|(distance, _)| *distance <= maximum_distance)
        .min_by(Ord::cmp);
    suggestion.map_or_else(
        || requested.to_owned(),
        |(_, candidate)| format!("{requested}; did you mean `{candidate}`?"),
    )
}

fn levenshtein(left: &str, right: &str) -> usize {
    let right = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];
    for (left_index, left_character) in left.chars().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_character) in right.iter().enumerate() {
            let substitution =
                previous[right_index] + usize::from(left_character != *right_character);
            current[right_index + 1] = (current[right_index] + 1)
                .min(previous[right_index + 1] + 1)
                .min(substitution);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::TempDir;

    use crate::model::{Binding, Context};

    use super::*;

    fn config_with_contexts() -> Config {
        let mut config = Config::new().unwrap_or_else(|error| panic!("config: {error}"));
        let personal = Name::parse("personal")
            .unwrap_or_else(|error| panic!("valid name should parse: {error}"));
        let work =
            Name::parse("work").unwrap_or_else(|error| panic!("valid name should parse: {error}"));
        config.contexts = BTreeMap::from([
            (
                personal,
                Context {
                    claude: Some(
                        "claude:personal"
                            .parse()
                            .unwrap_or_else(|error| panic!("valid profile: {error}")),
                    ),
                    codex: None,
                },
            ),
            (
                work,
                Context {
                    claude: Some(
                        "claude:work"
                            .parse()
                            .unwrap_or_else(|error| panic!("valid profile: {error}")),
                    ),
                    codex: None,
                },
            ),
        ]);
        config
    }

    #[test]
    fn closest_binding_wins_over_active_context() {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let parent = temporary.path().join("company");
        let child = parent.join("special");
        std::fs::create_dir_all(&child)
            .unwrap_or_else(|error| panic!("create test directories: {error}"));
        let mut config = config_with_contexts();
        config.bindings = vec![
            Binding {
                path: parent
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("canonical parent: {error}")),
                context: Name::parse("personal")
                    .unwrap_or_else(|error| panic!("valid name: {error}")),
            },
            Binding {
                path: child
                    .canonicalize()
                    .unwrap_or_else(|error| panic!("canonical child: {error}")),
                context: Name::parse("work").unwrap_or_else(|error| panic!("valid name: {error}")),
            },
        ];
        let state = MutableState {
            version: crate::model::SCHEMA_VERSION,
            current_context: Some(
                Name::parse("personal").unwrap_or_else(|error| panic!("valid name: {error}")),
            ),
        };

        let resolved = resolve_context(&config, &state, &child, None)
            .unwrap_or_else(|error| panic!("context should resolve: {error}"));
        assert_eq!(resolved.name.as_str(), "work");
        assert_eq!(resolved.source, ResolutionSource::DirectoryBinding);
    }

    #[test]
    fn missing_names_suggest_only_close_candidates() {
        let config = config_with_contexts();
        assert_eq!(
            context_not_found(
                &config,
                &Name::parse("persnal")
                    .unwrap_or_else(|error| panic!("valid misspelling: {error}")),
            )
            .to_string(),
            "context not found: persnal; did you mean `personal`?"
        );
        assert_eq!(
            context_not_found(
                &config,
                &Name::parse("unknown")
                    .unwrap_or_else(|error| panic!("valid missing name: {error}")),
            )
            .to_string(),
            "context not found: unknown"
        );
    }
}
