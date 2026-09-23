// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Tracing/logging initialization for the Issuerd binary.

use issuerd_core::IssuerdError;
use std::io::IsTerminal;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

/// Console output format for the fmt layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable text (default).
    Pretty,
    /// One JSON object per event, for log shippers.
    Json,
}

/// Logging settings resolved from the CLI flags and the `[logging]` config section.
#[derive(Debug, Clone)]
pub struct LoggingSettings {
    pub level: Level,
    pub format: LogFormat,
    /// Unparsable `[logging].level` value, surfaced as a WARN once the
    /// subscriber is installed (fallback: INFO).
    pub invalid_level: Option<String>,
    /// Unparsable `[logging].format` value, likewise (fallback: pretty).
    pub invalid_format: Option<String>,
}

fn verbosity_to_level(verbosity: i32) -> Level {
    match verbosity {
        i32::MIN..=-2 => Level::ERROR,
        -1 => Level::WARN,
        0 => Level::INFO,
        1 => Level::DEBUG,
        2..=i32::MAX => Level::TRACE,
    }
}

fn parse_level(raw: &str) -> Option<Level> {
    match raw.to_ascii_lowercase().as_str() {
        "error" => Some(Level::ERROR),
        "warn" | "warning" => Some(Level::WARN),
        "info" => Some(Level::INFO),
        "debug" => Some(Level::DEBUG),
        "trace" => Some(Level::TRACE),
        _ => None,
    }
}

impl LoggingSettings {
    /// Resolve the effective logging settings.
    ///
    /// Level precedence: `RUST_LOG` (applied in `init_logging` via
    /// `EnvFilter::try_from_default_env`) > explicit `-v`/`-q` flags >
    /// `[logging].level`; INFO when nothing is set. `format` comes from
    /// `[logging].format` (`"json"` selects the JSON layer; `"pretty"` is the
    /// default) and applies to the console layer only — journald has its own
    /// structured format.
    pub fn resolve(verbosity: i32, config: Option<&issuerd_server::config::LoggingConfig>) -> Self {
        let mut invalid_level = None;
        let level = if verbosity != 0 {
            verbosity_to_level(verbosity)
        } else {
            match config.map(|c| c.level.as_str()) {
                Some(raw) => parse_level(raw).unwrap_or_else(|| {
                    invalid_level = Some(raw.to_string());
                    Level::INFO
                }),
                None => Level::INFO,
            }
        };

        let mut invalid_format = None;
        let format = match config.map(|c| c.format.as_str()) {
            Some(raw) if raw.eq_ignore_ascii_case("json") => LogFormat::Json,
            Some(raw) if raw.eq_ignore_ascii_case("pretty") => LogFormat::Pretty,
            Some(raw) => {
                invalid_format = Some(raw.to_string());
                LogFormat::Pretty
            }
            None => LogFormat::Pretty,
        };

        Self {
            level,
            format,
            invalid_level,
            invalid_format,
        }
    }
}

/// Install the assembled subscriber as the global default.
///
/// Deliberately uses `set_global_default` rather than `SubscriberInitExt::init`:
/// `init()` would install its own `tracing_log::LogTracer` (tracing-subscriber's
/// default `tracing-log` feature) and panic when the bridge is already active —
/// the bridge below is installed explicitly instead.
fn install_subscriber<S>(subscriber: S) -> Result<(), IssuerdError>
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    tracing::dispatcher::set_global_default(subscriber.into()).map_err(|e| {
        IssuerdError::ServerError(format!("failed to install tracing subscriber: {e}"))
    })
}

pub fn init_logging(settings: &LoggingSettings) -> Result<(), IssuerdError> {
    // Bridge the `log` facade into tracing — dependencies like ldap3, redis,
    // reqwest, rustls and sqlx-core emit through `log` and their records would
    // otherwise be silently dropped. Failure means a logger is already
    // installed; that must not abort startup.
    if let Err(e) = tracing_log::LogTracer::init() {
        eprintln!("Failed to bridge the `log` facade into tracing: {e}");
    }

    // RUST_LOG wins over the resolved flag/config level.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = settings.level;
        EnvFilter::new(format!(
            "issuerd={level},issuerd_server={level},issuerd_core={level},\
             issuerd_auth_flow={level},issuerd_protocol={level},issuerd_token={level},\
             issuerd_storage={level},issuerd_cluster={level},issuerd_admin_api={level},issuerd_federation={level}"
        ))
    });

    #[cfg(target_os = "linux")]
    if std::env::var_os("JOURNAL_STREAM").is_some() {
        match tracing_journald::layer() {
            Ok(layer) => {
                install_subscriber(tracing_subscriber::registry().with(env_filter).with(layer))?;
                return Ok(());
            }
            Err(e) => {
                eprintln!("Failed to initialize journald layer: {e}, falling back to fmt");
            }
        }
    }

    // ANSI escape codes only on a real terminal; piped/container logs stay clean.
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(true).with_line_number(true);

    match settings.format {
        LogFormat::Json => {
            // The JSON formatter panics when ANSI is enabled.
            let layer = fmt_layer.with_ansi(false).json();
            install_subscriber(tracing_subscriber::registry().with(env_filter).with(layer))?;
        }
        LogFormat::Pretty => {
            let layer = fmt_layer.with_ansi(std::io::stdout().is_terminal());
            install_subscriber(tracing_subscriber::registry().with(env_filter).with(layer))?;
        }
    }

    if let Some(raw) = &settings.invalid_level {
        tracing::warn!(value = %raw, "invalid [logging].level, falling back to \"info\"");
    }
    if let Some(raw) = &settings.invalid_format {
        tracing::warn!(value = %raw, "invalid [logging].format, falling back to \"pretty\"");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use issuerd_server::config::LoggingConfig;

    fn config(level: &str, format: &str) -> LoggingConfig {
        LoggingConfig {
            level: level.to_string(),
            format: format.to_string(),
        }
    }

    #[test]
    fn flags_beat_config_level() {
        let settings = LoggingSettings::resolve(1, Some(&config("warn", "pretty")));
        assert_eq!(settings.level, Level::DEBUG);
        assert_eq!(settings.invalid_level, None);
    }

    #[test]
    fn config_level_used_when_no_flags() {
        let settings = LoggingSettings::resolve(0, Some(&config("debug", "json")));
        assert_eq!(settings.level, Level::DEBUG);
        assert_eq!(settings.format, LogFormat::Json);
        assert_eq!(settings.invalid_level, None);
        assert_eq!(settings.invalid_format, None);
    }

    #[test]
    fn defaults_without_config() {
        let settings = LoggingSettings::resolve(0, None);
        assert_eq!(settings.level, Level::INFO);
        assert_eq!(settings.format, LogFormat::Pretty);
    }

    #[test]
    fn invalid_config_values_fall_back_with_warning() {
        let settings = LoggingSettings::resolve(0, Some(&config("loud", "xml")));
        assert_eq!(settings.level, Level::INFO);
        assert_eq!(settings.format, LogFormat::Pretty);
        assert_eq!(settings.invalid_level.as_deref(), Some("loud"));
        assert_eq!(settings.invalid_format.as_deref(), Some("xml"));
    }
}
