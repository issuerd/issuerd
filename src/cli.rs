// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// Command-line interface definitions (daemon, provision, openapi, example commands).

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "issuerd")]
#[command(about = "Issuerd Identity and Access Management Server")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase verbosity (can be used multiple times)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Decrease verbosity (can be used multiple times)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub quiet: u8,
}

impl Cli {
    pub fn verbosity(&self) -> i32 {
        self.verbose as i32 - self.quiet as i32
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the Issuerd daemon
    Daemon {
        /// Path to configuration file
        #[arg(short, long, default_value = "issuerd.toml")]
        config: PathBuf,
    },
    /// Apply a provision config file exactly once
    Provision {
        /// Path to server configuration file (for storage connection)
        #[arg(short, long, default_value = "issuerd.toml")]
        config: PathBuf,
        /// Path to provision config file (YAML/TOML/JSON)
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Export the OpenAPI specification
    Openapi {
        /// Path to write the OpenAPI JSON file
        #[arg(short, long, default_value = "openapi.json")]
        output: PathBuf,
    },
    /// Generate example configuration files
    Example {
        /// Type of example to generate
        #[arg(value_enum)]
        kind: ExampleKind,
        /// Output file path
        #[arg(short, long, default_value = "examples/issuerd.example.toml")]
        output: PathBuf,
    },
    /// Probe a health endpoint, exiting non-zero unless it answers 2xx/3xx.
    /// Intended for container healthchecks so the runtime image needs no curl.
    Healthcheck {
        /// URL to probe
        #[arg(long, default_value = "http://localhost:8080/ready")]
        url: String,
        /// Skip TLS certificate verification (for self-signed dev/test certs)
        #[arg(long)]
        insecure: bool,
        /// Probe timeout in seconds
        #[arg(long, default_value = "5")]
        timeout_secs: u64,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ExampleKind {
    ServerConfig,
    ProvisionConfig,
}
