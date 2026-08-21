#![forbid(unsafe_code)]

pub mod activation;
pub mod binary;
mod brand;
pub mod cli;
pub mod commands;
pub mod config;
pub mod doctor;
pub mod error;
pub mod identity;
pub mod model;
pub mod resolver;
pub mod runner;
pub mod secret;
pub mod shell;
pub mod tui;

pub use error::{Error, Result};
