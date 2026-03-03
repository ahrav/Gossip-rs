// Pre-existing doc link issues from scanner-rs port — suppress until
// a dedicated doc cleanup pass addresses them.
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::redundant_explicit_links)]

pub mod creddata;
pub mod finding_parser;
pub(crate) mod fs_walk;
pub mod leaky_repo;
pub mod line_index;
pub mod matching;
pub mod metrics;
pub mod pipeline;
pub mod provenance;
pub mod regression;
pub mod report;
pub mod synthetic;
pub mod types;
