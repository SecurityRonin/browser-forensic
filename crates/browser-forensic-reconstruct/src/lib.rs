#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Viewable page reconstruction from browser cache.
//!
//! Builds, on top of [`browser_forensic_cache`], a URL-keyed index of cached
//! resources and reconstructs *viewable* artifacts from it:
//!
//! * a **self-contained single-file HTML** page (sub-resources inlined as
//!   `data:` URIs, missing ones shown as visible placeholders);
//! * a **WARC** file of the cached resources (replayable in pywb /
//!   replayweb.page);
//! * a **cached-image gallery**.
//!
//! ## Honesty is the whole point
//!
//! A cache reconstruction shows **cached representations consistent with
//! access** — what the cache stored, not a rendering of the page as displayed.
//! Every artifact carries a prominent, machine-readable and human-visible provenance
//! manifest ([`manifest::Manifest`]) stating the limit and enumerating which
//! sub-resources were **found in cache** and which were **referenced but
//! missing** — gaps are shown, never hidden or fabricated. This is a
//! *consistent-with* artifact: JS-generated, lazy-loaded, and auth-gated
//! content is not reconstructable, and component resources may carry different
//! cache timestamps.
//!
//! Untrusted-input posture: `#![forbid(unsafe_code)]` (workspace), no
//! `unwrap`/`expect` in production code, sub-resource count and total output
//! size bounded, never panics on malformed markup.

pub mod collect;
pub mod gallery;
pub mod index;
pub mod manifest;
pub mod output;
pub mod singlefile;
pub mod util;
pub mod warc;

pub use collect::{indexed_from_cached, indexed_from_cachestorage};
pub use gallery::{build_gallery, gallery_index_html, Gallery, GalleryImage};
pub use index::{normalize_url, resolve_ref, CacheSource, IndexedResource, ResourceIndex};
pub use manifest::{FoundResource, Manifest, MissingResource, PROVENANCE_BANNER};
pub use output::{reconstruct_to_dir, OutputFormat, ReconstructReport};
pub use singlefile::{reconstruct_singlefile, ReconstructedPage};
pub use warc::{write_warc, WarcStats};
