//! Structured, process-attributed browser-artifact carving from a memory image.
//!
//! This rides on the fleet [`memory-forensic`](https://github.com/SecurityRonin/memory-forensic)
//! (`memf`) framework instead of scanning a whole buffer blind:
//!
//! 1. [`memf_format::open_dump_with_raw_fallback`] opens the image (raw/LiME/AVML/crash-dump).
//! 2. Symbols are resolved from an ISF file or auto-profiled from the kernel PDB
//!    ([`memf_symbols::AutoProfile`]); [`memf_session::build_analysis_context`]
//!    recovers the OS, DTB/CR3, and `PsActiveProcessHead`.
//! 3. A [`VirtualAddressSpace`] + [`ObjectReader`] enumerate the `_EPROCESS`
//!    list (page-table-translated), and for each *browser* process the committed
//!    user pages are walked and scanned for URL / cookie artifacts.
//!
//! Every event is tagged with the **owning pid and process image name** —
//! Volatility-style attribution a whole-image byte scan cannot provide.
//!
//! # Why the `_EPROCESS` walk and page enumeration are reimplemented here
//!
//! memf's Windows walkers live in `memf-windows`, which hard-depends on
//! `yara-x` → `wasmtime` — a large JIT carrying many RUSTSEC advisories (and a
//! GPL-3.0-dual transitive crate) that browser-forensic never exercises. Rather
//! than drag that unreachable code (and its `cargo deny` exceptions) into a
//! forensic CLI, the two pieces we need are rebuilt on memf-core's *public*
//! [`ObjectReader`] (symbol-driven `_EPROCESS` field reads — no hardcoded
//! offsets) and a spec-defined x86-64 4-level page-table walk. Both are
//! validated against memf-core's own translation engine on constructed page
//! tables (see the module tests).
//!
//! # What is structurally recovered vs. best-effort
//!
//! - **Structurally recovered:** the process list (page-table-translated
//!   `_EPROCESS` walk) and per-process committed user pages. An extracted URL or
//!   cookie is attributed to a *named process at a known pid* — not merely
//!   "present somewhere in the image".
//! - **Best-effort within a process:** the artifacts themselves are still
//!   byte-scanned from heap pages (URL and `Cookie:` patterns, via the same
//!   [`crate::scan_bytes_for_urls`] / [`crate::scan_bytes_for_cookies`] used for
//!   raw buffers). Reconstructing complete history/cookie SQLite DBs from
//!   in-memory `_CACHE_` structures is out of scope.
//!
//! When the image has no resolvable process structure (a raw buffer, or a
//! non-Windows image), this fails with a [`MemoryCarveError::is_degradable`]
//! error so the caller can fall back to the raw byte scan. A genuine bootstrap
//! failure (unreadable image, or a Windows image with no usable profile) fails
//! loud rather than reporting a false empty.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use browser_forensic_core::{BrowserEvent, BrowserFamily};
use memf_core::object_reader::ObjectReader;
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_format::PhysicalMemoryProvider;
use memf_session::OsProfile;
use memf_symbols::SymbolResolver;
use serde_json::json;

use crate::{scan_bytes_for_cookies, scan_bytes_for_urls};

// x86-64 4-level paging constants (Intel SDM Vol 3A §4.5).
const PTE_PRESENT: u64 = 1 << 0;
const PTE_PAGE_SIZE: u64 = 1 << 7; // PS: a PDPTE/PDE that maps a large page, not a table
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000; // physical frame bits [12,51]
const PT_ENTRIES: u64 = 512;
const USER_PML4_ENTRIES: u64 = 256; // low-canonical (user) half: PML4 indices 0..256
const PAGE_4K: u64 = 0x1000;
const PAGE_2M: u64 = 0x0020_0000;

// Robustness caps against corrupt / adversarial page tables.
const MAX_LEAVES_PER_PROCESS: usize = 262_144; // ≤ ~1 GiB of 4 KiB pages enumerated
const MAX_REGION_BYTES: usize = 2 * 1024 * 1024; // never read more than one 2 MiB leaf at once

/// Failure modes of [`carve_memory_image`].
///
/// [`is_degradable`](MemoryCarveError::is_degradable) separates the two policy
/// classes: a **hard bootstrap failure** (fail loud, non-zero) from a case the
/// caller may **degrade** to a raw byte scan (loud warning, never silent empty).
#[derive(Debug, thiserror::Error)]
pub enum MemoryCarveError {
    /// The image file could not be opened (missing, unreadable, unrecognized).
    /// A hard bootstrap failure — never silently degraded.
    #[error("cannot open memory image {path}: {source}")]
    Open {
        /// The image path, verbatim.
        path: String,
        /// The underlying open error.
        source: anyhow::Error,
    },

    /// The image is a recognized Windows OS image but no usable profile could be
    /// established (no symbols, or the `_EPROCESS` walk failed). Fails loud so
    /// the analyst supplies `--symbols <ISF>` rather than seeing a false empty.
    #[error("Windows image but no usable profile: {0}")]
    NoProfile(String),

    /// The image has no recognizable OS/process structure (a raw buffer). The
    /// caller should degrade to a raw byte scan.
    #[error("no OS/process structure in image ({0}); raw byte-scan fallback applies")]
    NotAnOsImage(String),

    /// A recognized OS with no browser-process walker yet (Linux/macOS). The
    /// caller should degrade to a raw byte scan of the whole image.
    #[error(
        "process-attributed browser carve is Windows-only today; {os} image not yet supported"
    )]
    UnsupportedOs {
        /// The detected OS name.
        os: String,
    },
}

impl MemoryCarveError {
    /// Whether the caller may degrade to a raw byte scan (loud) instead of
    /// failing loud. `true` for "not an OS image" and "unsupported OS"; `false`
    /// for open failures and Windows-with-no-profile (both fail loud).
    #[must_use]
    pub fn is_degradable(&self) -> bool {
        matches!(self, Self::NotAnOsImage(_) | Self::UnsupportedOs { .. })
    }
}

/// Classify a process image name into a [`BrowserFamily`], or `None` for a
/// non-browser process. Case-insensitive. This is the single source of truth for
/// "is this process a browser worth carving".
#[must_use]
pub fn browser_family_for_process(image_name: &str) -> Option<BrowserFamily> {
    let name = image_name.to_ascii_lowercase();
    match name.as_str() {
        "chrome.exe" | "msedge.exe" | "brave.exe" | "opera.exe" | "vivaldi.exe"
        | "chromium.exe" => Some(BrowserFamily::Chromium),
        "firefox.exe" => Some(BrowserFamily::Firefox),
        _ => None,
    }
}

/// A browser process located in the `_EPROCESS` list.
#[derive(Debug, Clone)]
struct BrowserProc {
    pid: u64,
    image_name: String,
    /// Page-table root (DTB / CR3) for the process address space.
    cr3: u64,
}

/// Carve process-attributed browser artifacts from a memory image, auto-resolving
/// symbols from the kernel PDB where possible.
///
/// Equivalent to [`carve_memory_image_with_symbols`] with no ISF file.
///
/// # Errors
/// See [`MemoryCarveError`]. Bootstrap failures fail loud; a raw/unsupported
/// image returns a [`MemoryCarveError::is_degradable`] error.
pub fn carve_memory_image(path: &Path) -> Result<Vec<BrowserEvent>, MemoryCarveError> {
    carve_memory_image_with_symbols(path, None)
}

/// Carve process-attributed browser artifacts from a memory image.
///
/// `isf` is an optional Volatility-3 ISF symbol file. When `None`, symbols are
/// auto-profiled from the dump (kernel PDB; may need network + a symbol cache).
///
/// # Errors
/// See [`MemoryCarveError`].
pub fn carve_memory_image_with_symbols(
    path: &Path,
    isf: Option<&Path>,
) -> Result<Vec<BrowserEvent>, MemoryCarveError> {
    // 1. Open the image. An I/O / unrecognized-format failure is a hard bootstrap
    //    failure (fail loud), never a silent empty.
    let boxed =
        memf_format::open_dump_with_raw_fallback(path).map_err(|e| MemoryCarveError::Open {
            path: path.display().to_string(),
            source: anyhow::Error::new(e),
        })?;
    // Arc so each browser process gets its own cheap-to-clone view of the same
    // physical memory for a per-process address space.
    let provider: Arc<dyn PhysicalMemoryProvider> = Arc::from(boxed);

    // 2. Symbols + OS/DTB/list-head bootstrap.
    let resolver = resolve_symbols(&provider, isf)?;
    let metadata = provider.metadata();

    let os = memf_session::detect_os(metadata.as_ref(), resolver.as_ref())
        .map_err(|e| MemoryCarveError::NotAnOsImage(e.to_string()))?;
    if os != OsProfile::Windows {
        return Err(MemoryCarveError::UnsupportedOs { os: os.to_string() });
    }

    let ctx = memf_session::build_analysis_context(
        metadata.as_ref(),
        resolver.as_ref(),
        provider.as_ref(),
    )
    .map_err(|e| MemoryCarveError::NoProfile(e.to_string()))?;

    let head = ctx.ps_active_process_head.ok_or_else(|| {
        MemoryCarveError::NoProfile(
            "PsActiveProcessHead unresolved (no header value, no symbol RVA); supply --symbols <ISF>"
                .to_string(),
        )
    })?;

    // 3. Enumerate the process list over a kernel-address-space reader, then scan
    //    each browser process's committed user pages.
    let kernel_vas = VirtualAddressSpace::new(
        Arc::clone(&provider),
        ctx.cr3,
        TranslationMode::X86_64FourLevel,
    );
    let reader = ObjectReader::new(kernel_vas, resolver);
    let procs = walk_browser_processes(&reader, head)?;

    let mut events = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for proc in &procs {
        carve_process(&provider, proc, &mut events, &mut seen);
    }
    Ok(events)
}

/// Distinct browser processes referenced by a carved event set, as
/// `(pid, image_name)` — a convenience for callers reporting attribution.
#[must_use]
pub fn browser_processes(events: &[BrowserEvent]) -> Vec<(u64, String)> {
    let mut seen = std::collections::BTreeSet::new();
    for ev in events {
        let pid = ev.attrs.get("pid").and_then(serde_json::Value::as_u64);
        let proc = ev
            .attrs
            .get("process")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if let (Some(pid), Some(proc)) = (pid, proc) {
            seen.insert((pid, proc));
        }
    }
    seen.into_iter().collect()
}

/// Walk the `_EPROCESS` `ActiveProcessLinks` list (both directions, to survive a
/// torn Flink chain) and return the browser processes with their pid, image
/// name, and page-table root. Mirrors memf-windows' process walker but on
/// memf-core's public [`ObjectReader`] with symbol-driven field offsets.
fn walk_browser_processes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<BrowserProc>, MemoryCarveError> {
    let eprocs = reader
        .walk_list_bidirectional(
            ps_head_vaddr,
            "_LIST_ENTRY",
            "Flink",
            "Blink",
            "_EPROCESS",
            "ActiveProcessLinks",
        )
        .map_err(|e| MemoryCarveError::NoProfile(format!("_EPROCESS list walk failed: {e}")))?;

    // Pcb (the embedded _KPROCESS) offset within _EPROCESS, resolved once.
    let pcb_off = reader
        .required_field_offset("_EPROCESS", "Pcb")
        .map_err(|e| MemoryCarveError::NoProfile(format!("missing _EPROCESS.Pcb: {e}")))?;

    let mut procs = Vec::new();
    for eproc in eprocs {
        // Skip a single torn / paged-out entry rather than aborting the walk
        // (Volatility pslist parity): one bad node must never empty the list.
        let Ok(image_name) = reader.read_field_string(eproc, "_EPROCESS", "ImageFileName", 15)
        else {
            continue;
        };
        if browser_family_for_process(&image_name).is_none() {
            continue;
        }
        let Ok(pid) = reader.read_field::<u64>(eproc, "_EPROCESS", "UniqueProcessId") else {
            continue;
        };
        let kproc = eproc.wrapping_add(pcb_off as u64);
        let Ok(cr3) = reader.read_field::<u64>(kproc, "_KPROCESS", "DirectoryTableBase") else {
            continue;
        };
        procs.push(BrowserProc {
            pid,
            image_name,
            cr3,
        });
    }
    Ok(procs)
}

/// Scan one browser process's committed user pages, appending attributed events.
fn carve_process(
    provider: &Arc<dyn PhysicalMemoryProvider>,
    proc: &BrowserProc,
    out: &mut Vec<BrowserEvent>,
    seen: &mut HashSet<String>,
) {
    let family = browser_family_for_process(&proc.image_name).unwrap_or(BrowserFamily::Chromium);
    let vas = VirtualAddressSpace::new(
        Arc::clone(provider),
        proc.cr3,
        TranslationMode::X86_64FourLevel,
    );
    for (vaddr, len) in enumerate_user_leaves(provider.as_ref(), proc.cr3) {
        let read_len = usize::try_from(len)
            .unwrap_or(MAX_REGION_BYTES)
            .min(MAX_REGION_BYTES);
        let mut buf = vec![0u8; read_len];
        if vas.read_virt(vaddr, &mut buf).is_err() {
            continue;
        }
        for ev in scan_bytes_for_urls(&buf) {
            attribute(out, seen, ev, proc, &family, "url");
        }
        for ev in scan_bytes_for_cookies(&buf) {
            attribute(out, seen, ev, proc, &family, "cookie");
        }
    }
}

/// Re-tag a raw-scan [`BrowserEvent`] with its owning process and record it,
/// deduplicating on `(pid, kind, value)` so overlapping reads don't multiply.
fn attribute(
    out: &mut Vec<BrowserEvent>,
    seen: &mut HashSet<String>,
    mut ev: BrowserEvent,
    proc: &BrowserProc,
    family: &BrowserFamily,
    kind: &str,
) {
    let key = format!("{}|{kind}|{}", proc.pid, ev.description);
    if !seen.insert(key) {
        return;
    }
    ev.browser = family.clone();
    ev.source = format!("memory:{}#{}", proc.image_name, proc.pid);
    ev = ev
        .with_attr("pid", json!(proc.pid))
        .with_attr("process", json!(proc.image_name))
        .with_attr("recovery", json!("structured"));
    out.push(ev);
}

/// Read an 8-byte page-table entry at a physical address, or `None` if the read
/// is short / fails (a hole in the dump).
fn read_pte(provider: &dyn PhysicalMemoryProvider, phys: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    match provider.read_phys(phys, &mut buf) {
        Ok(8) => Some(u64::from_le_bytes(buf)),
        _ => None,
    }
}

/// Enumerate the present *user* leaf pages of an x86-64 4-level address space as
/// `(vaddr, len)` pairs, by forward-walking the page tables under `cr3`.
///
/// Only the low-canonical (user) half is walked (PML4 indices `0..256`); 1 GiB
/// pages are skipped (browser heaps are 4 KiB/2 MiB, and a 1 GiB read would be
/// unbounded). A visited-set on table frames plus [`MAX_LEAVES_PER_PROCESS`]
/// bound the work on corrupt or adversarial tables.
fn enumerate_user_leaves(provider: &dyn PhysicalMemoryProvider, cr3: u64) -> Vec<(u64, u64)> {
    let mut leaves = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let pml4_base = cr3 & PTE_ADDR_MASK;

    for i in 0..USER_PML4_ENTRIES {
        if leaves.len() >= MAX_LEAVES_PER_PROCESS {
            break;
        }
        let Some(pml4e) = read_pte(provider, pml4_base + i * 8) else {
            continue;
        };
        if pml4e & PTE_PRESENT == 0 {
            continue;
        }
        let pdpt_base = pml4e & PTE_ADDR_MASK;
        if !visited.insert(pdpt_base) {
            continue;
        }
        for j in 0..PT_ENTRIES {
            if leaves.len() >= MAX_LEAVES_PER_PROCESS {
                break;
            }
            let Some(pdpte) = read_pte(provider, pdpt_base + j * 8) else {
                continue;
            };
            if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PAGE_SIZE != 0 {
                continue; // absent, or a 1 GiB page (skipped)
            }
            let pd_base = pdpte & PTE_ADDR_MASK;
            if !visited.insert(pd_base) {
                continue;
            }
            for k in 0..PT_ENTRIES {
                if leaves.len() >= MAX_LEAVES_PER_PROCESS {
                    break;
                }
                let Some(pde) = read_pte(provider, pd_base + k * 8) else {
                    continue;
                };
                if pde & PTE_PRESENT == 0 {
                    continue;
                }
                if pde & PTE_PAGE_SIZE != 0 {
                    leaves.push((compose_va(i, j, k, 0), PAGE_2M)); // 2 MiB leaf
                    continue;
                }
                let pt_base = pde & PTE_ADDR_MASK;
                if !visited.insert(pt_base) {
                    continue;
                }
                for l in 0..PT_ENTRIES {
                    if leaves.len() >= MAX_LEAVES_PER_PROCESS {
                        break;
                    }
                    let Some(pte) = read_pte(provider, pt_base + l * 8) else {
                        continue;
                    };
                    if pte & PTE_PRESENT != 0 {
                        leaves.push((compose_va(i, j, k, l), PAGE_4K)); // 4 KiB leaf
                    }
                }
            }
        }
    }
    leaves
}

/// Compose a canonical user virtual address from its four page-table indices.
/// Valid for the user half (`pml4 < 256`), so bit 47 is 0 and no sign extension
/// is needed.
fn compose_va(pml4: u64, pdpt: u64, pd: u64, pt: u64) -> u64 {
    (pml4 << 39) | (pdpt << 30) | (pd << 21) | (pt << 12)
}

/// Resolve a symbol backend: an explicit ISF file (fail loud if unreadable), or
/// auto-profile from the dump, degrading to an empty resolver if the kernel PDB
/// cannot be acquired (the caller surfaces a clear "no profile" error later).
fn resolve_symbols(
    provider: &Arc<dyn PhysicalMemoryProvider>,
    isf: Option<&Path>,
) -> Result<Box<dyn SymbolResolver>, MemoryCarveError> {
    if let Some(p) = isf {
        return memf_symbols::isf::IsfResolver::from_path(p)
            .map(|r| Box::new(r) as Box<dyn SymbolResolver>)
            .map_err(|e| {
                MemoryCarveError::NoProfile(format!("cannot load ISF symbols {}: {e}", p.display()))
            });
    }

    if let Ok(auto) = memf_symbols::AutoProfile::new() {
        if let Ok(resolver) = auto.from_dump(provider) {
            return Ok(resolver);
        }
    }

    memf_symbols::isf::IsfResolver::from_value(&json!({}))
        .map(|r| Box::new(r) as Box<dyn SymbolResolver>)
        .map_err(|e| MemoryCarveError::NoProfile(format!("empty symbol resolver init failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;
    use serde_json::Value;

    fn windows_symbols() -> Box<dyn SymbolResolver> {
        Box::new(
            IsfResolver::from_value(&IsfBuilder::windows_kernel_preset().build_json()).unwrap(),
        )
    }

    #[test]
    fn browser_family_classification() {
        assert_eq!(
            browser_family_for_process("CHROME.EXE"),
            Some(BrowserFamily::Chromium)
        );
        assert_eq!(
            browser_family_for_process("firefox.exe"),
            Some(BrowserFamily::Firefox)
        );
        assert_eq!(browser_family_for_process("notepad.exe"), None);
    }

    #[test]
    fn error_degradability_matches_policy() {
        assert!(MemoryCarveError::NotAnOsImage("x".into()).is_degradable());
        assert!(MemoryCarveError::UnsupportedOs { os: "Linux".into() }.is_degradable());
        assert!(!MemoryCarveError::NoProfile("x".into()).is_degradable());
        assert!(!MemoryCarveError::Open {
            path: "p".into(),
            source: anyhow::anyhow!("io"),
        }
        .is_degradable());
    }

    #[test]
    fn browser_processes_dedups_by_pid_and_name() {
        let ev = |pid: u64, proc: &str| {
            BrowserEvent::new(
                0,
                BrowserFamily::Chromium,
                browser_forensic_core::ArtifactKind::Memory,
                "s",
                "d",
            )
            .with_attr("pid", json!(pid))
            .with_attr("process", json!(proc))
        };
        let evs = vec![
            ev(10, "chrome.exe"),
            ev(10, "chrome.exe"),
            ev(20, "firefox.exe"),
        ];
        assert_eq!(
            browser_processes(&evs),
            vec![
                (10, "chrome.exe".to_string()),
                (20, "firefox.exe".to_string())
            ]
        );
    }

    /// Tier-2: the page-table walk is validated against memf-core's *independent*
    /// translation engine. Every leaf we enumerate must translate, via
    /// `virt_to_phys`, back to the physical frame the builder mapped.
    #[test]
    fn enumerate_user_leaves_matches_independent_translation() {
        let mapped: &[(u64, u64)] = &[
            (0x0000_0000_1000, 0x2_0000), // low user page
            (0x7FFF_0000_2000, 0x2_1000), // high user page (still PML4 < 256)
        ];
        let mut b = PageTableBuilder::new();
        for &(va, pa) in mapped {
            b = b.map_4k(va, pa, flags::PRESENT | flags::WRITABLE | flags::USER);
        }
        let (cr3, mem) = b.build();

        let leaves = enumerate_user_leaves(&mem, cr3);
        for &(va, _) in mapped {
            assert!(
                leaves.iter().any(|&(lv, _)| lv == va),
                "enumerator must find mapped VA {va:#x}"
            );
        }
        // Independent oracle: memf-core translates each enumerated VA, and it must
        // land on a frame we actually mapped (no phantom leaves).
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        for &(va, _) in &leaves {
            let phys = vas.virt_to_phys(va).expect("enumerated VA must translate");
            assert!(
                mapped
                    .iter()
                    .any(|&(mva, mpa)| mva == va && (phys & PTE_ADDR_MASK) == mpa),
                "leaf {va:#x} translated to unexpected phys {phys:#x}"
            );
        }
        // Kernel-half pages are never enumerated.
        assert!(leaves.iter().all(|&(va, _)| va < (USER_PML4_ENTRIES << 39)));
    }

    /// Tier-2: end-to-end for one process — a URL sitting in a committed user
    /// page is carved and attributed to the owning pid/process.
    #[test]
    fn carve_process_finds_and_attributes_url() {
        let heap_va = 0x0000_0002_0000;
        let heap_pa = 0x5_0000;
        let (cr3, mut mem) = PageTableBuilder::new()
            .map_4k(
                heap_va,
                heap_pa,
                flags::PRESENT | flags::WRITABLE | flags::USER,
            )
            .build();
        mem.write_bytes(heap_pa, b"junk\0https://carved.example/secret\0more");

        let provider: Arc<dyn PhysicalMemoryProvider> = Arc::new(mem);
        let proc = BrowserProc {
            pid: 4321,
            image_name: "chrome.exe".to_string(),
            cr3,
        };
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        carve_process(&provider, &proc, &mut out, &mut seen);

        let url = out.iter().find(|e| {
            e.attrs.get("url").and_then(Value::as_str) == Some("https://carved.example/secret")
        });
        let url = url.expect("carved URL from the mapped heap page");
        assert_eq!(url.attrs.get("pid").and_then(Value::as_u64), Some(4321));
        assert_eq!(
            url.attrs.get("process").and_then(Value::as_str),
            Some("chrome.exe")
        );
        assert_eq!(url.browser, BrowserFamily::Chromium);
        assert_eq!(
            url.attrs.get("recovery").and_then(Value::as_str),
            Some("structured")
        );
    }

    /// Tier-2: the `_EPROCESS` walk finds a browser process and reads its pid,
    /// image name, and DTB via symbol-driven offsets — over memf-core's real
    /// address-space translation.
    #[test]
    fn walk_browser_processes_extracts_pid_name_cr3() {
        // Kernel VAs for the list head and the single _EPROCESS.
        let head_va = 0xFFFF_F800_0000_1000_u64;
        let head_pa = 0x10_0000_u64;
        let eproc_va = 0xFFFF_F800_0000_2000_u64;
        let eproc_pa = 0x11_0000_u64;
        // Offsets from windows_kernel_preset.
        let active_links = 0x448_u64;
        let (kcr3, mut mem) = PageTableBuilder::new()
            .map_4k(head_va, head_pa, flags::PRESENT | flags::WRITABLE)
            .map_4k(eproc_va, eproc_pa, flags::PRESENT | flags::WRITABLE)
            .build();

        // PsActiveProcessHead._LIST_ENTRY.{Flink,Blink} → eproc.ActiveProcessLinks
        let links_va = eproc_va + active_links;
        mem.write_u64(head_pa, links_va); // Flink
        mem.write_u64(head_pa + 8, links_va); // Blink
                                              // _EPROCESS at eproc_pa: ActiveProcessLinks.{Flink,Blink} → back to head
        mem.write_u64(eproc_pa + active_links, head_va);
        mem.write_u64(eproc_pa + active_links + 8, head_va);
        mem.write_u64(eproc_pa + 0x440, 0x1234); // UniqueProcessId
        mem.write_u64(eproc_pa + 0x28, 0xAB_0000); // Pcb(_KPROCESS).DirectoryTableBase
        mem.write_bytes(eproc_pa + 0x5A8, b"chrome.exe\0"); // ImageFileName

        let reader = ObjectReader::new(
            VirtualAddressSpace::new(mem, kcr3, TranslationMode::X86_64FourLevel),
            windows_symbols(),
        );
        let procs = walk_browser_processes(&reader, head_va).expect("walk");
        assert_eq!(procs.len(), 1, "one browser process");
        assert_eq!(procs[0].pid, 0x1234);
        assert_eq!(procs[0].image_name, "chrome.exe");
        assert_eq!(procs[0].cr3, 0xAB_0000);
    }

    /// A non-browser process is not returned by the walk.
    #[test]
    fn walk_skips_non_browser_process() {
        let head_va = 0xFFFF_F800_0000_1000_u64;
        let head_pa = 0x10_0000_u64;
        let eproc_va = 0xFFFF_F800_0000_2000_u64;
        let eproc_pa = 0x11_0000_u64;
        let active_links = 0x448_u64;
        let (kcr3, mut mem) = PageTableBuilder::new()
            .map_4k(head_va, head_pa, flags::PRESENT | flags::WRITABLE)
            .map_4k(eproc_va, eproc_pa, flags::PRESENT | flags::WRITABLE)
            .build();
        let links_va = eproc_va + active_links;
        mem.write_u64(head_pa, links_va);
        mem.write_u64(head_pa + 8, links_va);
        mem.write_u64(eproc_pa + active_links, head_va);
        mem.write_u64(eproc_pa + active_links + 8, head_va);
        mem.write_u64(eproc_pa + 0x440, 0x99);
        mem.write_u64(eproc_pa + 0x28, 0xAB_0000);
        mem.write_bytes(eproc_pa + 0x5A8, b"notepad.exe\0");

        let reader = ObjectReader::new(
            VirtualAddressSpace::new(mem, kcr3, TranslationMode::X86_64FourLevel),
            windows_symbols(),
        );
        assert!(walk_browser_processes(&reader, head_va).unwrap().is_empty());
    }
}
