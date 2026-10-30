# etwtrace-rs

A WPR-style ETW recorder and reporter for Windows, written in Rust. It records CPU samples, context switches and ready-thread events with stacks, plus optional hardware counters (PMC overflow sampling, LBR, per-context-switch counts) and many more kernel events. It writes a standard `.etl` file.

## Usage

`record` and `probe` need an elevated prompt.

```
etwtrace list                          # hardware counters, interval limits, free slots
etwtrace probe [-interval N]           # which counters deliver overflow samples here
etwtrace record [-o File.etl] [-sec N] [options]
etwtrace report File.etl               # event counts, stack coverage, per-event summaries
```

```
etwtrace record -pmc BranchMispredictions:100000,LLCMisses:20000 -lbr -sec 10
etwtrace record -counters InstructionRetired,UnhaltedCoreCycles -fileio -tcpip -dns -sec 30
```

Run `etwtrace` with no arguments for every option.

## Build

```
cargo build --release
```

Requires Rust 1.95+ on Windows. Every push to `main` publishes `etwtrace.exe` and `etwtrace.pdb` from CI after checks pass, tagged `main-<run-number>`. Tagged releases (`v*`) also publish these files.

## Layout

- `crates/etw`: safe wrappers over the Win32 ETW APIs (the only crate with `unsafe`)
- `crates/etwtrace`: the CLI
