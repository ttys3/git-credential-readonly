# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add a Bubble Tea-based credential management TUI with structured, validated
  fields for listing, creating, editing, and deleting credentials.
- Add opt-in storage through macOS Keychain, Linux/BSD Secret Service, and
  Windows Credential Manager, with explicit `keyring` and `auto` lookup modes.

### Changed

- Preserve the existing credential-file backend while making TUI writes
  atomic, concurrency-aware, scope-ordered, and permission-restricted.
- Require Go 1.25 or newer for the Bubble Tea v2 interface.

### Security

- Keep secrets out of TUI lists, confirmation screens, and the on-disk keyring
  index; verify protected payload metadata before returning a credential.
- Make keyring edits and deletions interruption-safe with atomic index switches
  and verified cleanup of obsolete protected items.
- Generate credential URLs from validated structured fields instead of asking
  users to manually encode usernames, tokens, hosts, and paths.

## [1.1.3] - 2026-09-04

### Changed

- Validate GoReleaser snapshot builds on pull requests while publishing releases
  only from tags, using Go 1.27.1 and GoReleaser Action v7.

### Fixed

- Match multi-level credential path scopes only at slash boundaries, preventing
  similarly prefixed groups or repositories from receiving the wrong token.
- Match Git's credential URL parsing and decoding behavior, including literal
  plus signs, single-pass percent decoding, and query or fragment boundaries.
- Keep passwords and malformed credential lines out of debug logs, and set
  debug log file permissions to `0600` on POSIX systems.

## [1.1.2] - 2026-09-03

### Fixed

- Accept both blank-line and end-of-file termination in Git credential helper requests.
- Match full repository paths while retaining owner and organization shorthand matching.
- Document the required ordering when an empty `credential.helper` resets inherited helpers.

[Unreleased]: https://github.com/ttys3/git-credential-readonly/compare/v1.1.3...HEAD
[1.1.3]: https://github.com/ttys3/git-credential-readonly/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/ttys3/git-credential-readonly/compare/v1.1.1...v1.1.2
