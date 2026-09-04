# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ttys3/git-credential-readonly/compare/v1.1.2...HEAD
[1.1.2]: https://github.com/ttys3/git-credential-readonly/compare/v1.1.1...v1.1.2
