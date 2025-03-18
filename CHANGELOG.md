# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Context support for timeouts and cancellation
- Improved error handling with more consistent error messages
- Mutex to protect the busy flag for better concurrency handling
- Expanded test coverage
- GitHub Actions workflow for CI/CD
- Comprehensive documentation and examples

### Changed
- Updated Go version to 1.20
- Improved stream reading with context awareness
- Enhanced error handling in all methods
- Better handling of nil pointers and edge cases

### Fixed
- Race condition in concurrent command execution
- Potential resource leaks in error cases
- Improved error messages for better debugging