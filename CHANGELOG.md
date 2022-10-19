# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [v1.0] - 2022-10-19
### Added
- Tag pushing will now trigger CI workflow to perform test then release.
- Add cross platform support for docker in CI workflow.
- More tests are added to CI workflow:
    - debian:buster/bullseye in linux/arm64 platform.
    - ubuntu:18.04/20.04 in linux/arm64 platform. Test failed in ubuntu:22.04 with error "swtpm: seccomp_load failed with errno 125: Operation canceled", to be investigated.

## [vX.X] - YYYY-MM-DD
### Added
### Changed
### Fixed
### Removed
