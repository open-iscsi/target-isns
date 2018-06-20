# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.5] - 2018-06-20
### Fixed
- Fix registration of new targets after all existing targets are
  removed (issue #38).
- Fix invalid update error returned by the Microsoft iSNS server when
  removing a portal (issue #40).
- Fix string truncation and compilation with gcc 8. Contributed by Lee
  Duncan.

## [0.6.4] - 2018-01-20
### Fixed
- Fix segfault caused by large PDUs by generating multiple PDUs for
  large registration messages. Contributed by Kyle Fortin.

### Added
- Add the `--configfs-iscsi-path` option to exercise target-isns with
  fake configfs hierarchies that emulate large iSCSI configurations.
  Contributed by Kyle Fortin.
- Add [how to test target-isns with Open-iSNS](documentation/testing.md)
- Add a [changelog](CHANGELOG.md).


## [0.6.3] - 2017-03-05
