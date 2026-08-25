# Changelog

## [1.1.0](https://github.com/vln-devsecops/actions-sca-syft-grype/compare/v1.0.1...v1.1.0) (2026-08-25)


### Features

* add include-dev-dependencies input, document scan scope ([#14](https://github.com/vln-devsecops/actions-sca-syft-grype/issues/14)) ([478f9a6](https://github.com/vln-devsecops/actions-sca-syft-grype/commit/478f9a6f1b040110e0dd26a4576ee1026cfb8c47))


### Bug Fixes

* exclude this action's own checkout from the syft catalogue ([#16](https://github.com/vln-devsecops/actions-sca-syft-grype/issues/16)) ([c8545f0](https://github.com/vln-devsecops/actions-sca-syft-grype/commit/c8545f0444ffd6973a2080923f06f8bc381cce32))

## [1.0.1](https://github.com/vln-devsecops/actions-sca-syft-grype/compare/v1.0.0...v1.0.1) (2026-08-24)


### Bug Fixes

* use job.workflow_ref to resolve this action's own source ([#12](https://github.com/vln-devsecops/actions-sca-syft-grype/issues/12)) ([b5a9cfc](https://github.com/vln-devsecops/actions-sca-syft-grype/commit/b5a9cfcc7fe82799375bb91b9024fd8bf7113774))

## [1.0.0](https://github.com/vln-devsecops/actions-sca-syft-grype/compare/v0.1.0...v1.0.0) (2026-08-24)


### Features

* emit a CycloneDX SBOM alongside syft's native syft-json ([67c7f00](https://github.com/vln-devsecops/actions-sca-syft-grype/commit/67c7f001e7cf30b61fc9a8b1650ea4f84b651a79))
* emit a CycloneDX SBOM alongside syft's native syft-json ([#11](https://github.com/vln-devsecops/actions-sca-syft-grype/issues/11)) ([67c7f00](https://github.com/vln-devsecops/actions-sca-syft-grype/commit/67c7f001e7cf30b61fc9a8b1650ea4f84b651a79))
* SCA via syft (SBOM) + grype (vulnerability scan) ([#1](https://github.com/vln-devsecops/actions-sca-syft-grype/issues/1)) ([4e6f837](https://github.com/vln-devsecops/actions-sca-syft-grype/commit/4e6f837f61c34d15b037515b29f37638cc157924))
