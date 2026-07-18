# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-17

### Added

- Initial release of the Keycloak OIDC protocol mapper
  `oidc-orgs-with-roles-mapper` ("Organizations (id/path) with roles").
- Emits an organizations claim shaped as
  `[{ "orgId", "orgPath", "roles": [...] }]`, derived from the user's group
  membership under a configurable root path.
- Configuration options: `claimName` (target JWT claim), `orgsRootPath`
  (group path whose children are organizations), and `rolesMode` with `strict`
  (`/orgs/<org>/roles/<ROLE>`) and `loose` (also `/orgs/<org>/<ROLE>`) behavior.
- Support for adding the claim to the access token, ID token, UserInfo
  response, and token introspection.
- Built for Keycloak 26.5.1 on JDK 17.
