# Contributing to kc-groupid-mapper

Thank you for your interest in contributing! Issues and pull requests are
welcome from everyone. By participating in this project, you agree to abide by
our [Code of Conduct](CODE_OF_CONDUCT.md).

`kc-groupid-mapper` is a custom [Keycloak](https://www.keycloak.org/) OIDC
protocol mapper, part of the [OptimCE](https://github.com/OptimCE) platform. It
is developed in the [OptimCE monorepo](https://github.com/OptimCE/monorepo) and
mirrored to this repository as a standalone provider.

## Reporting Bugs and Suggesting Features

Open a [GitHub issue](https://github.com/OptimCE/kc-groupid-mapper/issues). For
bugs, include what you did, what you expected, and what happened instead — the
Keycloak version, the mapper configuration (claim name, orgs root path, roles
mode), the relevant group structure, and the resulting token claim all help a
lot.

For security vulnerabilities, **do not open a public issue**; follow the
[security policy](SECURITY.md) instead.

## Setting Up a Development Environment

You need **JDK 17** and **Maven**.

```bash
git clone https://github.com/OptimCE/kc-groupid-mapper.git
cd kc-groupid-mapper
mvn -B package
```

The build produces the provider JAR at `target/kc-groupid-mapper-1.0.0.jar`. To
test it against a running Keycloak, copy the JAR into the server's providers
directory and rebuild:

```bash
cp target/kc-groupid-mapper-*.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
```

Then add the **Organizations (id/path) with roles** mapper to a client or client
scope and inspect the issued token. See the [README](README.md) for the full
configuration reference.

## Submitting Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. Make your changes. Keep each pull request focused on a single topic.
3. Make sure the project still builds (`mvn -B package`).
4. Open a pull request against `main`, describing **what** you changed and
   **why**.

Note: releases are cut automatically when the `<version>` in `pom.xml` changes
on `main`, so version bumps are handled by the maintainers — please don't
include them in feature pull requests.

## Commit Messages

Use short, imperative commit messages, preferably following the
[Conventional Commits](https://www.conventionalcommits.org/) style:

```
feat: add loose roles mode
fix: handle org group paths that contain spaces
chore: bump Keycloak to 26.5.1
docs: document the orgs claim shape
```

## License

kc-groupid-mapper is licensed under the [Apache License 2.0](LICENSE). By
contributing, you agree that your contributions will be licensed under the same
license.
