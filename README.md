<p align="center">
  <img src="docs/logo.svg" alt="OptimCE logo" width="160">
</p>

# kc-groupid-mapper

> Keycloak OIDC protocol mapper that turns group membership into an `orgs` token claim with roles.

[![Website](https://img.shields.io/badge/Website-optimce.be-2e7d32.svg)](https://www.optimce.be/en/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Keycloak](https://img.shields.io/badge/Keycloak-26.5.1-blue.svg)](https://www.keycloak.org/)
[![en](https://img.shields.io/badge/lang-en-43a047.svg)](README.md)
[![fr](https://img.shields.io/badge/lang-fr-lightgrey.svg)](docs/README.fr.md)
[![de](https://img.shields.io/badge/lang-de-lightgrey.svg)](docs/README.de.md)
[![nl](https://img.shields.io/badge/lang-nl-lightgrey.svg)](docs/README.nl.md)

`kc-groupid-mapper` is a custom [Keycloak](https://www.keycloak.org/) OIDC
protocol mapper. It reads a user's group membership and adds a single claim to
their tokens describing the **organizations** they belong to and their **roles**
within each one — derived entirely from the group tree, with no extra data
model.

It is part of the [OptimCE](https://www.optimce.be/en/) platform, where it lets
downstream services authorize requests per energy community from the access
token alone. It is developed in the
[OptimCE monorepo](https://github.com/OptimCE/monorepo) and released here as a
standalone provider.

## What It Does

The mapper walks each of the user's groups and looks for organization groups
under a configurable **root path**. The expected group layout is:

```
/orgs
  /acme
    /roles
      /ADMIN
      /BILLING
  /globex
    /roles
      /VIEWER
```

For every organization the user belongs to, it emits one entry containing the
group id (`orgId`), the group path (`orgPath`), and the set of roles collected
from the `roles/` subgroups. A user who is a member of `/orgs/acme/roles/ADMIN`,
`/orgs/acme/roles/BILLING`, and `/orgs/globex/roles/VIEWER` gets:

```json
"orgs": [
  {
    "orgId": "3f2a9c14-…",
    "orgPath": "/orgs/acme",
    "roles": ["ADMIN", "BILLING"]
  },
  {
    "orgId": "9c1b7e08-…",
    "orgPath": "/orgs/globex",
    "roles": ["VIEWER"]
  }
]
```

The claim name (`orgs` above) is configurable, and the claim can be added to the
access token, the ID token, the UserInfo response, and token introspection.

### Roles mode

How roles are extracted from an organization's subgroups depends on the
`rolesMode` option:

- **`strict`** (default) — only groups under `roles/` count, i.e.
  `/orgs/<org>/roles/<ROLE>`.
- **`loose`** — both `/orgs/<org>/roles/<ROLE>` and the shorthand
  `/orgs/<org>/<ROLE>` count.

## Configuration

Once the provider is deployed, add the **Organizations (id/path) with roles**
mapper (provider id `oidc-orgs-with-roles-mapper`) to a client or client scope
and configure:

| Option | Config key | Default | Description |
|---|---|---|---|
| Claim name | `claimName` | *(empty)* | Name of the JWT claim that holds the organizations-with-roles array. |
| Orgs root group path | `orgsRootPath` | `/` | Group path whose direct children are organizations, e.g. `/orgs`. `/` means top-level groups are organizations. |
| Roles mode | `rolesMode` | `strict` | `strict` accepts only `/orgs/<org>/roles/<ROLE>`; `loose` also accepts `/orgs/<org>/<ROLE>`. |

The standard OIDC token-inclusion toggles (add to ID token, access token,
lightweight access token, UserInfo, and token introspection) are available as
well.

## Building

Requires **JDK 17** and **Maven**.

```bash
mvn -B package
```

This produces the provider JAR at `target/kc-groupid-mapper-1.0.0.jar`.
Pre-built JARs are also attached to each
[GitHub Release](https://github.com/OptimCE/kc-groupid-mapper/releases).

## Using It in Keycloak

The provider targets **Keycloak 26.5.1**.

1. Copy the JAR into Keycloak's providers directory:

   ```bash
   cp target/kc-groupid-mapper-1.0.0.jar /opt/keycloak/providers/
   ```

2. Rebuild Keycloak so it picks up the new provider:

   ```bash
   /opt/keycloak/bin/kc.sh build
   ```

3. In the admin console, add the **Organizations (id/path) with roles** mapper
   to a client or client scope and set the options above.

To bake it into a Keycloak image, the included [`Dockerfile`](Dockerfile) builds
the JAR and installs it in one multi-stage build:

```dockerfile
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn -B -q -e -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM quay.io/keycloak/keycloak:26.5.1
WORKDIR /opt/keycloak
COPY --from=builder /app/target/kc-groupid-mapper-*.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
```

## How OptimCE Uses It

In the OptimCE realm the mapper is attached to a dedicated client scope with the
claim name `orgs` and `rolesMode` set to `loose`, so that every issued token
carries the caller's communities and their roles. See the Keycloak realm
configuration in the [monorepo](https://github.com/OptimCE/monorepo) for the
full setup.

## Contributing

Contributions are welcome! Please read the
[contributing guidelines](CONTRIBUTING.md) and our
[Code of Conduct](CODE_OF_CONDUCT.md) before opening an issue or pull request.

## Security

To report a security vulnerability, please follow the
[security policy](SECURITY.md) — do not open a public issue.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
