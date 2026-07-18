<p align="center">
  <img src="logo.svg" alt="OptimCE-Logo" width="160">
</p>

# kc-groupid-mapper

> Keycloak-OIDC-Protokoll-Mapper, der Gruppenmitgliedschaft in einen `orgs`-Token-Claim mit Rollen umwandelt.

[![Website](https://img.shields.io/badge/Website-optimce.be-2e7d32.svg)](https://www.optimce.be/de/)
[![Lizenz](https://img.shields.io/badge/Lizenz-Apache%202.0-blue.svg)](../LICENSE)
[![Keycloak](https://img.shields.io/badge/Keycloak-26.5.1-blue.svg)](https://www.keycloak.org/)
[![en](https://img.shields.io/badge/lang-en-lightgrey.svg)](../README.md)
[![fr](https://img.shields.io/badge/lang-fr-lightgrey.svg)](README.fr.md)
[![de](https://img.shields.io/badge/lang-de-43a047.svg)](README.de.md)
[![nl](https://img.shields.io/badge/lang-nl-lightgrey.svg)](README.nl.md)

`kc-groupid-mapper` ist ein benutzerdefinierter
[Keycloak](https://www.keycloak.org/) OIDC-Protokoll-Mapper. Er liest die
Gruppenmitgliedschaft eines Benutzers und fügt seinen Tokens einen Claim hinzu,
der die **Organisationen**, denen er angehört, sowie seine **Rollen** in jeder
einzelnen beschreibt — vollständig aus dem Gruppenbaum abgeleitet, ohne
zusätzliches Datenmodell.

Er ist Teil der [OptimCE](https://www.optimce.be/de/)-Plattform, wo er es
nachgelagerten Diensten ermöglicht, Anfragen pro Energiegemeinschaft allein
anhand des Access-Tokens zu autorisieren. Er wird im
[OptimCE-Monorepo](https://github.com/OptimCE/monorepo) entwickelt und hier als
eigenständiger Provider veröffentlicht.

## Was er tut

Der Mapper durchläuft jede Gruppe des Benutzers und sucht unter einem
konfigurierbaren **Wurzelpfad** nach Organisationsgruppen. Die erwartete
Gruppenstruktur sieht so aus:

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

Für jede Organisation, der der Benutzer angehört, gibt er einen Eintrag mit der
Gruppen-ID (`orgId`), dem Gruppenpfad (`orgPath`) und der Menge der aus den
`roles/`-Untergruppen gesammelten Rollen aus. Ein Benutzer, der Mitglied von
`/orgs/acme/roles/ADMIN`, `/orgs/acme/roles/BILLING` und
`/orgs/globex/roles/VIEWER` ist, erhält:

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

Der Name des Claims (oben `orgs`) ist konfigurierbar, und der Claim kann dem
Access-Token, dem ID-Token, der UserInfo-Antwort und der Token-Introspektion
hinzugefügt werden.

### Rollenmodus

Wie Rollen aus den Untergruppen einer Organisation extrahiert werden, hängt von
der Option `rolesMode` ab:

- **`strict`** (Standard) — nur Gruppen unter `roles/` zählen, d. h.
  `/orgs/<org>/roles/<ROLE>`.
- **`loose`** — sowohl `/orgs/<org>/roles/<ROLE>` als auch die Kurzform
  `/orgs/<org>/<ROLE>` zählen.

## Konfiguration

Sobald der Provider bereitgestellt ist, fügen Sie den Mapper **Organizations
(id/path) with roles** (Provider-ID `oidc-orgs-with-roles-mapper`) zu einem
Client oder Client-Scope hinzu und konfigurieren Sie:

| Option | Konfigurationsschlüssel | Standardwert | Beschreibung |
|---|---|---|---|
| Claim name | `claimName` | *(leer)* | Name des JWT-Claims, der das Organisationen-mit-Rollen-Array enthält. |
| Orgs root group path | `orgsRootPath` | `/` | Gruppenpfad, dessen direkte Kinder Organisationen sind, z. B. `/orgs`. `/` bedeutet, dass Gruppen der obersten Ebene Organisationen sind. |
| Roles mode | `rolesMode` | `strict` | `strict` akzeptiert nur `/orgs/<org>/roles/<ROLE>`; `loose` akzeptiert auch `/orgs/<org>/<ROLE>`. |

Die üblichen OIDC-Umschalter zur Token-Aufnahme (Hinzufügen zu ID-Token,
Access-Token, Lightweight-Access-Token, UserInfo und Token-Introspektion) stehen
ebenfalls zur Verfügung.

## Bauen

Erfordert **JDK 17** und **Maven**.

```bash
mvn -B package
```

Dies erzeugt das Provider-JAR unter `target/kc-groupid-mapper-1.0.0.jar`.
Vorgefertigte JARs sind außerdem an jedes
[GitHub-Release](https://github.com/OptimCE/kc-groupid-mapper/releases)
angehängt.

## Verwendung in Keycloak

Der Provider ist auf **Keycloak 26.5.1** ausgerichtet.

1. Kopieren Sie das JAR in das Providers-Verzeichnis von Keycloak:

   ```bash
   cp target/kc-groupid-mapper-1.0.0.jar /opt/keycloak/providers/
   ```

2. Bauen Sie Keycloak neu, damit es den neuen Provider erkennt:

   ```bash
   /opt/keycloak/bin/kc.sh build
   ```

3. Fügen Sie in der Admin-Konsole den Mapper **Organizations (id/path) with
   roles** zu einem Client oder Client-Scope hinzu und setzen Sie die obigen
   Optionen.

Um ihn in ein Keycloak-Image einzubinden, baut das mitgelieferte
[`Dockerfile`](../Dockerfile) das JAR und installiert es in einem einzigen
mehrstufigen Build:

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

## Wie OptimCE ihn verwendet

Im OptimCE-Realm ist der Mapper an einen eigenen Client-Scope mit dem
Claim-Namen `orgs` und `rolesMode` auf `loose` gebunden, sodass jedes
ausgestellte Token die Gemeinschaften des Aufrufers und deren Rollen trägt. Die
vollständige Einrichtung finden Sie in der Keycloak-Realm-Konfiguration im
[Monorepo](https://github.com/OptimCE/monorepo).

## Mitwirken

Beiträge sind willkommen! Bitte lesen Sie die
[Beitragsrichtlinien](../CONTRIBUTING.md) und unseren
[Verhaltenskodex](../CODE_OF_CONDUCT.md), bevor Sie ein Issue oder einen Pull
Request eröffnen.

## Sicherheit

Um eine Sicherheitslücke zu melden, folgen Sie bitte der
[Sicherheitsrichtlinie](../SECURITY.md) — öffnen Sie kein öffentliches Issue.

## Lizenz

Dieses Projekt ist unter der [Apache License 2.0](../LICENSE) lizenziert.
