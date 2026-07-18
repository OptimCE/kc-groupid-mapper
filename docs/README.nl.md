<p align="center">
  <img src="logo.svg" alt="OptimCE-logo" width="160">
</p>

# kc-groupid-mapper

> Keycloak OIDC-protocol-mapper die groepslidmaatschap omzet in een `orgs`-tokenclaim met rollen.

[![Website](https://img.shields.io/badge/Website-optimce.be-2e7d32.svg)](https://www.optimce.be/nl/)
[![Licentie](https://img.shields.io/badge/Licentie-Apache%202.0-blue.svg)](../LICENSE)
[![Keycloak](https://img.shields.io/badge/Keycloak-26.5.1-blue.svg)](https://www.keycloak.org/)
[![en](https://img.shields.io/badge/lang-en-lightgrey.svg)](../README.md)
[![fr](https://img.shields.io/badge/lang-fr-lightgrey.svg)](README.fr.md)
[![de](https://img.shields.io/badge/lang-de-lightgrey.svg)](README.de.md)
[![nl](https://img.shields.io/badge/lang-nl-43a047.svg)](README.nl.md)

`kc-groupid-mapper` is een aangepaste [Keycloak](https://www.keycloak.org/)
OIDC-protocol-mapper. Hij leest het groepslidmaatschap van een gebruiker en
voegt aan diens tokens een claim toe die de **organisaties** beschrijft waartoe
hij behoort en zijn **rollen** binnen elk daarvan — volledig afgeleid uit de
groepsboom, zonder extra datamodel.

Hij maakt deel uit van het [OptimCE](https://www.optimce.be/nl/)-platform, waar
hij downstreamdiensten in staat stelt om verzoeken per energiegemeenschap te
autoriseren op basis van uitsluitend het accesstoken. Hij wordt ontwikkeld in de
[OptimCE-monorepo](https://github.com/OptimCE/monorepo) en hier als zelfstandige
provider gepubliceerd.

## Wat het doet

De mapper doorloopt elke groep van de gebruiker en zoekt onder een
configureerbaar **hoofdpad** naar organisatiegroepen. De verwachte
groepsstructuur ziet er zo uit:

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

Voor elke organisatie waartoe de gebruiker behoort, geeft hij één vermelding met
de groeps-id (`orgId`), het groepspad (`orgPath`) en de verzameling rollen die
uit de `roles/`-subgroepen zijn verzameld. Een gebruiker die lid is van
`/orgs/acme/roles/ADMIN`, `/orgs/acme/roles/BILLING` en
`/orgs/globex/roles/VIEWER` krijgt:

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

De naam van de claim (`orgs` hierboven) is configureerbaar, en de claim kan
worden toegevoegd aan het accesstoken, het ID-token, het UserInfo-antwoord en
tokenintrospectie.

### Rollenmodus

Hoe rollen uit de subgroepen van een organisatie worden gehaald, hangt af van de
optie `rolesMode`:

- **`strict`** (standaard) — alleen groepen onder `roles/` tellen mee, d.w.z.
  `/orgs/<org>/roles/<ROLE>`.
- **`loose`** — zowel `/orgs/<org>/roles/<ROLE>` als de verkorte vorm
  `/orgs/<org>/<ROLE>` tellen mee.

## Configuratie

Zodra de provider is uitgerold, voegt u de mapper **Organizations (id/path) with
roles** (provider-id `oidc-orgs-with-roles-mapper`) toe aan een client of
clientscope en configureert u:

| Optie | Configuratiesleutel | Standaardwaarde | Beschrijving |
|---|---|---|---|
| Claim name | `claimName` | *(leeg)* | Naam van de JWT-claim die de array organisaties-met-rollen bevat. |
| Orgs root group path | `orgsRootPath` | `/` | Groepspad waarvan de directe kinderen organisaties zijn, bv. `/orgs`. `/` betekent dat groepen op het hoogste niveau organisaties zijn. |
| Roles mode | `rolesMode` | `strict` | `strict` accepteert alleen `/orgs/<org>/roles/<ROLE>`; `loose` accepteert ook `/orgs/<org>/<ROLE>`. |

De standaard OIDC-schakelaars voor tokenopname (toevoegen aan ID-token,
accesstoken, lightweight-accesstoken, UserInfo en tokenintrospectie) zijn
eveneens beschikbaar.

## Bouwen

Vereist **JDK 17** en **Maven**.

```bash
mvn -B package
```

Dit levert de provider-JAR op in `target/kc-groupid-mapper-1.0.0.jar`. Vooraf
gebouwde JAR's worden ook bij elke
[GitHub-release](https://github.com/OptimCE/kc-groupid-mapper/releases) gevoegd.

## Gebruik in Keycloak

De provider is gericht op **Keycloak 26.5.1**.

1. Kopieer de JAR naar de providers-map van Keycloak:

   ```bash
   cp target/kc-groupid-mapper-1.0.0.jar /opt/keycloak/providers/
   ```

2. Herbouw Keycloak zodat de nieuwe provider wordt opgepikt:

   ```bash
   /opt/keycloak/bin/kc.sh build
   ```

3. Voeg in de beheerconsole de mapper **Organizations (id/path) with roles** toe
   aan een client of clientscope en stel de bovenstaande opties in.

Om hem in een Keycloak-image op te nemen, bouwt de meegeleverde
[`Dockerfile`](../Dockerfile) de JAR en installeert die in één meerfasige build:

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

## Hoe OptimCE het gebruikt

In het OptimCE-realm is de mapper gekoppeld aan een aparte clientscope met
claimnaam `orgs` en `rolesMode` ingesteld op `loose`, zodat elk uitgegeven token
de gemeenschappen van de aanroeper en hun rollen bevat. Zie de
Keycloak-realmconfiguratie in de [monorepo](https://github.com/OptimCE/monorepo)
voor de volledige installatie.

## Bijdragen

Bijdragen zijn welkom! Lees a.u.b. de
[bijdragerichtlijnen](../CONTRIBUTING.md) en onze
[gedragscode](../CODE_OF_CONDUCT.md) voordat u een issue of pull request opent.

## Beveiliging

Om een beveiligingslek te melden, volg a.u.b. het
[beveiligingsbeleid](../SECURITY.md) — open geen openbare issue.

## Licentie

Dit project is gelicentieerd onder de [Apache License 2.0](../LICENSE).
