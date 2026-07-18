<p align="center">
  <img src="logo.svg" alt="Logo OptimCE" width="160">
</p>

# kc-groupid-mapper

> Mappeur de protocole OIDC Keycloak qui transforme l'appartenance aux groupes en une revendication de jeton `orgs` avec les rôles.

[![Site web](https://img.shields.io/badge/Site%20web-optimce.be-2e7d32.svg)](https://www.optimce.be/fr/)
[![Licence](https://img.shields.io/badge/Licence-Apache%202.0-blue.svg)](../LICENSE)
[![Keycloak](https://img.shields.io/badge/Keycloak-26.5.1-blue.svg)](https://www.keycloak.org/)
[![en](https://img.shields.io/badge/lang-en-lightgrey.svg)](../README.md)
[![fr](https://img.shields.io/badge/lang-fr-43a047.svg)](README.fr.md)
[![de](https://img.shields.io/badge/lang-de-lightgrey.svg)](README.de.md)
[![nl](https://img.shields.io/badge/lang-nl-lightgrey.svg)](README.nl.md)

`kc-groupid-mapper` est un mappeur de protocole OIDC
[Keycloak](https://www.keycloak.org/) personnalisé. Il lit l'appartenance d'un
utilisateur aux groupes et ajoute à ses jetons une revendication décrivant les
**organisations** auxquelles il appartient ainsi que ses **rôles** dans chacune
d'elles — le tout dérivé de l'arborescence des groupes, sans modèle de données
supplémentaire.

Il fait partie de la plateforme [OptimCE](https://www.optimce.be/fr/), où il
permet aux services en aval d'autoriser les requêtes par communauté d'énergie à
partir du seul jeton d'accès. Il est développé dans le
[monorepo OptimCE](https://github.com/OptimCE/monorepo) et publié ici en tant
que provider autonome.

## Ce qu'il fait

Le mappeur parcourt chacun des groupes de l'utilisateur et recherche des groupes
d'organisation sous un **chemin racine** configurable. La structure de groupes
attendue est la suivante :

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

Pour chaque organisation à laquelle l'utilisateur appartient, il émet une entrée
contenant l'identifiant du groupe (`orgId`), le chemin du groupe (`orgPath`) et
l'ensemble des rôles collectés depuis les sous-groupes `roles/`. Un utilisateur
membre de `/orgs/acme/roles/ADMIN`, `/orgs/acme/roles/BILLING` et
`/orgs/globex/roles/VIEWER` obtient :

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

Le nom de la revendication (`orgs` ci-dessus) est configurable, et la
revendication peut être ajoutée au jeton d'accès, au jeton d'identité, à la
réponse UserInfo et à l'introspection de jeton.

### Mode des rôles

La manière dont les rôles sont extraits des sous-groupes d'une organisation
dépend de l'option `rolesMode` :

- **`strict`** (par défaut) — seuls les groupes sous `roles/` comptent,
  c.-à-d. `/orgs/<org>/roles/<ROLE>`.
- **`loose`** — `/orgs/<org>/roles/<ROLE>` et le raccourci
  `/orgs/<org>/<ROLE>` comptent tous les deux.

## Configuration

Une fois le provider déployé, ajoutez le mappeur **Organizations (id/path) with
roles** (id de provider `oidc-orgs-with-roles-mapper`) à un client ou à un
client scope, puis configurez :

| Option | Clé de configuration | Valeur par défaut | Description |
|---|---|---|---|
| Claim name | `claimName` | *(vide)* | Nom de la revendication JWT qui contient le tableau organisations-avec-rôles. |
| Orgs root group path | `orgsRootPath` | `/` | Chemin de groupe dont les enfants directs sont des organisations, p. ex. `/orgs`. `/` signifie que les groupes de premier niveau sont des organisations. |
| Roles mode | `rolesMode` | `strict` | `strict` n'accepte que `/orgs/<org>/roles/<ROLE>` ; `loose` accepte aussi `/orgs/<org>/<ROLE>`. |

Les bascules standard d'inclusion dans les jetons OIDC (ajout au jeton
d'identité, au jeton d'accès, au jeton d'accès allégé, à UserInfo et à
l'introspection de jeton) sont également disponibles.

## Compilation

Nécessite **JDK 17** et **Maven**.

```bash
mvn -B package
```

Cela produit le JAR du provider dans `target/kc-groupid-mapper-1.0.0.jar`. Des
JAR précompilés sont également attachés à chaque
[release GitHub](https://github.com/OptimCE/kc-groupid-mapper/releases).

## Utilisation dans Keycloak

Le provider cible **Keycloak 26.5.1**.

1. Copiez le JAR dans le répertoire des providers de Keycloak :

   ```bash
   cp target/kc-groupid-mapper-1.0.0.jar /opt/keycloak/providers/
   ```

2. Reconstruisez Keycloak pour qu'il prenne en compte le nouveau provider :

   ```bash
   /opt/keycloak/bin/kc.sh build
   ```

3. Dans la console d'administration, ajoutez le mappeur **Organizations
   (id/path) with roles** à un client ou à un client scope et définissez les
   options ci-dessus.

Pour l'intégrer à une image Keycloak, le [`Dockerfile`](../Dockerfile) fourni
compile le JAR et l'installe en une seule construction multi-étapes :

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

## Comment OptimCE l'utilise

Dans le realm OptimCE, le mappeur est attaché à un client scope dédié avec le
nom de revendication `orgs` et `rolesMode` réglé sur `loose`, de sorte que
chaque jeton émis porte les communautés de l'appelant et leurs rôles. Consultez
la configuration du realm Keycloak dans le
[monorepo](https://github.com/OptimCE/monorepo) pour l'installation complète.

## Contribuer

Les contributions sont les bienvenues ! Merci de lire les
[directives de contribution](../CONTRIBUTING.md) et notre
[Code de conduite](../CODE_OF_CONDUCT.md) avant d'ouvrir une issue ou une pull
request.

## Sécurité

Pour signaler une vulnérabilité de sécurité, veuillez suivre la
[politique de sécurité](../SECURITY.md) — n'ouvrez pas d'issue publique.

## Licence

Ce projet est sous licence [Apache License 2.0](../LICENSE).
