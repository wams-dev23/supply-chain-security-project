# Synthèse des labs 0 → 5

Chaîne réalisée de bout en bout, en local (Docker + kind + Kyverno), avec GHCR comme registry.

- **Fork** : `wams-dev23/supply-chain-security-project` (upstream : `aubinaso/…`)
- **Image** : `ghcr.io/wams-dev23/scs-demo-app` (package public)
- **Digest signé** : `sha256:4e4ef40c84943171fe11ebddd39e3fe9710b9a206f60f775d91e3e1c8aef9076`
- **Cluster** : kind `scs` (1 control-plane + 1 worker), Kyverno v1.18.2
- **Signature** : cosign v2.5.3, mode par clé (`cosign.pub` versionné, `cosign.key` jamais commité)

## Résultats par lab

| Lab | Résultat |
|---|---|
| 0 — Environnement & image | Outils OK, image build, `/health` → `{"status":"ok","version":"1.0.0"}`, poussée sur GHCR, digest récupéré |
| 1 — SBOM & scan | SBOM SPDX + CycloneDX (113 paquets), scan Grype, gate `--fail-on` cassée puis image saine rétablie |
| 2 — Signature & attestations | Image signée par digest, attestations SBOM + provenance SLSA attachées et vérifiées, `cosign tree` montre `.sig` + `.att` |
| 3 — Cluster & admission | 4 ClusterPolicy `Ready` en `Enforce`, image conforme **acceptée**, 2 pods `Running`, app joignable |
| 4 — Attaque / Défense | Les 5 attaques **bloquées**, cas nominal intact |
| 5 — CI de bout en bout | Workflow vert, image signée **keyless** par l'OIDC du runner, acceptée par le cluster ; toute image non signée par ce workflow refusée |

## Tableau attaque → contrôle → menace

| Attaque | Résultat | Policy qui bloque | Menace réelle |
|---|---|---|---|
| 1 — Image jamais signée | ❌ Refusée | `verify-image-signature` | Déploiement d'artefact non autorisé |
| 2 — Image modifiée après signature | ❌ Refusée | `verify-image-signature` (signature liée au digest) | **SolarWinds** — build/artefact altéré |
| 3 — Registry non autorisé (`nginx`) | ❌ Refusée | `allowed-registries` | Typosquatting / registry pirate |
| 4 — Tag `:latest` | ❌ Refusée *(après correction, voir plus bas)* | `disallow-latest-tag` | Substitution sous tag mutable |
| 5 — Signée mais sans provenance | ❌ Refusée | `require-provenance-attestation` | Absence de traçabilité d'origine |

Preuve la plus parlante pour l'attaque 2 : le digest passe de `4e4ef40c…` à `2d4d348d…` dès l'ajout
d'un `RUN echo "backdoor"`. Aucune signature n'existe pour ce nouveau digest → refus.

## Écarts constatés par rapport au sujet

Cinq points où le dépôt fourni ou l'énoncé ne fonctionnent pas tels quels.

### 1. La policy `02-disallow-latest` était contournable (faille réelle)

Le motif fourni était `image: "!*:latest"`. Or `verifyImages` (policies 03/04) utilise
`mutateDigest: true`, qui réécrit l'image en `repo:latest@sha256:…` dans le webhook de
**mutation**, c'est-à-dire **avant** les règles de **validation**. La chaîne ne se terminant plus
par `:latest`, le motif ne matchait plus : **un `:latest` signé était admis** (vérifié, cf.
`lab4-faille-latest-contourne.txt`).

Correction appliquée : motif `!*:latest*`. L'attaque 4 est ensuite bien refusée par
`disallow-latest-tag`, sans régression sur le cas nominal.

C'est l'illustration exacte du piège du Lab 3.5 : une policy peut être `Ready` et en `Enforce`
tout en ne protégeant de rien. Seul le test d'attaque le révèle.

### 2. L'attestation SBOM SPDX dépasse la limite de Kyverno

Le SBOM SPDX de l'image fait 2,3 Mo, or Kyverno plafonne son contexte à 2 Mio (limite **codée en
dur**, aucun flag ne la règle). La policy 04, qui charge les attestations, échouait avec
`context size limit exceeded: 2311332 bytes exceeds limit of 2097152 bytes` — refusant l'image
légitime pour une raison purement technique.

Choix retenu : attacher le SBOM au format **CycloneDX** (1,3 Mo, sous la limite) et conserver le
SPDX comme livrable fichier. Les deux formats sont générés au Lab 1, et CycloneDX est un standard
SBOM au même titre que SPDX.

À savoir aussi : `cosign attest` **ajoute** une couche au manifeste `.att` au lieu de le
remplacer. Réattester ne suffit donc pas à retirer une attestation trop grosse — il faut
supprimer le `.att` (scope `delete:packages`) ou repartir d'un nouveau digest.

### 3. `runAsNonRoot` incompatible avec le Dockerfile fourni

Le Dockerfile fait `USER appuser` (nom), le deployment exige `runAsNonRoot: true`. Le kubelet ne
sait pas vérifier qu'un nom d'utilisateur est non-root → `CreateContainerConfigError`.
Correction : `runAsUser: 10001` ajouté au `securityContext` (uid créé dans le Dockerfile).

### 4. `readOnlyRootFilesystem` empêche gunicorn de démarrer

gunicorn écrit ses fichiers de worker via `tempfile` → `FileNotFoundError: No usable temporary
directory found`. Correction : `emptyDir` monté sur `/tmp`, ce qui conserve le durcissement.

### 5. La démo de gate du Lab 1.4 n'est pas discriminante

Le lab propose `grype --only-fixed --fail-on high` sur l'image vulnérable. Mais l'image **saine**
contient déjà **8 vulnérabilités High corrigeables** héritées de `python:3.12-slim` : au seuil
`high`, les deux images cassent la chaîne. La preuve réellement discriminante est la vulnérabilité
`GHSA-m2qf-hxjv-5gpq` (High, Flask 2.0.1), absente de l'image saine. Avec le seuil `critical` du
`.grype.yaml` fourni, l'image saine passe bien (code 0).

## Lab 5 — CI de bout en bout

- **Image CI** : `ghcr.io/wams-dev23/scs-demo-app-ci`
- **Digest signé keyless** : `sha256:2b9cbacb3c8676f51557d89e057343dc31aefd3577876b4d0e0f63771681d2fb`
- **Identité signataire** : `https://github.com/wams-dev23/supply-chain-security-project/.github/workflows/supply-chain.yml@refs/heads/main`
- **Issuer OIDC** : `https://token.actions.githubusercontent.com`

Aucune clé privée n'existe côté CI : l'identité est celle du workflow, attestée par Fulcio et
journalisée dans Rekor. Les policies `05-verify-signature-keyless` et `06-require-provenance-keyless`
exigent cette identité exacte, sur cette branche exacte.

**Le contre-test est la démonstration la plus parlante du projet** : une image poussée à la main sur
le dépôt CI et signée avec **notre propre clé cosign valide** est **refusée**
(`lab5-contretest-fausse-image-ci.txt`). Posséder une clé de signature ne suffit pas — il faut être
le workflow. C'est ce qu'un attaquant ne peut pas falsifier : il n'a pas l'OIDC du runner GitHub.

Note de conception : les policies 03/04 (par clé) ont dû être restreintes à
`ghcr.io/wams-dev23/scs-demo-app:*` et `…@*`. Le motif d'origine `scs-demo-app*` matchait aussi
`scs-demo-app-ci`, et les deux modes se seraient mutuellement rejetés.

### Écarts supplémentaires rencontrés au Lab 5

**La gate Grype de la CI ne scannait rien.** `anchore/scan-action@v4` épingle Grype v0.80.0, dont la
base de vulnérabilités n'est plus alimentée : Grype refuse de la charger (`the vulnerability
database was built 18 weeks ago (max allowed age is 5 days)`) et l'action traduit ce plantage en
« vulnérabilités critiques trouvées ». La gate cassait donc **sur une base morte, pas sur une CVE** —
un faux positif permanent, aussi trompeur qu'un faux négatif. Corrigé en installant Grype
directement, comme au Lab 1.

**Actions est désactivé par défaut sur un fork** : le premier `git push` n'a déclenché aucun run.

**Un package GHCR créé par un push manuel reste orphelin** (rattaché à aucun dépôt), et le
`GITHUB_TOKEN` du workflow n'a alors aucun droit d'écriture dessus
(`permission_denied: write_package`). Le rattachement ne se fait qu'au premier push venant du dépôt
lui-même — d'où l'impasse pour `scs-demo-app`, poussé à la main aux labs 0-2. D'où le package CI
dédié `scs-demo-app-ci`, créé et rattaché automatiquement par le workflow.

**cosign a dû être épinglé en v2.5.3 dans le workflow** (`cosign-installer` installe la v3 par
défaut), pour la même raison qu'en local : la v3 n'écrit plus les tags `.sig`/`.att`.

**L'attestation SBOM du workflow a été passée en CycloneDX**, le SPDX dépassant la limite de
contexte de Kyverno.

## Points d'honnêteté pour le rapport

**La signature keyless en local n'a pas été faite** (Lab 2.3) : elle exige une authentification
OIDC interactive dans un navigateur. Les labs 2 à 4 sont donc en mode **par clé**. Le keyless a
bien été réalisé au Lab 5, via l'OIDC du runner, où il est automatique — c'est son usage réel.

**Deux niveaux SLSA coexistent dans ce rendu, et il faut le dire clairement.**

L'image des labs 0-4 (`scs-demo-app`) est **~L1** : build **à la main sur un poste local**, et
provenance **rédigée manuellement** (`provenance.json`) — elle affirme ce qu'on lui a dit
d'affirmer. Rien n'empêche de mentir dedans : c'est une signature authentique sur une déclaration
invérifiable.

L'image du Lab 5 (`scs-demo-app-ci`) est **~L2** : build sur plateforme hébergée (GitHub Actions),
provenance générée par le workflow et signée par l'identité OIDC du runner, non falsifiable par
quelqu'un qui n'est pas ce workflow.

Ce qui manque pour **L3** : la provenance est produite par le workflow lui-même, pas par un
générateur isolé (`slsa-github-generator`). Un mainteneur ayant les droits d'écriture peut modifier
`supply-chain.yml` et lui faire signer n'importe quoi, en conservant une identité valide. La
falsifiabilité par un initié reste entière.

**Deux écarts d'outillage** par rapport à l'énoncé, imposés par les versions actuelles :
cosign **v3** stocke signatures et attestations via l'API OCI referrers (tag de repli
`sha256-<digest>`) et ne crée plus les tags `.sig`/`.att` attendus par Kyverno et décrits au Lab
2.6 → **cosign v2.5.3** utilisé. Kyverno a par ailleurs été lancé avec `--allowInsecureRegistry`
lors de la phase registre local ; ce flag est inutile sur GHCR (HTTPS) et devrait être retiré.

## Fichiers de preuve

| Fichier | Contenu |
|---|---|
| `lab1-gate-cassee.txt` / `-resume.txt` | Scan Grype de l'image Flask 2.0.1, code de sortie 2 |
| `lab2-cosign-tree.txt` | Signature + attestations attachées au digest |
| `lab3-nominal-accepte.txt` | Pods `Running` + 4 policies `Ready` |
| `lab4-attaque1-non-signee.txt` | Refus : image jamais signée |
| `lab4-attaque2-modifiee.txt` | Refus : image backdoorée après signature |
| `lab4-attaque3-registry.txt` | Refus : registry non autorisé |
| `lab4-attaque4-latest.txt` | Refus : tag `:latest` (après correction du motif) |
| `lab4-attaque5-sans-provenance.txt` | Refus : signée mais sans provenance |
| `lab4-faille-latest-contourne.txt` | Preuve du contournement avant correction |
| `lab5-keyless-verify.txt` | `cosign verify` keyless réussi avec l'identité du workflow |
| `lab5-ci-image-acceptee.txt` | Image CI admise par le cluster + les 6 policies |
| `lab5-contretest-fausse-image-ci.txt` | Refus : image signée avec notre clé mais pas par le workflow |
| `cosign.pub` | Clé publique de vérification |
