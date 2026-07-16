# Synthèse des labs 0 → 4

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

## Points d'honnêteté pour le rapport

**La signature keyless n'a pas été faite** (Lab 2.3). Elle exige une authentification OIDC
interactive dans un navigateur. Tout a été réalisé en mode **par clé**, ce qui couvre les labs 2
à 4. Le keyless relève du Lab 5 (OIDC du runner GitHub), où il est automatique.

**Le niveau SLSA réellement atteint est ~L1**, pas L2 : le build a été fait **à la main sur un
poste local**, et la provenance a été **rédigée manuellement** (`provenance.json`) — elle affirme
ce qu'on lui a dit d'affirmer. Rien n'empêche de mentir dedans. Le passage à L2 suppose un build
sur plateforme hébergée avec provenance générée par le runner (Lab 5).

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
| `cosign.pub` | Clé publique de vérification |
