# État des livrables

Point de situation au 16/07/2026. Ce document liste ce qui est attendu, ce qui existe, et où.

Référence : [`../docs/03-livrables-evaluation.md`](../docs/03-livrables-evaluation.md).

## Vue d'ensemble

| # | Livrable | Poids | État |
|---|---|---|---|
| **L1** | POC fonctionnel (le fork) | 35 % | ✅ **Fait** |
| **L2** | Rapport court (5-8 pages) | 25 % *(avec L3)* | ❌ **À écrire** |
| **L3** | Threat model (1-3 pages) | *(idem)* | ❌ **À écrire** |
| **L4** | Démo attaque/défense (captures) | *(compté dans L1)* | ✅ **Fait** — captures texte, pas de vidéo |
| **L5** | Soutenance | 20 % | — hors périmètre |
| **QCM** | QCM individuel | 20 % | — hors périmètre (le jour de l'épreuve) |

**Les labs 0 à 5 sont tous terminés.** Ils constituent le travail, pas les livrables : L2 et L3
restent à produire, et pèsent 25 % à eux deux.

---

## L1 — POC fonctionnel ✅

Fork : **`wams-dev23/supply-chain-security-project`** (`upstream` = `aubinaso/…`).

Ce que le dépôt contient, par lab :

| Lab | Livrable | Emplacement |
|---|---|---|
| 0 | Fork + image + digest | `ghcr.io/wams-dev23/scs-demo-app@sha256:4e4ef40c…` |
| 1 | SBOM SPDX + CycloneDX (113 paquets) | `sbom.spdx.json`, `sbom.cdx.json` — ⚠️ *ignorés par git, voir plus bas* |
| 1 | Preuve de la gate cassée | `preuves/lab1-gate-cassee.txt` + `-resume.txt` |
| 2 | Clé publique de vérification | `cosign.pub` |
| 2 | Provenance SLSA | `provenance.json` — ⚠️ *ignoré par git* |
| 2 | Signature + attestations attachées | `preuves/lab2-cosign-tree.txt` |
| 3 | Policies Kyverno (mode par clé) | `policies/kyverno/01` → `04` |
| 3 | Manifeste de déploiement par digest | `k8s/deployment.yaml` |
| 3 | Preuve du cas nominal accepté | `preuves/lab3-nominal-accepte.txt` |
| 4 | Preuves des 5 attaques bloquées | `preuves/lab4-attaque1` → `attaque5` |
| 4 | Preuve de la faille trouvée + corrigée | `preuves/lab4-faille-latest-contourne.txt` |
| 5 | Pipeline CI complet | `.github/workflows/supply-chain.yml` |
| 5 | Policies Kyverno (mode keyless) | `policies/kyverno/05`, `06` |
| 5 | Preuves keyless | `preuves/lab5-keyless-verify.txt`, `lab5-ci-image-acceptee.txt`, `lab5-contretest-fausse-image-ci.txt` |
| — | Synthèse technique + écarts constatés | `preuves/SYNTHESE.md` |

Deux images tournent dans le cluster, admises par 6 `ClusterPolicy` en `Enforce` :
`scs-demo-app` (signée par clé) et `scs-demo-app-ci` (signée keyless par le workflow).

## L4 — Démo attaque/défense ✅

Les 5 attaques du lab 4 sont bloquées, plus un contre-test au lab 5 :

| Attaque | Policy qui bloque | Preuve |
|---|---|---|
| Image jamais signée | `verify-image-signature` | `lab4-attaque1-non-signee.txt` |
| Image modifiée après signature | signature liée au digest | `lab4-attaque2-modifiee.txt` |
| Registry non autorisé | `allowed-registries` | `lab4-attaque3-registry.txt` |
| Tag `:latest` | `disallow-latest-tag` | `lab4-attaque4-latest.txt` |
| Signée sans provenance | `require-provenance-attestation` | `lab4-attaque5-sans-provenance.txt` |
| Signée avec notre clé mais pas par la CI | `*-keyless` | `lab5-contretest-fausse-image-ci.txt` |

⚠️ Ce sont des **captures texte**. Le sujet accepte « vidéo ou captures » — c'est donc conforme,
mais il n'y a pas de capture vidéo.

## L2 — Rapport ❌ à écrire

Template : [`TEMPLATE-rapport.md`](TEMPLATE-rapport.md). 5-8 pages attendues.
Noté sur la **rigueur, l'esprit critique et l'honnêteté sur les limites**.

La matière est déjà rassemblée dans `preuves/SYNTHESE.md` : elle contient les résultats par lab,
le tableau attaque → contrôle → menace, les 7 écarts constatés dans le sujet, et la discussion
SLSA. **Mais ce n'est pas le rapport** — il reste à structurer et rédiger.

## L3 — Threat model ❌ à écrire

Template : [`TEMPLATE-threat-model.md`](TEMPLATE-threat-model.md). 1-3 pages.
Attendu : attaques → contrôles → **couverture** (donc aussi ce qui *n'est pas* couvert).

---

## Checklist d'auto-évaluation du POC

Reprise de `docs/03-livrables-evaluation.md` §3, évaluée honnêtement.

- [x] Un SBOM (SPDX ou CycloneDX) est généré pour l'image
- [ ] ⚠️ Le scan casse le build sur une CVE **`CRITICAL` corrigeable** — **partiel**, voir ci-dessous
- [x] L'image est signée et `cosign verify` réussit avec notre identité
- [x] Une attestation SBOM est attachée et vérifiable
- [x] Une attestation de provenance SLSA est attachée et vérifiable
- [x] Le cluster accepte notre image signée et conforme
- [x] Le cluster refuse une image non signée
- [x] Le cluster refuse une image modifiée après signature
- [x] Le cluster refuse le tag `:latest` **et** un registry non autorisé
- [x] Reproductible : `kind create` + `kubectl apply` reconstruit la démo

### Le point à ne pas surjouer

Le critère demande que le scan casse sur une CVE **`CRITICAL`** corrigeable. **Nous n'en avons
jamais rencontré.** La démonstration casse sur une **`High`** (`GHSA-m2qf-hxjv-5gpq`, Flask 2.0.1),
et l'image saine passe le seuil `critical` du `.grype.yaml` (code 0).

Le mécanisme de gate est donc prouvé, mais pas sur une critique. À dire tel quel dans le rapport :
l'honnêteté sur les limites est explicitement au barème.

Nuance associée : l'image **saine** contient déjà **8 vulnérabilités `High` corrigeables** héritées
de `python:3.12-slim`. Au seuil `high`, les deux images cassent la chaîne — la démo du Lab 1.4
n'est donc pas discriminante en soi. La preuve qui l'est : `GHSA-m2qf-hxjv-5gpq`, absente de
l'image saine.

## Bonus du sujet (§4) déjà couverts

- ✅ Policy exigeant l'**attestation de provenance**, pas seulement la signature (`04`, `06`)
- ✅ Discussion **SLSA L2 vs L3** et ce qui reste contournable (`preuves/SYNTHESE.md`)
- ✅ **Signature keyless** OIDC avec rôle de Rekor (lab 5)
- ❌ Blocage sur **vulnérabilité à l'admission** (attestation de scan vérifiée par Kyverno)
- ❌ Comparaison argumentée **cosign/Sigstore vs Notation/Notary v2**

---

## Points ouverts à trancher

**Les SBOM et `provenance.json` ne sont pas dans le fork.** Le `.gitignore` du sujet exclut
`sbom*.json` et `provenance.json` comme « sorties de labs ». Or L1 demande « dépôt forké avec app,
**SBOM**, signature, attestations ». Deux options : les versionner (quitte à contredire le
`.gitignore` fourni), ou assumer qu'ils sont régénérables (`syft "$DIGEST" -o spdx-json`) et
surtout **attachés à l'image comme attestation signée**, ce qui est l'argument le plus solide.

**Le trigger `push` du workflow est inerte.** Tous les runs verts ont été lancés en
`workflow_dispatch`. GitHub désactive les workflows sur un fork et exige un clic dans l'onglet
**Actions** (« I understand my workflows, go ahead and enable them »), qu'aucune API n'expose.
À faire pour satisfaire le Lab 5.1.

**`cosign.key` n'est pas dans le dépôt** (vérifié sur tout l'historique) — c'est voulu. Mot de
passe : `labscs2026`. Sans lui, impossible de re-signer l'image des labs 0-4.

**Le cluster kind `scs` tourne toujours**, avec les 6 policies actives et les 2 images admises.
