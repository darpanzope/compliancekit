# v0.5 launch playbook

The internal checklist for shipping compliancekit publicly. Once the
launch sequence is complete and the post-mortem is captured this file
becomes a historical reference; leave it in-tree for the v0.7 / v0.8
launches that follow the same pattern at smaller scale.

Audience: Darpan + future-Claude collaborating on the day.

---

## 1. Pre-flight (do these before tagging)

A green ✔ next to each line below means it has been verified, not just
attempted. Trust nothing that has not been clicked through end-to-end.

### Repo / GitHub

- [ ] **Rotate `ghp_6oza...`** at https://github.com/settings/tokens.
      It was in chat history across two sessions. Treat as compromised.
- [ ] Create the **Homebrew tap repo**: `darpanzope/homebrew-tap` (public).
      Add a placeholder `Formula/.keep` so it is not an empty repo.
- [ ] Create the **Action repo**: `darpanzope/compliancekit-action` (public).
      Push the contents of `action/` from this repo as the initial commit.
      Tag `v1.0.0`; create the floating major-version tag `v1` pointing at it.
- [ ] Create the **fine-grained PAT** for the release pipeline:
      *Settings → Developer settings → Personal access tokens → Fine-grained → New.*
      Scope: `darpanzope/homebrew-tap` only, `Contents: read+write`.
      Save the token; add as **repo secret `HOMEBREW_TAP_GITHUB_TOKEN`** on `darpanzope/compliancekit`.
- [ ] In `darpanzope/compliancekit` repo settings, **enable GitHub Discussions**.
      The post-launch FAQ thread lives there.
- [ ] Verify the repo is **still private**. The launch sequence flips it.

### Asciinema

- [ ] Record a 60-90s demo with `scripts/asciinema.sh` (create the script
      if it doesn't exist — three commands: `compliancekit doctor`,
      `compliancekit scan --output json,html`, `compliancekit evidence ...`).
- [ ] Upload to https://asciinema.org/ under the project account.
      Capture the cast ID.
- [ ] Replace the placeholder block at the top of README.md with the
      cast's SVG embed.

### Reproducibility

- [ ] Run `goreleaser release --snapshot --clean --skip=publish,sign,homebrew,docker`
      locally. Confirm `dist/` contains four tarballs + checksums.txt +
      SBOMs. This catches goreleaser config regressions before the real
      release.
- [ ] On a fresh Linux VM (or container), test
      `curl ... install.sh | sh` against the snapshot once a release exists.
      Repeat on macOS arm64.
- [ ] Smoke `docker run --rm ghcr.io/darpanzope/compliancekit:<version> doctor`
      against the staged image.

### Docs final pass

- [ ] README hero block: install commands actually work.
- [ ] CLI.md examples still match the binary (`compliancekit checks list`
      etc.). Run them.
- [ ] CONFIGURATION.md schema matches `internal/config/config.go`.
- [ ] CHECKS.md (developer-facing) is consistent with how checks land
      now that the registry stores metadata.
- [ ] docs/checks.md is regenerated against the v0.5 binary (CI gate
      already enforces this, but verify on a fresh clone).

---

## 2. Release day, in order

The order matters: the binary release publishes the artifacts the
Homebrew formula and the Action both download.

### T-0: tag and release

```sh
# From the main branch, fully clean working tree, all commits up.
git tag -a v0.5.0 -m "v0.5.0 -- Public launch"
git push origin main
git push origin v0.5.0
```

The `release` workflow fires. It takes ~6-10 minutes. Watch it in the
Actions tab.

### T+10 min: verify the artifacts

- [ ] GitHub Release page at `https://github.com/darpanzope/compliancekit/releases/tag/v0.5.0`
      lists 4 tar.gz archives, checksums.txt, checksums.txt.sig,
      checksums.txt.pem, 4 .sbom.json files.
- [ ] `docker pull ghcr.io/darpanzope/compliancekit:v0.5.0` succeeds.
- [ ] `docker inspect ghcr.io/darpanzope/compliancekit:v0.5.0 \
      --format='{{ index .Config.Labels "org.opencontainers.image.version" }}'`
      prints `v0.5.0`.
- [ ] The Homebrew tap repo has a new commit landing
      `Formula/compliancekit.rb`.
- [ ] On a fresh Mac, `brew install darpanzope/tap/compliancekit && \
      compliancekit version` works.
- [ ] On Linux, `curl -sSfL .../install.sh | sh` works.
- [ ] `cosign verify-blob ...` succeeds against checksums.txt (recipe in
      README); test the recipe verbatim so a reader following it does the
      same thing.

### T+20 min: copy the Action

The `action/` source in the main repo now matches v0.5.0; copy it to
the dedicated repo:

```sh
git -C ../compliancekit-action rm -r .       # if reusing the repo
cp -R action/* ../compliancekit-action/
( cd ../compliancekit-action \
    && git add -A \
    && git commit -m "compliancekit-action: v0.5 source" \
    && git tag -a v1.0.0 -m "v1.0.0 (compliancekit v0.5.0)" \
    && git tag -f v1 \
    && git push --force origin main v1.0.0 v1 )
```

- [ ] In a private sandbox repo, run a workflow that uses
      `darpanzope/compliancekit-action@v1`. Confirm it installs
      v0.5.0 and uploads SARIF.

### T+30 min: flip the repo public

*Settings → General → Danger Zone → Change repository visibility → Public.*

- [ ] Re-add the **GitHub Sponsors** button on the repo home (was hidden
      while private).
- [ ] Re-enable **Discussions** if disabled.
- [ ] Pin the v0.5.0 release as the **release page**.

---

## 3. Broadcast (after the repo is public, in this order)

Stagger the posts. HN first because the front-page window is hours;
Reddit and lobste.rs scrape HN for trending links, so a few minutes'
head start matters. LinkedIn last because that's the audience that
believes "if it's been on HN already it must be real."

### Hacker News (T+0)

URL: https://news.ycombinator.com/submit

**Title:**

> Show HN: Compliancekit – SOC 2 evidence packs for DigitalOcean and Linux

**URL:** `https://github.com/darpanzope/compliancekit`

**First comment (post within 60 seconds of submitting, otherwise the
comment is harder to anchor at the top):**

> Hi HN — I built compliancekit because every compliance scanner I
> wanted to use (Prowler, ScoutSuite, Steampipe) targets enterprise
> security teams on AWS / GCP / Azure, and the indie SaaS reality is
> ten droplets on DigitalOcean and a SOC 2 auditor a customer dragged
> in.
>
> The differentiator versus the existing tools is the output. They
> emit JSON. compliancekit emits a folder an auditor will accept: per
> control, per framework, with a `MANIFEST.sha256` for tamper
> evidence and a `control-mapping.csv` that imports straight into
> Drata, Vanta, and AuditBoard.
>
> v0.5 ships:
> - 20 checks across DigitalOcean and Linux (15 of those are CIS
>   Ubuntu/Debian aligned)
> - Three frameworks bundled: SOC 2 TSC, ISO 27001:2022 Annex A,
>   CIS Controls v8
> - Five output formats including SARIF (so it feeds Code Scanning)
>   and a self-contained HTML dashboard
> - One static binary, cosign-signed releases via GitHub OIDC,
>   per-archive SBOM
> - A GitHub Action so dropping it into CI is ~10 lines of YAML
>
> Roadmap: Hetzner at v0.7, K8s at v0.8, AWS / GCP / etc at v1.7.
> serve mode (continuous monitoring without the SaaS bill) at v1.1.
>
> MIT licence. Happy to answer anything.

### lobste.rs (T+5 min)

Submit as a Show post. Same URL. Tag: `programming, security, devops`.

Short description:

> Open-source compliance scanner that emits an audit-ready folder
> (not JSON) for SOC 2 / ISO 27001 / CIS Controls v8. Targets
> DigitalOcean and Linux fleets; Prowler-shaped for the indie SaaS
> audience.

### Reddit (T+15 min, in this subreddit order)

Different framings per subreddit. The "Prowler for the people Prowler
forgot" line lands well on `/r/devops`; less well elsewhere.

**`r/devops`** – Show post
Title: *I built an open-source SOC 2 / ISO 27001 evidence-pack generator
for DigitalOcean and Linux*
Body: HN-style intro plus the demo gif.

**`r/sysadmin`** – Tool post
Title: *compliancekit: agentless Linux hardening scanner with CIS
mappings, single binary*
Body: focus on the Linux side (15 checks, SSH-only, no agent, CIS
benchmark alignment).

**`r/cybersecurity`** – Self post
Title: *Open-source compliance scanner that produces auditor-ready
evidence packs (DigitalOcean + Linux at v0.5; AWS / GCP / K8s on the
roadmap)*
Body: emphasise the supply chain (cosign keyless, SBOM, distroless
Docker image).

**`r/digitalocean`** – Show post
Title: *compliancekit: scan your droplets for SOC 2 / ISO 27001 / CIS
hardening, one binary*
Body: focus on the DO side (5 checks today, more coming).

**`r/SaaS`** – Show post
Title: *Built this for indie SaaS founders dealing with their first
SOC 2: open-source evidence-pack generator*
Body: the auditor-pain angle, not the security-engineering angle.
Mention "your auditor wants Drata or Vanta? control-mapping.csv
imports cleanly into both."

### tldr.sec (T+1 hour)

Submit via https://tldrsec.com/submit (or the editor's known email).

Short pitch: *Open-source compliance scanner for DigitalOcean + Linux
that emits Drata/Vanta-importable evidence packs. v0.5 ships SOC 2,
ISO 27001:2022, CIS v8 mappings; cosign-signed releases with SBOM.*

### DigitalOcean community tutorials team (T+1 hour)

Email community@digitalocean.com:

> Subject: open-source compliance scanner for DigitalOcean — would
> your tutorials team be interested?
>
> Hi — I just open-sourced compliancekit, a single-binary compliance
> scanner that has first-class DigitalOcean support (droplet
> inventory, firewall analysis, backup posture, etc.) plus SOC 2 / ISO
> 27001 / CIS Controls v8 mappings on every finding. v0.5 just
> launched on HN. The whole thing is MIT-licensed and I would be
> happy to draft a tutorial article for the community site walking
> through a SOC 2-readiness scan on a typical droplet fleet.
>
> Repo: https://github.com/darpanzope/compliancekit
> HN: <link to thread>
> Demo: <link to asciinema>
>
> Cheers,
> Darpan

### LinkedIn + Twitter (T+2 hours)

Re-share the HN URL when it has stabilised on the front page (or
hasn't, depending). LinkedIn copy:

> Open-sourced compliancekit today. It's an SOC 2 / ISO 27001 / CIS
> Controls v8 scanner for the audience the existing tools forgot:
> indie SaaS teams on DigitalOcean, Hetzner, and a Linux fleet.
>
> The thing that took longest wasn't the checks — it was the output.
> Auditors don't want JSON. They want a folder, organised by
> framework, with one Markdown file per control, a CSV that imports
> into Drata, and a SHA-256 manifest. That's the v0.4 evidence pack
> and it's the part I'm most excited about.
>
> MIT licence, single static binary, GitHub Action for CI. Roadmap
> goes through K8s at v0.8 and AWS at v1.7.
>
> github.com/darpanzope/compliancekit

Twitter / X: shortened version, same link, no emojis.

---

## 4. Post-launch (T+1 day)

- [ ] Reply to **every** top-level HN comment within 24h. The thread
      momentum dies the moment people stop seeing fresh replies.
- [ ] Open the first batch of **roadmap issues**: each milestone in
      `ROADMAP.md` from v0.6 onwards as a tracking issue, linked to
      the roadmap section.
- [ ] Pin a **"v0.5 launch: ask anything"** discussion at
      `darpanzope/compliancekit/discussions/1`.
- [ ] Capture launch metrics for next time:
      - GitHub stars at T+24h, T+72h, T+7d
      - HN points + comment count
      - Reddit upvotes per subreddit
      - Homebrew tap installs (from the formula's analytics)
      - Docker pulls (from GHCR)
      - Action runs (from the Action's usage page)

---

## 5. Rollback plan

If something is wrong with v0.5.0 (panic at install, broken cosign
signature, regression in the evidence pack):

```sh
# 1. Mark the release as a draft so installers fall back to v0.4.x:
gh release edit v0.5.0 --draft

# 2. Pull the Docker tag (latest first so curl-installers don't grab it):
gh api -X DELETE /user/packages/container/compliancekit/versions/<id>

# 3. Revert the Homebrew formula by force-pushing the tap to the
#    previous commit (the tap is small, force-push is acceptable).

# 4. Drop a clear "v0.5.0 has been retracted -- patched release coming"
#    comment on every active broadcast thread (HN, Reddit, etc).

# 5. Cut v0.5.1 once fixed. Do not re-use the v0.5.0 tag.
```

Do not delete the GitHub Release outright. Marking it as a draft
preserves the audit trail (installers and CI runs that already ran
against it still have something to reference) while preventing new
traffic.
