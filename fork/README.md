# About This Fork

`benheise/Ghostwriter` follows [GhostManager/Ghostwriter](https://github.com/GhostManager/Ghostwriter) releases and adds
the changes listed below. SpecterOps and the Ghostwriter maintainers do not support or review this fork. Report problems
with these changes on this fork, not upstream.

Every change ships two ways:

* **This repository.** `master` is the latest upstream release with the fork's commits on top.
* **Patch files** for people who run upstream Ghostwriter. Each [release](https://github.com/benheise/Ghostwriter/releases)
  of the fork has a patch set for the matching upstream version.

## Changes

| Change | Patch | Summary |
|--------|-------|---------|
| Default template and export fixes | `0001` | Blank severity under each finding in the default Word template, default download filenames missing the project type, Word footnote styles not being applied (and the related export failure), and the PowerPoint notes title |
| CVE IDs on findings | `0002` | A validated `cves` list on library and report findings. It is copied with findings, edited in the collaborative forms, and available as `finding.cves` in templates. It also appears in the JSON and Excel reports, CSV imports and exports, GraphQL, and the findings library filters. The `extract_cves` command fills it from text already in findings |

Planned: a local copy of the CISA KEV catalogue and FIRST EPSS scores, refreshed on a configurable schedule, with KEV
and EPSS values for each finding's CVEs in the report data.

The [CHANGELOG](../CHANGELOG.md) lists every change under its release.

## Applying the Patches to Upstream Ghostwriter

The patches change Python code, the database schema, the GraphQL metadata, and the browser code. The pre-built images
that Ghostwriter CLI installs by default cannot pick up these changes, so you must build the images from your patched
source.

1. **Back up first.** Run `./ghostwriter-cli backup` (or your usual database backup) and keep a copy of your `.env`.
2. **Check out the matching upstream release.** A patch set only applies to the upstream version it names:

   ```bash
   git clone https://github.com/GhostManager/Ghostwriter.git
   cd Ghostwriter
   git checkout v7.3.5
   ```

   If you already run Ghostwriter from a clone, use that directory and confirm `cat VERSION` matches the patch set.
3. **Apply the patches.** Download the patch files from the matching fork release. Apply them in order, either all of
   them or `0001` alone:

   ```bash
   git am --3way /path/to/patches/*.patch
   ```

   `git am` keeps each change as its own commit. If you don't want commits, `git apply --check` and then `git apply`
   each file in order. These also work in an extracted release archive that isn't a git checkout. The template fix
   modifies binary `.docx` files, so plain `patch` cannot apply `0001`. Use git.

   Each release also has a single combined patch (`ghostwriter-<version>-benheise.patch`) and a `SHA256SUMS` file.
   Check the download with `sha256sum -c SHA256SUMS`.
4. **Build and start Ghostwriter from the patched source.** `production.yml` builds every image from the checkout:

   ```bash
   docker compose -p ghostwriter_sys -f production.yml build
   docker compose -p ghostwriter_sys -f production.yml up -d
   ```

   `-p ghostwriter_sys` keeps the project name that Ghostwriter CLI uses, so the containers reuse your existing database
   and media volumes. Without it, Compose names the project after the directory and starts with empty volumes. Run
   these commands in the directory that holds your `.env`. Django applies the new database migrations when it starts.
5. **Optional: fill CVE IDs from existing findings.** Preview, then apply:

   ```bash
   docker compose -p ghostwriter_sys -f production.yml run --rm django python manage.py extract_cves --dry-run
   docker compose -p ghostwriter_sys -f production.yml run --rm django python manage.py extract_cves
   ```

After this, use `docker compose -p ghostwriter_sys -f production.yml` for container commands. `./ghostwriter-cli containers up`
and `./ghostwriter-cli update` start the unpatched pre-built images again.

### Upgrading Upstream Later

Before you upgrade to a new upstream release, download the fork's patch set for that release. If the fork hasn't
published one yet, stay on your current version or remove the patches first. Then check out the new upstream tag,
apply the new patches, and rebuild as above.

### Removing the Patches

Run these while the patched code is still running, so the CVE columns are dropped cleanly:

```bash
docker compose -p ghostwriter_sys -f production.yml run --rm django python manage.py migrate reporting 0072
docker compose -p ghostwriter_sys -f production.yml run --rm django python manage.py migrate commandcenter 0054
```

Removing the CVE field deletes the stored CVE IDs. The second command only resets migration history. The corrected
filename templates stay in place, because the original value referred to a variable that does not exist. Then check
out the unpatched release and rebuild, or go back to the pre-built images with Ghostwriter CLI.

## Maintaining the Fork

`master` never gets force-pushed. For each upstream release:

1. Merge the release tag, with GhostManager/Ghostwriter as the `upstream` remote: `git fetch upstream --tags && git merge vX.Y.Z`. Resolve conflicts, keeping upstream's
   behaviour unless one of the fork's changes depends on it.
2. Run the checks the upstream CI runs: the Django test suite, `npm run check` in `javascript/`, and `npm run codegen`
   against a Hasura instance running the merged metadata, if the GraphQL schema changed.
3. Build the patch set: `fork/make-patches.sh vX.Y.Z`. It cherry-picks the fork's own commits onto a clean copy of the
   upstream tag, so a patch that no longer applies fails here rather than for users.
4. Tag `vX.Y.Z-benheise.N`, push the tag, and publish a release with the files from `fork/dist/vX.Y.Z/` and the
   apply steps above.

Commits that touch only `fork/` or this note in `README.md` stay out of the patches.
