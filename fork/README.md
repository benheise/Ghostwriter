# About This Fork

`benheise/Ghostwriter` follows [GhostManager/Ghostwriter](https://github.com/GhostManager/Ghostwriter) releases and adds
the changes listed below. SpecterOps and the Ghostwriter maintainers do not support or review this fork. Report problems
with these changes on this fork, not upstream.

Every change ships two ways:

* **This repository.** `master` is the latest upstream release with the fork's commits on top.
* **Patch files** for people who run upstream Ghostwriter, in [`fork/patches/`](patches/), one directory per upstream
  version.

## Changes

| Change | Patch | Summary |
|--------|-------|---------|
| Default template and export fixes | `0001` | Blank severity under each finding in the default Word template, default download filenames missing the project type, Word footnote styles not being applied (and the related export failure), and the PowerPoint notes title |
| CVE IDs on findings | `0002` | A validated `cves` list on library and report findings. It is copied with findings, edited in the collaborative forms, and available as `finding.cves` in templates. It also appears in the JSON and Excel reports, CSV imports and exports, GraphQL, and the findings library filters. The `extract_cves` command fills it from text already in findings |
| KEV and EPSS data | `0003` | A local copy of the CISA KEV catalog and FIRST EPSS scores, off by default. The new Vulnerability Intelligence Configuration page sets the update frequency (every 6 or 12 hours, daily, weekly, or manual) and run time, and manages the Django Q schedule. Downloads are checked so bad data never replaces good data. Includes offline import commands and read-only admin and GraphQL access. See `DOCS/configuring-global-settings/configuring-vulnerability-intelligence.mdx` |
| KEV and EPSS in reports and pages | `0004` | Each finding's KEV and EPSS data in report templates (`finding.kev`, `finding.epss_max`, a per-CVE `finding.vuln_intel` list and more), report-level "as of" dates and totals, five Excel columns, and KEV/EPSS badges on finding pages, the findings library and report findings tables. A new EPSS threshold setting highlights high scores |

Planned: freezing each finding's KEV and EPSS values when a report is marked complete, so a delivered report regenerates identically.

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
3. **Apply the patches.** Get the patch set for your version from this fork, check it, and apply the patches in order.
   You can apply all of them or `0001` alone:

   ```bash
   git clone --depth 1 https://github.com/benheise/Ghostwriter.git ../ghostwriter-fork
   (cd ../ghostwriter-fork/fork/patches/v7.3.5 && sha256sum -c SHA256SUMS)
   git am --3way ../ghostwriter-fork/fork/patches/v7.3.5/0*.patch
   ```

   `git am` keeps each change as its own commit. If you don't want commits, `git apply --check` and then `git apply`
   each file in order. These also work in an extracted release archive that isn't a git checkout. The template fix
   modifies binary `.docx` files, so plain `patch` cannot apply `0001`. Use git.

   Each version's directory also has a single combined patch (`ghostwriter-<version>-benheise.patch`) and the
   `SHA256SUMS` file used above.
4. **Bring over your configuration (Ghostwriter CLI installs only).** The CLI keeps your configuration outside any
   source tree, in its data directory (`~/.local/share/ghostwriter` on Linux). Copy it into the checkout, using `sudo`
   if the CLI ran as root:

   ```bash
   GW_DATA=~/.local/share/ghostwriter
   cp "$GW_DATA/.env" .
   cp -r "$GW_DATA/ssl" .
   cp "$GW_DATA"/settings/*.py config/settings/production.d/ 2>/dev/null || true
   ```

   If `$GW_DATA/nginx-ipv4.conf` exists, your host has no IPv6, so the CLI gave nginx an IPv4-only configuration.
   Copy that file into the checkout too. Then create `docker-compose.ipv4.yml` next to `production.yml`:

   ```yaml
   services:
     nginx:
       volumes:
         - ./nginx-ipv4.conf:/etc/nginx/nginx.conf:ro
   ```

   Add `-f docker-compose.ipv4.yml` after `-f production.yml` in every command below. Finally, stop the pre-built
   containers with `./ghostwriter-cli containers down`. Your volumes are kept.
5. **Build and start Ghostwriter from the patched source.** `production.yml` builds every image from the checkout:

   ```bash
   docker compose -p ghostwriter_sys -f production.yml build
   docker compose -p ghostwriter_sys -f production.yml up -d
   ```

   `-p ghostwriter_sys` keeps the project name that Ghostwriter CLI uses, so the containers reuse your existing database
   and media volumes. Without it, Compose names the project after the directory and starts with empty volumes. Django
   applies the new database migrations when it starts.
6. **Optional: fill CVE IDs from existing findings.** Preview, then apply:

   ```bash
   docker compose -p ghostwriter_sys -f production.yml run --rm django python manage.py extract_cves --dry-run
   docker compose -p ghostwriter_sys -f production.yml run --rm django python manage.py extract_cves
   ```

After this, use `docker compose -p ghostwriter_sys -f production.yml` for container commands. `./ghostwriter-cli containers up`
and `./ghostwriter-cli update` start the unpatched pre-built images again.

### Upgrading Upstream Later

Before you upgrade to a new upstream release, check `fork/patches/` for that release's patch set. If there isn't one
yet, stay on your current version or remove the patches first. Then check out the new upstream tag,
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

1. Merge the release tag, with GhostManager/Ghostwriter as the `upstream` remote:
   `git fetch upstream --tags && git merge --no-ff vX.Y.Z`. Resolve conflicts, keeping upstream's behaviour unless one
   of the fork's changes depends on it. If upstream added a migration to an app where the fork has its own, never
   rename either one: installs that applied the patches have recorded the fork's migration names. Add a merge
   migration instead (`python manage.py makemigrations --merge`) in a regular commit after the merge commit, so the
   patch set picks it up.
2. Run the checks upstream CI runs. They need only Docker, Node and Python:
   * `fork/run-tests.sh` checks for missing migrations, then runs the Django suite in the upstream images for the
     version in `VERSION`, with CI's environment.
   * `fork/codegen.sh` applies the migrations, starts Hasura with the merged metadata and confirms it is consistent,
     regenerates `javascript/src/__generated__`, and runs `npm run check` and the collaboration GraphQL authorization
     test. Commit any regenerated files.
3. Build the patch set: `fork/make-patches.sh vX.Y.Z`. It cherry-picks the fork's own commits onto a clean copy of the
   upstream tag, so a patch that no longer applies fails here rather than for users. If a commit no longer
   cherry-picks cleanly because the merge had to resolve a conflict in it, `fork/make-patches.sh --combined-only
   vX.Y.Z` publishes just the combined patch, taken from the merged tree.
4. Commit the new `fork/patches/vX.Y.Z/` directory with the merge and push `master`. Optionally, tag the commit
   `vX.Y.Z-benheise.N` and publish a GitHub release that links to the directory.

Commits that touch only `fork/` or this note in `README.md` stay out of the patches.

A daily scheduled task follows these steps whenever GhostManager publishes a release. If the merge needs a design
decision or the checks fail, it pushes the attempt to a `sync/vX.Y.Z` branch, leaves `master` alone, and reports what
needs attention.
