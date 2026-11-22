#!/usr/bin/env bash
# Build the fork's patch set for an upstream Ghostwriter release.
#
# Usage: fork/make-patches.sh <upstream-tag> [output-dir]
#
# Cherry-picks the fork's own commits (those on HEAD that are not merges and not in the upstream tag)
# onto a clean copy of the tag, then writes one numbered patch per commit, a combined patch, and
# SHA256SUMS. Changes to fork/ and README.md stay out of the patches. Fails if a commit no longer
# applies, so a broken patch is caught here rather than by users.
set -euo pipefail

tag="${1:?usage: fork/make-patches.sh <upstream-tag> [output-dir]}"
root="$(git rev-parse --show-toplevel)"
out="${2:-$root/fork/patches/$tag}"
base="$(git rev-parse --verify --quiet "$tag^{commit}")" || { echo "Unknown tag: $tag" >&2; exit 1; }
excludes=(":(exclude)fork" ":(exclude)README.md")

commits=()
while IFS= read -r commit; do
    # Skip commits that only touch fork/ or README.md
    if [ -n "$(git diff-tree --no-commit-id --name-only -r "$commit" -- . "${excludes[@]}")" ]; then
        commits+=("$commit")
    fi
done < <(git rev-list --reverse --no-merges "$base..HEAD")
[ "${#commits[@]}" -gt 0 ] || { echo "No fork commits on top of $tag" >&2; exit 1; }

work="$(mktemp -d)"
check="$(mktemp -d)"
cleanup() {
    for dir in "$work" "$check"; do
        git -C "$root" worktree remove --force "$dir" >/dev/null 2>&1 || rm -rf "$dir"
    done
}
trap cleanup EXIT
rmdir "$work"
git -C "$root" worktree add --quiet --detach "$work" "$base"

for commit in "${commits[@]}"; do
    if ! git -C "$work" cherry-pick --allow-empty "$commit" >/dev/null 2>&1; then
        echo "Commit $(git log -1 --format='%h %s' "$commit") does not apply cleanly to $tag" >&2
        git -C "$work" cherry-pick --abort >/dev/null 2>&1 || true
        exit 1
    fi
done

rm -rf "$out"
mkdir -p "$out"
version="${tag#v}"
git -C "$work" format-patch --quiet --binary --no-signature --zero-commit -o "$out" "$base..HEAD" -- . "${excludes[@]}"
git -C "$work" diff --binary "$base" HEAD -- . "${excludes[@]}" > "$out/ghostwriter-$version-benheise.patch"

# Prove the set applies to a clean copy of the tag, one by one and combined
rmdir "$check"
git -C "$root" worktree add --quiet --detach "$check" "$base"
git -C "$check" apply --check "$out/ghostwriter-$version-benheise.patch"
for patch in "$out"/0*.patch; do
    git -C "$check" apply --index "$patch"
done
expected="$(git -C "$work" diff --binary "$base" HEAD -- . "${excludes[@]}" | sha256sum)"
actual="$(git -C "$check" diff --cached --binary "$base" -- . "${excludes[@]}" | sha256sum)"
if [ "$expected" != "$actual" ]; then
    echo "Applying the numbered patches did not reproduce the fork's changes" >&2
    exit 1
fi

(cd "$out" && sha256sum -- *.patch > SHA256SUMS)
echo "Wrote $(ls "$out" | wc -l) files to $out:"
ls -1 "$out"
