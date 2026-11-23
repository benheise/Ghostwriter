#!/usr/bin/env bash
# Build the fork's patch set for an upstream Ghostwriter release.
#
# Usage: fork/make-patches.sh [--combined-only] <upstream-tag> [output-dir]
#
# Cherry-picks the fork's own commits (those on HEAD that are not merges and not in the upstream tag)
# onto a clean copy of the tag, then writes one numbered patch per commit, a combined patch, and
# SHA256SUMS. Changes to fork/ and README.md stay out of the patches. Fails if a commit no longer
# applies, so a broken patch is caught here rather than by users.
#
# --combined-only skips the numbered patches and writes only the combined patch, taken straight from
# the difference between the tag and HEAD. Use it when HEAD has merged the tag but a fork commit no
# longer cherry-picks cleanly onto it; the merge's conflict resolutions are then part of the patch.
set -euo pipefail

combined_only=false
if [ "${1:-}" = "--combined-only" ]; then
    combined_only=true
    shift
fi
tag="${1:?usage: fork/make-patches.sh [--combined-only] <upstream-tag> [output-dir]}"
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
version="${tag#v}"
combined="$out/ghostwriter-$version-benheise.patch"

if [ "$combined_only" = true ]; then
    git merge-base --is-ancestor "$base" HEAD || { echo "HEAD does not contain $tag; merge it first" >&2; exit 1; }
    rm -rf "$out"
    mkdir -p "$out"
    git diff --binary "$base" HEAD -- . "${excludes[@]}" > "$combined"
    expected="$(git diff --binary "$base" HEAD -- . "${excludes[@]}" | sha256sum)"
    rmdir "$check"
    git -C "$root" worktree add --quiet --detach "$check" "$base"
    git -C "$check" apply --index "$combined"
    actual="$(git -C "$check" diff --cached --binary "$base" -- . "${excludes[@]}" | sha256sum)"
    [ "$expected" = "$actual" ] || { echo "The combined patch did not reproduce HEAD's changes" >&2; exit 1; }
    cat > "$out/README.txt" <<NOTE
Only the combined patch is available for $tag: a fork commit no longer applied cleanly on its own.
Apply it to a clean $tag checkout with: git apply --check $(basename "$combined") && git apply $(basename "$combined")
NOTE
else
    rmdir "$work"
    git -C "$root" worktree add --quiet --detach "$work" "$base"

    for commit in "${commits[@]}"; do
        if ! git -C "$work" cherry-pick --allow-empty "$commit" >/dev/null 2>&1; then
            echo "Commit $(git log -1 --format='%h %s' "$commit") does not apply cleanly to $tag" >&2
            echo "If HEAD has merged $tag, rerun with --combined-only" >&2
            git -C "$work" cherry-pick --abort >/dev/null 2>&1 || true
            exit 1
        fi
    done

    rm -rf "$out"
    mkdir -p "$out"
    git -C "$work" format-patch --quiet --binary --no-signature --zero-commit -o "$out" "$base..HEAD" -- . "${excludes[@]}"
    git -C "$work" diff --binary "$base" HEAD -- . "${excludes[@]}" > "$combined"

    # Prove the set applies to a clean copy of the tag, one by one and combined
    rmdir "$check"
    git -C "$root" worktree add --quiet --detach "$check" "$base"
    git -C "$check" apply --check "$combined"
    for patch in "$out"/0*.patch; do
        git -C "$check" apply --index "$patch"
    done
    expected="$(git -C "$work" diff --binary "$base" HEAD -- . "${excludes[@]}" | sha256sum)"
    actual="$(git -C "$check" diff --cached --binary "$base" -- . "${excludes[@]}" | sha256sum)"
    if [ "$expected" != "$actual" ]; then
        echo "Applying the numbered patches did not reproduce the fork's changes" >&2
        exit 1
    fi
fi

(cd "$out" && sha256sum -- *.patch > SHA256SUMS)
echo "Wrote $(ls "$out" | wc -l) files to $out:"
ls -1 "$out"
