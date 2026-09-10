# ASTRA FABLE-audit publication helper

Identity: **ASTRA**.

`fable_audits_final_inventory.json` is the local, parent-independent whitelist for the two accepted audit packages. It includes the two audit packages, their exact captured dependencies, the retained-history audit and its inputs, and publication/source messages. It excludes every `drafts/` and `__pycache__/` path. Each row binds the byte length, SHA-256, Git blob SHA-1, and transport encoding. Both copied `mcrypt.wasm` files are exact 211,879-byte binaries and use the Git blob API with `encoding=base64`; UTF-8 files are supplied to the Git tree API as inline `content`.

No network operation has been run by this preparation task. Once the branch parent is stable, fetch a fresh recursive base-tree response and create a parent-specific manifest:

```sh
python3 -B research/rev7-20260909-codex/comms/publish_fable_audits.py prepare \
  --parent PARENT_COMMIT_SHA \
  --base-tree BASE_TREE_SHA \
  --recursive-tree /path/to/fresh-recursive-tree.json \
  --output research/rev7-20260909-codex/comms/fable_audits_publication_manifest.json
```

The prepare step performs no network writes. It rejects any whitelisted path already present with a different Git blob SHA-1.

Publication is a separate explicit command:

```sh
python3 -B research/rev7-20260909-codex/comms/publish_fable_audits.py publish \
  --manifest research/rev7-20260909-codex/comms/fable_audits_publication_manifest.json \
  --branch codex/rev7-astra-20260909
```

Before any mutation, `publish` requires `gh api user --jq .login` to equal `irebased`, verifies the remote head and its base tree against the manifest, fetches a fresh recursive tree, and refuses changed remote paths. It uploads each distinct WebAssembly blob with Base64 encoding, verifies the returned blob and bytes, creates the tree with text content plus binary blob SHAs, then fetches and verifies every remote blob's SHA-256 and Git SHA-1. It then writes a detached-tree receipt and recursive-tree snapshot. The helper never creates a commit or updates a branch. Root separately creates the commit through the GitHub connector, verifies its author and committer are both `irebased`, and then updates the branch without force.
