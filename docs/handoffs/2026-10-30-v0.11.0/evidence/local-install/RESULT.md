# Local v0.11.0 installation

Installed to /usr/local with FUSE enabled, from clean tagged commit0e4eb24eba841a901dd6b320cbb3eb71ddf37f97. Normal PATH resolves /usr/local/bin/secdat and prints secdat0.11.0 / Build0e4eb24eba84. All15 installed files match staging; shared library resolves from /usr/local/lib; pkg-config reports0.11.0.

Official completion regression passed against the installed binary. Installed completion bytes match the reviewed source. Fresh interactive user Bash autoloads /usr/local/share/bash-completion/completions/secdat. Inherited --store, local store-delete, spaces, attached --store=, create no-suggestions and unchanged fixture data all pass.

Old15 installed files are retained in previous-install.tar with metadata/symlinks and a manifest. No user store migration, session restart or shell-rc edit was performed. Existing interactive shells with cached completion definitions can reload with:

```bash
source /usr/local/share/bash-completion/completions/secdat
```

Both failed evidence harness trials are preserved, with causes described in result.json. Product sources were not changed. Installation source worktree/build and logs are retained for reproducibility.
