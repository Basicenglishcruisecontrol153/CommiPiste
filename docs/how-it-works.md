# How it works

Open-source apps serve static files (JS, CSS, icons, …) from a public directory. Those exact files
exist in the project's git history. CommiPiste:

1. **Indexes** a repository offline: clones it, detects the public directory, walks the relevant
   history (tags/releases plus commits that change the public dir), and records each file's
   **git blob OID** per ref into a signature database (`hash → paths → commits`).
2. **Scans** a target online: auto-detects the software by banner/path (falling back to matching
   indexed static files when no banner identifies it), downloads the relevant static files over
   HTTP, reproduces their git blob OID from the bytes, and matches those hashes against the
   database to narrow the deployment down to a single commit.

The canonical hash is the **git blob OID** — `sha1("blob "+len+"\0"+content)`. Repository-side
hashes come straight from `git ls-tree` (no blob content is read), enabling a **blobless clone**
(`--filter=blob:none`, ~25× smaller); target-side hashes are reproduced from the downloaded bytes,
so they match directly.

<img width="1672" height="941" alt="how-it-works" src="https://github.com/user-attachments/assets/f884ca17-7a08-4f3d-919f-c4e7e8eef9a3" />

For the full internals and data model, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Sources beyond GitHub

Indexing only shells out to `git`, so `repo_url` works for **GitHub, GitLab, self-hosted, or any
git remote** (per-host commit links via `commit_url_tpl`; full-clone fallback if a server rejects
partial clone). For wordpress.org plugins/themes that aren't on git, set `source: wporg` — a backend
that reads `plugins.svn.wordpress.org/<slug>/` over plain HTTP and git-blob-hashes fetched content
(no `svn` binary needed).

## Dependents (WordPress plugins)

When a WordPress instance is identified, CommiPiste also probes each known plugin at
`wp-content/plugins/<slug>/` (presence-gated cheaply), fingerprinting installed ones as separate
findings. Drives off each plugin project's `served_prefix`. The same mechanism generalises to other
host/extension relationships.
