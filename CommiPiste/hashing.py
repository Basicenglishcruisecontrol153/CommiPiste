"""Canonical hashing for CommiPiste.

The canonical hash is the **git blob OID**: the same identifier git assigns to a file's content,

    blob_oid = sha1(b"blob " + str(len(content)).encode() + b"\\0" + content)

On the repository side we get these OIDs for free from `git ls-tree -r <ref>` (no need to read or
re-hash blob content). On the target side we reproduce the exact same OID from the bytes downloaded
over HTTP, so server files match index entries directly.

Git uses collision-detecting SHA-1 (sha1dc); for fingerprinting this is more than sufficient.
Repositories that use the SHA-256 object format already report SHA-256 OIDs in `ls-tree`, and the
same `git_blob_hash(..., algo="sha256")` reproduces them.
"""

from __future__ import annotations

import hashlib


def git_blob_hash(content: bytes, algo: str = "sha1") -> str:
    """Reproduce the git blob OID for the given raw file content.

    Mirrors git's object hashing so a file downloaded from a target hashes to the same OID that
    `git ls-tree` reported for the corresponding blob in the repository.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    h = hashlib.new(algo)
    h.update(header)
    h.update(content)
    return h.hexdigest()


def git_blob_hash_variants(content: bytes, algo: str = "sha1") -> list[str]:
    """OIDs to try for a fetched file: the raw OID, then the line-ending-normalized OID.

    Git stores text blobs with LF newlines, but some projects' *release packaging* converts the
    served copy to CRLF (e.g. EspoCRM's distribution zip). The served bytes then hash differently
    from the LF blob in the repo even though the content is identical. So for text files that
    contain CRLF we also offer the OID of the CRLF→LF-normalized content as a fallback.

    The raw OID is always first (an exact byte match must win); the normalized one is only added
    for files that look textual (no NUL byte) and actually contain CRLF, so binary assets are never
    altered.
    """
    variants = [git_blob_hash(content, algo)]
    if b"\r\n" in content and b"\0" not in content:
        normalized = content.replace(b"\r\n", b"\n")
        if normalized != content:
            variants.append(git_blob_hash(normalized, algo))
    return variants
