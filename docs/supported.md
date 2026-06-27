# What can be fingerprinted

CommiPiste matches the *exact bytes* a server serves against the *exact bytes* committed to the
project's git repository. This works only when the software **serves static assets verbatim from
its source tree** — i.e. the file at `/css/app.css` on the server is byte-for-byte the same file
that lives at `css/app.css` in the repo at some tagged release. Traditional PHP/Ruby/Perl web apps
(WordPress, Roundcube, GLPI, phpBB, MediaWiki, …) behave this way and fingerprint cleanly.

See [CATALOG.md](CATALOG.md) for the full per-project list and per-project caveats (thin index,
unverified, best-guess CPE).

## Not git-blob fingerprintable (single-page apps / compiled assets)

The following popular platforms do **not** serve their repository's source files verbatim. Several of
them *do* expose their version at an endpoint, so their **version** can still be read via
[active probing](active-probing.md) (`--active`): Mattermost, Grafana, Gitea, Jenkins, Discourse,
Flarum.

- **Grafana**, **Kibana** — React/Angular single-page apps served as webpack/Vite *build output*:
  bundled, minified, content-hashed filenames (`app.<hash>.js`). None of that exists in the git tree.
- **GitLab** — webpack build; served assets are bundled and fingerprint-named, not repo source.
- **Gitea / Forgejo** — Go binaries with web assets **embedded into the executable** at build time.
- **Jenkins** — Java WAR; static resources packaged/served from JARs, not repo-path files.
- **Keycloak** — Java app with a compiled SPA admin console and themes built at packaging time.
- **Discourse** — an Ember.js SPA served as fingerprinted, compiled bundles.

In short: when assets are **build artifacts** (bundled / minified / content-hash-named /
embedded-in-binary) rather than committed source served as-is, hashing the served file yields an OID
that appears in no commit, so version identification fails (or degrades to noisy `modified`/range
guesses). The same caveat partially applies to apps that ship *some* built bundles (e.g. Nextcloud's
webpacked JS, Magento's generated `pub/static`): their non-built assets (core CSS, images) and
discriminator files still pin the version, but the compiled bundles will not match.

Supporting these would require indexing from **release tarballs, distributed packages, or built
Docker images** (the actual artifacts a deployment runs) instead of the git repository — a planned
future capability, not the current git-blob approach.
