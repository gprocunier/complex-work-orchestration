# Documentation syntax highlighting

Code boxes are pre-rendered with **Shiki `github-dark-default`**. The committed HTML
and generated `docs/shiki.css` work without JavaScript, npm, a CDN or a
browser-side highlighter. Shiki's token styles are extracted into local classes
so the preview keeps its strict Content Security Policy, without inline styles.
This is
documentation authoring tooling, not an installed CWO runtime dependency.

Use Node.js 20 or newer:

```sh
cd tools/site
npm ci
npm run build
npm run check
npm test
```

Author code inside the existing `<pre><code>` elements. Set `data-language` on
`pre` explicitly: `bash` for terminal commands, `json` for JSON, or `text` for
agent prompts and recorded prose. Keep prompts' `prompt` class and all region
labels. Rebuilding safely replaces token spans while preserving decoded code
text, blank lines, code attributes and copy behavior. Both the shared-shell
generator and this highlighter are idempotent; run their checks after editing.

The exact build dependencies and integrity hashes are locked in
`package-lock.json`. CI regenerates in check mode to detect stale highlighting.
