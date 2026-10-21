import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from 'parse5';
import { highlightHtml, textContent } from './highlight.mjs';

test('GitHub Dark is real Shiki markup, idempotent and text-exact', async () => {
  for (const [lang, code] of [
    ['bash', 'printf &quot;%s\\n&quot; &quot;$HOME&quot; &amp;&amp; echo café\n\n'],
    ['json', '{&quot;ok&quot;: true, &quot;errors&quot;: []}\n'],
    ['text', 'Complete prompt.\n\nKeep &lt;IDs&gt; &amp; boundaries.\n'],
    ['text', ''],
  ]) {
    const source = `<pre class="prompt" data-language="${lang}" tabindex="0" role="region" aria-label="Example"><code>${code}</code></pre>`;
    const result = await highlightHtml(source);
    assert.equal(result.count, 1);
    assert.equal(textContent(parse(result.html)), textContent(parse(source)));
    assert.match(result.html, /class="prompt shiki github-dark-default shiki-style-/);
    assert.ok([...result.styles.values()].includes('background-color:#0d1117;color:#e6edf3'));
    assert.doesNotMatch(result.html, /\sstyle=/);
    assert.match(result.html, /tabindex="0" role="region" aria-label="Example"/);
    assert.equal((await highlightHtml(result.html)).html, result.html);
  }
});
test('only code content and build-owned pre attributes change', async () => {
  const source = '<h1>Keep this</h1><pre data-language="bash"><code class="language-bash">echo &quot;hi&quot;</code></pre><p>Next</p>';
  const { html, styles } = await highlightHtml(source);
  assert.ok(html.startsWith('<h1>Keep this</h1>'));
  assert.ok(html.endsWith('</pre><p>Next</p>'));
  assert.match(html, /<code class="language-bash">/);
  assert.ok([...styles.values()].includes('color:#A5D6FF')); // GitHub Dark string token.
});
test('switching to dark removes stale light-theme classes', async () => {
  const { html } = await highlightHtml('<pre class="prompt shiki github-light shiki-style-old" data-language="text"><code>Keep complete prompt.</code></pre>');
  assert.doesNotMatch(html, /github-light|shiki-style-old/);
  assert.match(html, /data-theme="github-dark-default"/);
  assert.equal(textContent(parse(html)), 'Keep complete prompt.');
});
test('missing or incorrect language and malformed blocks fail closed', async () => {
  for (const source of [
    '<pre><code>echo hi</code></pre>',
    '<pre data-language="guessed"><code>echo hi</code></pre>',
    '<pre data-language="text">unwrapped</pre>',
    '<pre data-language="text"><code>a</code><code>b</code></pre>',
  ]) await assert.rejects(highlightHtml(source));
});
