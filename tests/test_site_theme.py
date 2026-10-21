from __future__ import annotations

import hashlib
import json
from pathlib import Path
from html.parser import HTMLParser
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from site_diagram_theme import svg_theme_style
from generate_site import PAGES
import generate_diagram_themes as THEMES


class ThemeChoices(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.inputs, self.labels, self.icons = [], [], []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag in ('input', 'label', 'svg'):
            target = {'input': self.inputs, 'label': self.labels, 'svg': self.icons}[tag]
            target.append(dict(attrs))


class SiteThemeTests(unittest.TestCase):
    def test_all_pages_have_one_accessible_icon_radio_group_and_early_bootstrap(self):
        for name in PAGES:
            source = (ROOT / 'docs' / name).read_text()
            with self.subTest(page=name):
                self.assertEqual(source.count('id="site-theme"'), 1)
                fieldset = re.search(r'<fieldset class="theme-control" id="site-theme">.*?</fieldset>', source, re.S)[0]
                self.assertIn('<legend class="sr-only">Color theme</legend>', fieldset)
                self.assertNotIn('<select', source)
                choices = ThemeChoices(fieldset)
                self.assertEqual([i['value'] for i in choices.inputs], ['system', 'light', 'dark'])
                self.assertEqual([i['value'] for i in choices.inputs if 'checked' in i], ['system'])
                self.assertEqual(len(choices.labels), 3)
                self.assertEqual(len(choices.icons), 3)
                for item, label, icon in zip(choices.inputs, choices.labels, choices.icons):
                    self.assertEqual(item['type'], 'radio')
                    self.assertEqual(item['name'], 'theme')
                    self.assertEqual(item['id'], 'theme-' + item['value'])
                    self.assertEqual(label['for'], item['id'])
                    self.assertEqual(label['title'], {'system': 'System theme (default)', 'light': 'Light theme', 'dark': 'Dark theme'}[item['value']])
                    self.assertIn('sr-only', item['class'].split())
                    self.assertNotIn('hidden', item)
                    self.assertNotIn('disabled', item)
                    self.assertEqual(icon['aria-hidden'], 'true')
                    self.assertEqual(icon['focusable'], 'false')
                    self.assertEqual(icon['stroke'], 'currentColor')
                    self.assertIn(f'<span class="sr-only">{label["title"]}</span>', fieldset)
                self.assertIn('<meta name="color-scheme" content="light dark">', source)
                self.assertLess(source.index('<script src="./theme.js"></script>'), source.index('href="./styles.css"'))
                self.assertNotIn('onchange=', source)

    def test_icon_group_is_the_last_primary_nav_child_not_a_hidden_cycle(self):
        for name in PAGES:
            source = (ROOT / 'docs' / name).read_text()
            primary = source.split('<nav class="top-nav"', 1)[1].split('</nav>', 1)[0]
            with self.subTest(page=name):
                self.assertLess(primary.index('<details class="site-menu"'), primary.index('<fieldset'))
                self.assertTrue(primary.rstrip().endswith('</fieldset>'))
                self.assertEqual(primary.count('type="radio"'), 3)
                self.assertIn('<rect x="3" y="4"', primary)  # System / monitor.
                self.assertIn('<circle cx="12" cy="12" r="4"', primary)  # Light / sun.
                self.assertIn('M20.9 13.5A9 9', primary)  # Dark / moon.

    def test_css_supports_system_and_native_overrides_even_without_javascript(self):
        css = (ROOT/'docs/styles.css').read_text()
        self.assertIn('@media (prefers-color-scheme: dark)', css)
        self.assertIn(':root:not([data-theme="light"]):not(:has(#site-theme input[value="light"]:checked))', css)
        self.assertIn(':root[data-theme="dark"],\n:root:has(#site-theme input[value="dark"]:checked)', css)
        self.assertNotIn('#site-theme option', css)
        self.assertIn('color-scheme: light;', css)
        self.assertIn('color-scheme: dark;', css)
        self.assertIn('.theme-choice:has(input:focus-visible)', css)
        self.assertRegex(css, r'\.theme-choice \{[^}]*width: 44px; height: 44px;')
        self.assertIn('.theme-choice:has(input:checked)', css)
        self.assertNotIn('.theme-control select', css)
        # Do not invert brand marks or turn GitHub Dark boxes into page surfaces.
        self.assertNotRegex(css, r'filter\s*:\s*invert')
        self.assertIn('background: #0d1117;', css)
        self.assertIn('color: #e6edf3;', css)
        for selector in ('.review-popover', '.site-header', '.site-footer', '.data-table thead th'):
            body = re.search(re.escape(selector) + r' \{([^}]+)\}', css)[1]
            self.assertIn('var(--', body, selector)

    def test_all_svg_images_have_deterministic_theme_styles_and_preserve_approved_originals(self):
        ns = {'s':'http://www.w3.org/2000/svg'}
        assets = list((ROOT/'docs/diagrams').glob('*.svg')) + list((ROOT/'docs/illustrations').glob('*.svg'))
        self.assertEqual(len(assets), 40)
        manifest = json.loads((ROOT/'docs/illustrations/sources.json').read_text())
        for path in assets:
            source = path.read_text()
            tree = ET.fromstring(source)
            kind = 'illustration' if path.parent.name == 'illustrations' else 'flow'
            styles = tree.findall('s:style', ns)
            self.assertEqual(len(styles), 1, path.name)
            self.assertIn(svg_theme_style(kind), source)
            self.assertNotIn('url(', styles[0].text)
            if kind == 'illustration':
                original = THEMES.THEME_STYLE.sub('', source)
                self.assertEqual(hashlib.sha256(original.encode()).hexdigest(), manifest['original_illustrations'][path.name])
                self.assertNotIn('[fill="#ffffff"]', styles[0].text)  # Original logo tile.
                self.assertNotIn('[fill="#16212d"]', styles[0].text)  # White-logo backing.
        for path, expected in THEMES.outputs().items():
            self.assertEqual(path.read_text(), expected)

    def test_palette_normal_text_contrast(self):
        def luminance(color):
            rgb = [int(color[i:i+2],16)/255 for i in (1,3,5)]
            values = [v/12.92 if v <= .04045 else ((v+.055)/1.055)**2.4 for v in rgb]
            return sum(a*b for a,b in zip(values,(.2126,.7152,.0722)))
        pairs = [('#edf2f9','#111923'),('#b7c5d7','#182433'),('#8ac7ff','#182433'),
                 ('#ff8795','#182433'),('#ffffff','#cc0000'),
                 ('#172434','#ffe8ed'),('#45576f','#edf2f7'),('#b51b34','#f7f9fc'),
                 ('#087463','#f7f9fc'),('#805000','#ffffff'),
                 ('#edf2f9','#1b2d44'),('#ffb1ba','#111923')]
        for fg,bg in pairs:
            high,low = sorted((luminance(fg),luminance(bg)),reverse=True)
            self.assertGreaterEqual((high+.05)/(low+.05), 4.5, (fg,bg))

    def test_generator_rejects_non_palette_source_changes_and_check_does_not_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); assets=root/'docs/illustrations'; assets.mkdir(parents=True)
            for name in ('sources.json','connected-ecosystem.svg','supervised-delegation.svg'):
                shutil.copy2(ROOT/'docs/illustrations'/name,assets/name)
            target=assets/'supervised-delegation.svg'
            before=target.read_text()
            target.write_text(before.replace('From a plan to supervised work','Different approved content',1))
            with self.assertRaisesRegex(ValueError,'approved source changed'):
                THEMES.outputs(root)
            self.assertIn('Different approved content',target.read_text())
            target.write_text('stale')
            with patch.object(THEMES,'outputs',return_value={target:'current'}):
                self.assertEqual(THEMES.main(['--check']),1)
                self.assertEqual(target.read_text(),'stale')
                self.assertEqual(THEMES.main(['--write']),0)
                self.assertEqual(target.read_text(),'current')
        with self.assertRaises(ValueError):
            svg_theme_style('unknown')

    @unittest.skipUnless(shutil.which('node'), 'Node is required for theme behavior checks')
    def test_actual_script_storage_defaults_navigation_failures_cross_tab_and_reentrancy(self):
        harness = r'''
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const script=fs.readFileSync('docs/theme.js','utf8'),key='cwo-color-theme';
function setup({stored=null,failGet=false,failSet=false,failAccess=false,loading=true,missing=false,observer=false}={}){
 const writes=[],docEvents={},winEvents={},values=[];
 const choices=['system','light','dark'].map(value=>({value,checked:value==='system',events:{},addEventListener(e,f){this.events[e]=f}}));
 const checked=()=>choices.filter(c=>c.checked).map(c=>c.value);
 const storage={getItem(k){assert.equal(k,key);if(failGet)throw Error('denied');return stored},setItem(k,v){if(failSet)throw Error('quota');stored=v;writes.push([k,v])},removeItem(k){if(failSet)throw Error('denied');stored=null;writes.push([k,null])}};
 let theme,observe=false;
 const dataset={};Object.defineProperty(dataset,'theme',{get:()=>theme,set:v=>{theme=v;values.push(v);if(observe){assert.deepEqual(checked(),[v]);assert.ok(choices.every(c=>c.events.change));assert.ok(winEvents.storage)}}});
 const document={documentElement:{dataset},readyState:loading?'loading':'complete',querySelectorAll:s=>{assert.equal(s,'#site-theme input[type="radio"]');return missing?[]:choices},addEventListener:(e,f)=>docEvents[e]=f};
 const window={addEventListener:(e,f)=>winEvents[e]=f};Object.defineProperty(window,'localStorage',{get(){if(failAccess)throw Error('blocked');return storage}});
 vm.runInNewContext(script,{document,window});observe=observer;
 if(loading)docEvents.DOMContentLoaded();
 return {root:dataset,choices,checked,storage,writes,values,winEvents,change(v){choices.forEach(c=>c.checked=c.value===v);choices.find(c=>c.value===v).events.change()},stored:()=>stored};
}
for(const saved of [null,'','garbage','system','LIGHT']){const a=setup({stored:saved});assert.equal(a.root.theme,'system');assert.deepEqual(a.checked(),['system']);assert.equal(a.writes.length,0)}
for(const saved of ['light','dark']){const a=setup({stored:saved,observer:true});assert.equal(a.values[0],saved);assert.equal(a.root.theme,saved);assert.deepEqual(a.checked(),[saved]);assert.equal(a.writes.length,0)}
const a=setup({observer:true});a.change('dark');assert.equal(a.stored(),'dark');assert.equal(a.root.theme,'dark');
const priorWrites=a.writes.length;a.choices[0].events.change();assert.equal(a.root.theme,'dark');assert.equal(a.writes.length,priorWrites);
a.change('light');assert.equal(a.stored(),'light');assert.equal(a.root.theme,'light');
const reload=setup({stored:a.stored(),loading:false,observer:true});assert.deepEqual(reload.checked(),['light']);a.change('system');assert.equal(a.stored(),null);assert.equal(a.root.theme,'system');
for(const failure of [{failGet:true},{failSet:true},{failGet:true,failSet:true},{failAccess:true}]){const b=setup({...failure,observer:true});b.change('dark');assert.equal(b.root.theme,'dark');b.change('system');assert.equal(b.root.theme,'system')}
const c=setup({observer:true});const event=(k,v,storage=c.storage)=>c.winEvents.storage({key:k,newValue:v,storageArea:storage});
event('unrelated','dark');assert.equal(c.root.theme,'system');event(key,'dark',{});assert.equal(c.root.theme,'system');event(key,'dark');assert.equal(c.root.theme,'dark');assert.deepEqual(c.checked(),['dark']);event(key,'bad');assert.equal(c.root.theme,'system');event(key,'light');event(null,null);assert.equal(c.root.theme,'system');assert.equal(c.writes.length,0);
const blocked=setup({failAccess:true});blocked.winEvents.storage({key,newValue:'dark',storageArea:{}});assert.equal(blocked.root.theme,'system');
setup({missing:true});setup({missing:true,loading:false});
console.log(JSON.stringify({defaultAndInvalid:true,prePaint:true,storedAndReload:true,storageFailure:true,systemReset:true,crossTab:true,listenerBeforeObserver:true,allRadiosBeforeRootObserver:true,uncheckedChangeIgnored:true,missingControl:true}));
'''
        result=subprocess.run(['node','-e',harness],cwd=ROOT,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(all(json.loads(result.stdout).values()))


if __name__ == '__main__':
    unittest.main()
