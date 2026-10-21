from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'docs/illustrations'
NS = {'s': 'http://www.w3.org/2000/svg'}


class EcosystemIllustrationTests(unittest.TestCase):
    def test_approved_assets_and_brand_bytes_are_sealed_and_self_contained(self):
        manifest = json.loads((ASSETS/'sources.json').read_text())
        for name, digest in manifest['illustrations'].items():
            data = (ASSETS/name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            tree = ET.fromstring(data)
            self.assertEqual(tree.attrib['role'], 'img')
            self.assertIsNotNone(tree.find('s:desc', NS))
            for node in tree.iter():
                self.assertNotIn(node.tag.rsplit('}',1)[-1], ('script','foreignObject','a'))
                self.assertFalse(any(k.lower().startswith('on') for k in node.attrib))
        tree = ET.parse(ASSETS/'connected-ecosystem.svg')
        images = tree.findall('.//s:image', NS)
        self.assertEqual(len(images), 8)
        self.assertEqual({i.attrib['data-brand'] for i in images}, set(manifest['brands']))
        for image in images:
            key = image.attrib['data-brand']
            uri = image.attrib['{http://www.w3.org/1999/xlink}href']
            self.assertTrue(uri.startswith(('data:image/svg+xml;base64,','data:image/png;base64,')))
            self.assertEqual(hashlib.sha256(base64.b64decode(uri.split(',',1)[1])).hexdigest(), manifest['brands'][key]['sha256'])

    def test_hotspot_matches_existing_review_card_without_changing_geometry(self):
        manifest = json.loads((ASSETS/'sources.json').read_text())
        x,y,w,h = manifest['review_hotspot']['rect']
        vw,vh = manifest['review_hotspot']['viewbox']
        tree = ET.parse(ASSETS/'connected-ecosystem.svg')
        self.assertTrue(any(tuple(float(n.attrib[k]) for k in ('x','y','width','height')) == (x,y,w,h) for n in tree.findall('.//s:rect',NS)))
        self.assertTrue(any(n.text == 'Review' and x < float(n.attrib['x']) < x+w and y < float(n.attrib['y']) < y+h for n in tree.findall('.//s:text',NS)))
        css = (ROOT/'docs/styles.css').read_text()
        for prop, value in [('left',x/vw*100),('top',y/vh*100),('width',w/vw*100),('height',h/vh*100)]:
            self.assertIn(f'{prop}: {value:.8f}'.rstrip('0').rstrip('.')+'%',css)
        self.assertIn('@media (min-width: 64rem) and (min-height: 40rem)',css)
        self.assertIn('.review-explainer > summary { min-height: 44px;',css)
        self.assertIn('animation: review-aura 2.2s ease-in-out 2',css)
        self.assertIn('@media (prefers-reduced-motion: reduce)',css)
        self.assertIn('animation: none !important',css)
        self.assertIn('.review-explainer[open] + .review-popover { display: block; }',css)
        self.assertIn('.review-disclosure:not(.is-dismissed):hover > .review-popover { display: block; }',css)

    def test_two_layers_in_order_with_native_disclosure_text_and_truthful_limits(self):
        home = (ROOT/'docs/index.html').read_text()
        readme = (ROOT/'README.md').read_text()
        for text in (home,readme):
            self.assertLess(text.index('connected-ecosystem.svg'),text.index('supervised-delegation.svg'))
        for phrase in ('Plan, compare and decide','Execution, supervision and delegation',
                       '<details class="review-explainer">','<div class="review-disclosure">','aria-controls="review-zero-trust"',
                       'public-cloud and open-weight model output as untrusted input',
                       'Think of intelligence tradecraft','do not make a model trustworthy or guarantee safety',
                       'Read the architecture diagram in text','Read the supervision diagram in text',
                       'Outside and local-model reviews have their own requirements'):
            self.assertIn(phrase,home)
        self.assertEqual(home.count('<!-- diagram:purpose-preserving -->'),1)
        self.assertIn('<details class="supporting-flow">',home)
        self.assertNotIn('over a century',home)  # Analogy, not an unsupported historical proof.
        self.assertNotIn('onmouseenter=',home)

    @unittest.skipUnless(shutil.which('node'),'Node harness optional; actual browser checks required')
    def test_actual_script_hover_pin_touch_focus_escape_and_reentrant_visibility(self):
        harness = r'''
const vm=require('node:vm'),fs=require('node:fs');
function setup(withObserver=true){
 const events={}, clicks={}, docEvents={}, timers=new Map(), log=[];let serial=0,opened=false;
 const link={},outside={};
 const aura={classList:{add(c){log.push('aura:'+c)}}};
 const summary={getBoundingClientRect:()=>({top:600,bottom:650}),addEventListener:(e,f)=>clicks[e]=f,focus(){log.push('focus');document.activeElement=summary;events.focusin?.({})}};
 const classes=new Set();const zone={classList:{add:c=>classes.add(c),remove:c=>classes.delete(c)},parentElement:{querySelector:()=>aura},querySelector:()=>({getBoundingClientRect:()=>({height:350})}),addEventListener:(e,f)=>events[e]=f,contains:n=>[details,zone,summary,link].includes(n)};const details={parentElement:zone,querySelector:()=>summary,addEventListener:(e,f)=>events[e]=f,get open(){return opened},set open(v){opened=v;log.push(v?'open':'close')}};
 const document={activeElement:outside,querySelector:()=>null,querySelectorAll:s=>s==='.review-explainer'?[details]:[],addEventListener:(e,f)=>docEvents[e]=f};
 const window={innerHeight:900,matchMedia:()=>({matches:true}),addEventListener(){},setTimeout:f=>{timers.set(++serial,f);return serial},clearTimeout:id=>timers.delete(id)};
 if(withObserver)window.IntersectionObserver=class{constructor(cb){this.cb=cb}observe(){if(Object.keys(events).length!==6||!clicks.click||!docEvents.pointerdown)throw Error('observer before controls');this.cb([{isIntersecting:true}])}disconnect(){log.push('disconnect')}};
 vm.runInNewContext(fs.readFileSync('docs/site.js','utf8'),{document,window});
 return {details,events,docEvents,document,summary,link,outside,log,classes,flush(){const fs=[...timers.values()];timers.clear();fs.forEach(f=>f())},click(){let prevented=false;clicks.click({preventDefault(){prevented=true}});if(!prevented)details.open=!details.open;return prevented}};
}
const a=setup();a.events.pointerenter({pointerType:'mouse'});const hover=a.details.open;a.events.toggle();const popupFlipped=a.classes.has('is-above');a.events.pointerleave({});a.events.pointerenter({pointerType:'mouse'});a.flush();const gap=a.details.open;a.events.pointerleave({});a.flush();const leftClosed=!a.details.open;
const b=setup();b.events.pointerenter({pointerType:'mouse'});const pin=b.click();b.events.pointerleave({});b.flush();const pinned=b.details.open;b.docEvents.pointerdown({target:b.outside});const outsideClosed=!b.details.open;
const c=setup(false);c.events.pointerenter({pointerType:'touch'});const touchNotHover=!c.details.open;c.click();const touchOpen=c.details.open;c.click();const toggleClosed=!c.details.open;
const d=setup();d.click();d.document.activeElement=d.link;d.log.length=0;d.events.keydown({key:'Escape',preventDefault(){}});const focusBeforeClose=d.log.indexOf('focus')<d.log.indexOf('close');const escapeClosed=!d.details.open&&d.document.activeElement===d.summary;
d.click();d.events.focusout({relatedTarget:d.link});const retained=d.details.open;d.events.focusout({relatedTarget:d.outside});const focusoutClosed=!d.details.open;
console.log(JSON.stringify({hover,popupFlipped,gap,leftClosed,pin,pinned,outsideClosed,touchNotHover,touchOpen,toggleClosed,focusBeforeClose,escapeClosed,retained,focusoutClosed,reentrantObserver:a.log.includes('disconnect'),fallbackAura:c.log.includes('aura:is-visible')}));
'''
        result = subprocess.run(['node','-e',harness],cwd=ROOT,text=True,capture_output=True,check=True)
        for name,passed in json.loads(result.stdout).items():
            self.assertTrue(passed,name)


if __name__ == '__main__':
    unittest.main()
