from __future__ import annotations
import json
from pathlib import Path
import shutil
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('node'), 'Optional Node harness; browser validation remains required')
class SiteInteractionTests(unittest.TestCase):
    def test_complete_copy_and_synchronous_reentrant_and_rejected_paths(self):
        # Execute actual JS with a tiny DOM contract. No browser is driven here.
        harness = r'''
const vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('docs/site.js','utf8');
async function run(mode) {
  const text='task\n\nALL boundaries\nfinal acceptance and handoff';
  const code={textContent:text}, records={writes:[],selected:false,registeredBeforeInsert:false};
  const nodes=[];
  const block={querySelector:()=>code,before:(n)=>{records.registeredBeforeInsert=!!n.click;n.click();nodes.push(n)},after:(n)=>nodes.push(n)};
  const document={querySelector:()=>null,querySelectorAll:s=>s==='pre.prompt'?[block]:[],createElement:()=>({setAttribute(){},addEventListener(e,f){this[e]=f}}),createRange:()=>({selectNodeContents(n){records.selected=n===code}})};
  const navigator={clipboard:{writeText(s){records.writes.push(s);if(mode==='sync')throw Error('denied');return mode==='reject'?Promise.reject(Error('denied')):Promise.resolve()}}};
  const window={getSelection:()=>({removeAllRanges(){},addRange(){}})};
  vm.runInNewContext(source,{document,navigator,window});await nodes[0].click();
  return {...records,status:nodes[1].textContent,full:records.writes[0]===text};
}
(async()=>{console.log(JSON.stringify(await Promise.all(['success','sync','reject'].map(run))))})();
'''
        p=subprocess.run(['node','-e',harness],cwd=ROOT,capture_output=True,text=True,check=True)
        success,sync,reject=json.loads(p.stdout)
        for case in [success,sync,reject]:
            self.assertTrue(case['full'])
            self.assertTrue(case['registeredBeforeInsert'])
        self.assertEqual(success['status'],'Complete prompt copied.')
        self.assertFalse(success['selected'])
        for case in [sync,reject]:
            self.assertTrue(case['selected'])
            self.assertIn('copy it manually',case['status'])
            self.assertNotIn('copied.',case['status'])

    def test_desktop_contents_open_even_with_synchronous_media_callbacks(self):
        harness = r"""
const vm=require('node:vm'),fs=require('node:fs'),log=[];
const link={},summary={focus(){document.activeElement=summary;log.push('focus')}};
const contents={contains:n=>n===link||n===summary,querySelector:()=>summary,set open(v){this.value=v;log.push(v?'open':'close')}};
const menu={contains:()=>false,set open(v){this.value=v}};
const media=[];
const document={activeElement:link,querySelector:s=>s==='.site-menu'?menu:contents,querySelectorAll:()=>[]};
const window={matchMedia(){const m={matches:true,addEventListener(e,f){this.change=f;f()}};media.push(m);return m}};
vm.runInNewContext(fs.readFileSync('docs/site.js','utf8'),{document,window});
const desktopOpen=contents.value&&menu.value;
log.length=0;media[0].matches=false;media[0].change();media[0].matches=true;media[0].change();
console.log(JSON.stringify({desktopOpen,log}));
"""
        result = subprocess.run(['node', '-e', harness], cwd=ROOT, capture_output=True, text=True, check=True)
        observed = json.loads(result.stdout)
        self.assertTrue(observed['desktopOpen'])
        self.assertEqual(observed['log'], ['focus', 'close', 'open'])

    def test_disclosure_moves_focus_before_closing_on_a_breakpoint(self):
        harness=r'''
const vm=require('node:vm'),fs=require('node:fs');const order=[];
const active={};const disclosure={contains:n=>n===active,querySelector:()=>({focus(){order.push('focus')}}),set open(v){order.push(v?'open':'close')}};
const document={activeElement:active,querySelector:()=>disclosure,querySelectorAll:()=>[]};
const window={matchMedia:()=>({matches:false,addEventListener(){}})};
vm.runInNewContext(fs.readFileSync('docs/site.js','utf8'),{document,window});
console.log(JSON.stringify(order));
'''
        p=subprocess.run(['node','-e',harness],cwd=ROOT,capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(p.stdout),['focus','close','focus','close'])

if __name__=='__main__':unittest.main()
