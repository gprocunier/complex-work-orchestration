"""Source-faithful example diagrams; shared semantics, separately routed layouts."""
from __future__ import annotations

from html import escape
import textwrap

EXAMPLE_KINDS = frozenset({'example-retry', 'example-recovery', 'example-migration',
                           'example-encoding', 'example-restore'})


class Canvas:
    def __init__(self, narrow, height):
        self.narrow = narrow
        self.width, self.height = (360 if narrow else 1020), height
        self.parts = []

    def label(self, words, x, y, *, size=18):
        self.parts.append(f'<text x="{x}" y="{y}" text-anchor="middle" font-size="{size}" font-weight="600">{escape(words)}</text>')

    def node(self, key, title, details, x, y, *, shape='process', h=128):
        w = 280
        attrs = f'data-node="{key}" data-x="{x}" data-y="{y}" data-width="{w}" data-height="{h}"'
        if shape == 'decision':
            geometry = f'<polygon points="{x},{y-h/2} {x+w/2},{y} {x},{y+h/2} {x-w/2},{y}" fill="#fff4e5" stroke="#8f5200" stroke-width="2"/>'
        elif shape == 'store':
            left, top = x-w/2, y-h/2
            geometry = (f'<path d="M {left},{top+14} C {left},{top-5} {left+w},{top-5} {left+w},{top+14} V {top+h-14} C {left+w},{top+h+5} {left},{top+h+5} {left},{top+h-14} Z" fill="#fff" stroke="#6a6e73" stroke-width="2"/>'
                        f'<path d="M {left},{top+14} C {left},{top+33} {left+w},{top+33} {left+w},{top+14}" fill="none" stroke="#6a6e73" stroke-width="2"/>')
        else:
            geometry = f'<rect x="{x-w/2}" y="{y-h/2}" width="{w}" height="{h}" rx="{28 if shape == "result" else 12}" fill="#fff" stroke="#6a6e73" stroke-width="2"/>'
        lines = [(line, True) for line in textwrap.wrap(title, 23)] + [(line, False) for line in details]
        top = y - (len(lines)-1)*13
        if shape == 'store':
            top += 9
        labels = ''.join(f'<text x="{x}" y="{top+i*26}" text-anchor="middle" dominant-baseline="central" font-size="{(19 if shape == "decision" else 21) if bold else 18}" font-weight="{600 if bold else 400}">{escape(line)}</text>' for i, (line, bold) in enumerate(lines))
        self.parts.append(f'<g {attrs}>{geometry}{labels}</g>')

    def edge(self, source, target, path):
        self.parts.append(f'<path data-from="{source}" data-to="{target}" d="{path}" fill="none" stroke="#a60000" stroke-width="2.5" stroke-linejoin="round" marker-end="url(#arrow)"/>')

    def boundary(self, x1, y1, x2, y2):
        self.parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#6a6e73" stroke-width="1.5" stroke-dasharray="7 7"/>')

    def result(self):
        return self.width, self.height, ''.join(self.parts)


def retry(narrow):
    c = Canvas(narrow, 1510 if narrow else 680)
    rows = [('post-replay', 'POST · retry after failure', 'Write effect 1; status 503',
             'Attempt 2', ('Write effect 2; status 200',), 'Duplicate effect', ('2 attempts · 2 effects',)),
            ('post-stop', 'POST · do not replay', 'Write effect 1; status 503',
             'Stop after failure', ('No second attempt',), 'Outcome still ambiguous', ('1 attempt · 1 effect',)),
            ('get', 'GET · bounded retry', 'No write effect; status 503',
             'Attempt 2', ('No write effect; status 200',), 'Read retry completes', ('2 attempts · 0 write effects',))]
    for i, (key, heading, first, second_title, second, outcome, totals) in enumerate(rows):
        if narrow:
            base = i*500
            c.label(heading, 180, base+26, size=19)
            positions = [(180, base+110), (180, base+280), (180, base+440)]
            routes = [f'M 180,{base+174} V {base+210}', f'M 180,{base+344} V {base+386}']
        else:
            base = i*220
            c.label(heading, 510, base+32, size=22)
            positions = [(170, base+120), (510, base+120), (850, base+120)]
            routes = [f'M 310,{base+120} H 364', f'M 650,{base+120} H 704']
        c.node(key+'-first', 'Attempt 1', (first,), *positions[0])
        c.node(key+'-second', second_title, second, *positions[1])
        c.node(key+'-result', outcome, totals, *positions[2], shape='result', h=96)
        c.edge(key+'-first', key+'-second', routes[0])
        c.edge(key+'-second', key+'-result', routes[1])
    return c.result()


def recovery(narrow):
    c = Canvas(narrow, 1450 if narrow else 880)
    labels = {
        'session-one': ('Session 1 · fix validator', ('Booleans are not ports', 'Keep list-of-errors API'), 'process'),
        'beads': ('Beads task records', ('Validator accepted', 'Dependent CLI still waiting'), 'store'),
        'files': ('Project files', ('Code + tests', 'HANDOFF.md + evidence'), 'store'),
        'session-two': ('Session 2 · start fresh', ('Read both saved records', 'Check current code + tests'), 'process'),
        'acceptance': ('Acceptance verified?', ('Current evidence?',), 'decision'),
        'cli': ('Add the CLI', ('Preserve accepted behavior', 'Then test the new command'), 'result'),
        'investigate': ('Investigate first', ('Missing or stale evidence', 'Do not start the CLI yet'), 'result'),
    }
    if narrow:
        pos = dict(zip(labels, [(180,90),(180,290),(180,490),(180,750),(180,950),(180,1170),(180,1370)]))
        routes = [('session-one','beads','M 180,154 V 220'),
                  ('session-one','files','M 326,90 H 344 V 490 H 326'),
                  ('beads','session-two','M 34,290 H 16 V 750 H 34'),
                  ('files','session-two','M 180,554 V 680'),
                  ('session-two','acceptance','M 180,814 V 874'),
                  ('acceptance','cli','M 180,1020 V 1100'),
                  ('acceptance','investigate','M 326,950 H 344 V 1370 H 326')]
        c.boundary(42,615,318,615)
        c.label('New conversation',100,644,size=15)
        c.label('Yes',205,1060); c.label('No',316,1050)
    else:
        pos = dict(zip(labels, [(170,210),(510,100),(510,340),(850,210),(850,520),(680,770),(340,770)]))
        routes = [('session-one','beads','M 310,210 H 340 V 100 H 364'),
                  ('session-one','files','M 310,210 H 340 V 340 H 364'),
                  ('beads','session-two','M 650,100 H 680 V 185 H 704'),
                  ('files','session-two','M 650,340 H 680 V 235 H 704'),
                  ('session-two','acceptance','M 850,274 V 444'),
                  ('acceptance','cli','M 850,590 V 645 H 680 V 700'),
                  ('acceptance','investigate','M 710,520 H 340 V 700')]
        c.boundary(695,30,695,395)
        c.label('New conversation',850,32)
        c.label('Yes',790,635); c.label('No · recheck',455,505)
    for key, (title, detail, shape) in labels.items():
        c.node(key,title,detail,*pos[key],shape=shape,h=140 if shape=='decision' else 128)
    for args in routes: c.edge(*args)
    return c.result()


def migration(narrow):
    c = Canvas(narrow, 1510 if narrow else 900)
    labels = {
        'baseline': ('Save one baseline', ('Cases + compatibility', 'Scoring + selection rule'), 'store'),
        'repair': ('Repair the runner only', ('Keep the saved baseline', 'Recheck before execution'), 'process'),
        'check': ('Same saved rules?', ('Invoke the check',), 'decision'),
        'converter-a': ('Converter A', ('Use the same cases', 'and the same rules'), 'process'),
        'converter-b': ('Converter B', ('Use the same cases', 'and the same rules'), 'process'),
        'report': ('Compare the results', ('Apply the saved rule', 'Neither may qualify'), 'result'),
        'separate': ('Separate evaluation', ('Do not continue old run', 'Keep its original evidence'), 'result'),
    }
    if narrow:
        pos = dict(zip(labels, [(180,90),(180,300),(180,530),(180,760),(180,970),(180,1190),(180,1420)]))
        routes = [('baseline','repair','M 180,154 V 230'),
                  ('baseline','check','M 34,90 H 16 V 530 H 34'),
                  ('repair','check','M 180,364 V 454'),
                  ('check','converter-a','M 180,600 V 690'),
                  ('check','converter-b','M 326,530 H 344 V 970 H 326'),
                  ('converter-a','report','M 34,760 H 16 V 1190 H 34'),
                  ('converter-b','report','M 180,1034 V 1120'),
                  ('check','separate','M 180,600 V 640 H 4 V 1420 H 34')]
        # Keep the changed-rules branch outside the unchanged-input routes.
        c.label('Optional',247,202,size=17)
        c.label('Yes',214,653); c.label('No',75,626)
        c.label('Changed cases or rules → new evaluation',180,1320,size=15)
    else:
        pos = dict(zip(labels, [(510,90),(170,290),(510,290),(330,560),(690,560),(510,800),(850,290)]))
        routes = [('baseline','repair','M 510,154 V 185 H 170 V 220'),
                  ('baseline','check','M 510,154 V 214'),
                  ('repair','check','M 310,290 H 364'),
                  ('check','converter-a','M 510,360 V 420 H 330 V 490'),
                  ('check','converter-b','M 510,360 V 420 H 690 V 490'),
                  ('converter-a','report','M 330,624 V 690 H 480 V 730'),
                  ('converter-b','report','M 690,624 V 690 H 540 V 730'),
                  ('check','separate','M 650,290 H 704')]
        c.label('If repair is needed',335,215)
        c.label('Yes · unchanged',610,400)
        c.label('Changed cases or rules',850,195)
    for key,(title,detail,shape) in labels.items():
        c.node(key,title,detail,*pos[key],shape=shape,h=140 if shape=='decision' else 128)
    for args in routes: c.edge(*args)
    return c.result()


def encoding(narrow):
    c = Canvas(narrow, 1300 if narrow else 900)
    labels = {
        'input': ('Missing link: café.md', ('Diagnostic contains é',), 'process'),
        'memory': ('In-memory text stream', ('Unescaped JSON is accepted', 'No ASCII encoder tested'), 'result'),
        'process': ('Real process · ASCII', ('Unescaped JSON fails', 'UnicodeEncodeError'), 'process'),
        'escape': ('Correct JSON escaping', (r'Transport uses \u00e9', 'ASCII stdout can emit it'), 'process'),
        'test': ('Added subprocess test', ('Force ASCII stdout', 'Check status + decoded text'), 'process'),
        'consumer': ('Consumer decodes JSON', ('Original café.md preserved', 'No diagnostic text is lost'), 'result'),
    }
    if narrow:
        pos=dict(zip(labels,[(180,90),(180,300),(180,530),(180,760),(180,990),(180,1220)]))
        routes=[('input','memory','M 180,154 V 230'),
                ('input','process','M 326,90 H 344 V 530 H 326'),
                ('process','escape','M 180,594 V 690'),
                ('escape','consumer','M 34,760 H 16 V 1220 H 34'),
                ('test','consumer','M 180,1054 V 1150')]
        c.label('Verifies',220,1110)
    else:
        pos=dict(zip(labels,[(510,90),(270,320),(750,320),(750,550),(270,780),(750,780)]))
        routes=[('input','memory','M 510,154 V 205 H 270 V 250'),
                ('input','process','M 510,154 V 205 H 750 V 250'),
                ('process','escape','M 750,384 V 480'),
                ('escape','consumer','M 750,614 V 710'),
                ('test','consumer','M 410,780 H 604')]
        c.label('Verifies',510,755)
    for key,(title,detail,shape) in labels.items(): c.node(key,title,detail,*pos[key],shape=shape)
    for args in routes: c.edge(*args)
    return c.result()


def restore(narrow):
    c=Canvas(narrow,1230 if narrow else 740)
    labels={
        'previous': ('Previous values · 8080', ('Saved in a Python object', 'Not a backup file'), 'process'),
        'stage': ('Stage candidate · 8081', ('Write staged.json',), 'process'),
        'active': ('Apply candidate · 8081', ('Write active.json', 'Temporary local file only'), 'process'),
        'health': ('Simulated health fails', ('The fixture sets False', 'No service is contacted'), 'process'),
        'restore': ('Restore previous values', ('Serialize the saved object', 'Write active.json again'), 'process'),
        'verify': ('Read back and compare', ('Parsed JSON equals saved', 'Port is 8080 again'), 'result'),
    }
    if narrow:
        pos=dict(zip(labels,[(180,90),(180,300),(180,510),(180,720),(180,930),(180,1140)]))
        routes=[('previous','stage','M 180,154 V 230'),
                ('stage','active','M 180,364 V 440'),
                ('active','health','M 180,574 V 650'),
                ('health','restore','M 180,784 V 860'),
                ('previous','restore','M 34,90 H 16 V 930 H 34'),
                ('restore','verify','M 180,994 V 1070')]
    else:
        pos=dict(zip(labels,[(170,190),(510,90),(850,190),(850,440),(510,640),(170,640)]))
        routes=[('previous','stage','M 310,190 H 340 V 90 H 364'),
                ('stage','active','M 650,90 H 680 V 190 H 704'),
                ('active','health','M 850,254 V 370'),
                ('health','restore','M 850,504 V 550 H 555 V 570'),
                ('previous','restore','M 170,254 V 440 H 465 V 570'),
                ('restore','verify','M 370,640 H 316')]
        c.label('Use saved values',340,420)
    for key,(title,detail,shape) in labels.items(): c.node(key,title,detail,*pos[key],shape=shape)
    for args in routes: c.edge(*args)
    return c.result()


def render_example(kind, narrow):
    renderers={'example-retry':retry,'example-recovery':recovery,
               'example-migration':migration,'example-encoding':encoding,
               'example-restore':restore}
    return renderers[kind](narrow)
