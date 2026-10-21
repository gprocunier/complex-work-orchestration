"""Guide illustrations: shared meaning with separately routed narrow layouts.

These explain contracts; rendering one does not execute or qualify a route.
"""
from __future__ import annotations

from html import escape
import textwrap

GUIDE_KINDS = frozenset({'sharing-boundaries', 'scoped-work-graph',
    'source-count-groups', 'local-review', 'evidence-and-holds',
    'separate-reviews', 'hook-delivery', 'historical-contractors'})


class Canvas:
    def __init__(self, narrow, height):
        self.width, self.height = (360 if narrow else 1020), height
        self.parts = []

    def node(self, key, title, details, x, y, *, decision=False):
        w, h = 280, (180 if decision else 160)
        attrs = f'data-node="{key}" data-x="{x}" data-y="{y}" data-width="{w}" data-height="{h}"'
        if decision:
            shape = f'<polygon points="{x},{y-h/2} {x+w/2},{y} {x},{y+h/2} {x-w/2},{y}" fill="#fff4e5" stroke="#8f5200" stroke-width="2"/>'
        else:
            shape = f'<rect x="{x-w/2}" y="{y-h/2}" width="{w}" height="{h}" rx="12" fill="#fff" stroke="#6a6e73" stroke-width="2"/>'
        lines = [(s, True) for s in textwrap.wrap(title, 22)]
        lines += [(s, False) for detail in details for s in textwrap.wrap(detail, 26)]
        top = y - (len(lines)-1)*12
        labels = ''.join(f'<text x="{x}" y="{top+i*24}" text-anchor="middle" dominant-baseline="central" font-size="{20 if bold else 18}" font-weight="{600 if bold else 400}">{escape(line)}</text>' for i, (line, bold) in enumerate(lines))
        self.parts.append(f'<g {attrs}>{shape}{labels}</g>')

    def edge(self, source, target, path):
        self.parts.append(f'<path data-from="{source}" data-to="{target}" d="{path}" fill="none" stroke="#a60000" stroke-width="2.5" stroke-linejoin="round" marker-end="url(#arrow)"/>')

    def result(self):
        return self.width, self.height, ''.join(self.parts)


def draw(narrow, height, nodes, positions, routes, *, decisions=()):
    c = Canvas(narrow, height)
    # Edges first: labels/cards never disappear beneath a connector.
    for args in routes:
        c.edge(*args)
    for key, (title, details) in nodes.items():
        c.node(key, title, details, *positions[key], decision=key in decisions)
    return c.result()


def sharing(narrow):
    nodes = {
        'records': ('Project files + Beads', ('Saved locally', 'Not automatically private')),
        'client': ('Agent client + tools', ('Permissions control access', 'Selected context may leave')),
        'provider': ('Configured provider', ('Ordinary agent context', 'Check provider handling')),
        'outside': ('Additional reviewer', ('Extra opt-in required', 'Only approved material')),
        'local': ('Local/private endpoint', ('Separate opt-in + checks', 'Not an offline guarantee')),
    }
    if narrow:
        pos = dict(zip(nodes, [(180,100),(180,340),(180,600),(180,860),(180,1120)]))
        routes = [('records','client','M 180,180 V 254'),
                  ('client','provider','M 180,420 V 514'),
                  ('client','outside','M 320,340 H 344 V 860 H 326'),
                  ('client','local','M 40,340 H 16 V 1120 H 34')]
    else:
        pos = dict(zip(nodes, [(510,100),(510,340),(170,650),(510,650),(850,650)]))
        routes = [('records','client','M 510,180 V 254'),
                  ('client','provider','M 510,420 V 475 H 170 V 564'),
                  ('client','outside','M 510,420 V 564'),
                  ('client','local','M 510,420 V 475 H 850 V 564')]
    return draw(narrow, 1220 if narrow else 750, nodes, pos, routes)


def scoped(narrow):
    nodes = {
        'ended': ('Task A · attempt ended', ('Keep its failure evidence', 'Do not resume this attempt')),
        'inspect': ('Inspect what happened', ('Stop, resources, files, use', 'Keep failed / UNKNOWN facts')),
        'replacement': ('A distinct replacement', ('Only with new permission', 'and a fresh allowance')),
        'accepted': ('Task A accepted?', ('Verify the replacement', 'Do not assume acceptance')),
        'waiting': ('Task B · must wait', ('Depends on accepted A', 'Failure is not acceptance')),
        'dependent': ('Task B · may proceed', ('Only after A is accepted', 'and B passes its own checks')),
        'independent': ('Task C · independent', ('Does not need A’s result', 'Still check stop scope')),
        'checks': ('Check C’s own limits', ('Permission + prerequisites', 'Safety + shared capacity')),
        'continue': ('Task C · may proceed', ('Only if its checks pass', 'No automatic parent stop')),
    }
    if narrow:
        pos = dict(zip(nodes, [(180,100),(180,320),(180,540),(180,760),
            (180,1020),(180,1240),(180,1540),(180,1760),(180,1980)]))
        routes = [('ended','inspect','M 180,180 V 234'),
                  ('inspect','replacement','M 180,400 V 454'),
                  ('replacement','accepted','M 180,620 V 674'),
                  ('ended','waiting','M 320,100 H 344 V 1020 H 326'),
                  ('accepted','dependent','M 40,760 H 16 V 1240 H 34'),
                  ('waiting','dependent','M 180,1100 V 1154'),
                  ('independent','checks','M 180,1620 V 1674'),
                  ('checks','continue','M 180,1840 V 1894')]
    else:
        pos = dict(zip(nodes, [(170,100),(170,340),(170,580),(170,820),
            (510,340),(510,820),(850,100),(850,340),(850,580)]))
        routes = [('ended','inspect','M 170,180 V 254'),
                  ('inspect','replacement','M 170,420 V 494'),
                  ('replacement','accepted','M 170,660 V 734'),
                  ('ended','waiting','M 310,100 H 510 V 254'),
                  ('accepted','dependent','M 310,820 H 364'),
                  ('waiting','dependent','M 510,420 V 734'),
                  ('independent','checks','M 850,180 V 254'),
                  ('checks','continue','M 850,420 V 494')]
    return draw(narrow, 2080 if narrow else 920, nodes, pos, routes)


def groups(narrow):
    nodes = {
        'input': ('Check each input first', ('Use evaluated records', 'Not model-name counting')),
        'cloud': ('Provider A · one group', ('Two eligible model reviews', 'do not add a second group')),
        'local': ('Local aliases · one group', ('Eligible local/OpenShift', 'names share default group')),
        'count': ('Count eligible groups', ('Checked eligible records', 'Default minimum: two')),
        'compare': ('Invoke claim comparison', ('Only with required inputs', 'Agreement is not truth')),
        'excluded': ('Do not count these', ('Unknown / conflicting data', 'Unbound, held, non-primary')),
    }
    if narrow:
        pos = dict(zip(nodes, [(180,100),(180,340),(180,580),(180,820),(180,1060),(180,1300)]))
        routes = [('input','cloud','M 180,180 V 254'),
                  ('input','local','M 40,100 H 16 V 580 H 34'),
                  ('input','excluded','M 320,100 H 344 V 1300 H 326'),
                  ('cloud','count','M 320,340 H 332 V 700 H 220 V 734'),
                  ('local','count','M 180,660 V 734'),
                  ('count','compare','M 180,900 V 974')]
    else:
        pos = dict(zip(nodes, [(510,100),(170,340),(850,340),(510,590),(510,830),(170,830)]))
        routes = [('input','cloud','M 510,180 V 220 H 170 V 254'),
                  ('input','local','M 510,180 V 220 H 850 V 254'),
                  ('input','excluded','M 370,100 H 14 V 700 H 170 V 744'),
                  ('cloud','count','M 170,420 V 470 H 470 V 504'),
                  ('local','count','M 850,420 V 470 H 550 V 504'),
                  ('count','compare','M 510,670 V 744')]
    return draw(narrow, 1400 if narrow else 930, nodes, pos, routes)


def local_review(narrow):
    nodes = {
        'question': ('Approve question + route', ('Allowed material + endpoint', 'Explicit local opt-in')),
        'prepare': ('Prepare the request', ('Inspect profile + envelope', 'No model call')),
        'checks': ('Check before execution', ('Apply this profile’s checks', 'Proceed only if they pass')),
        'call': ('Make one approved call', ('Save actual dispatch JSON', 'Not just prepared input')),
        'answer': ('Check response usability', ('Keep the raw answer', 'Unusable is not success')),
        'mutation': ('Compare the workspace', ('Same attempt + saved report', 'Inspect unexpected changes')),
        'normalize': ('Package the answer', ('Raw answer + mutation report', 'Bundle is not evaluator input')),
        'evaluate': ('Evaluate original records', ('Raw answer + dispatch JSON', 'Matching mutation report')),
        'lead': ('Lead records decision', ('Evidence + required reviews', 'Only within granted scope')),
        'stop': ('Stop and investigate', ('Failed check, unusable reply', 'or unexpected mutation')),
    }
    if narrow:
        pos = {key:(180,100+i*240) for i,key in enumerate(nodes)}
        routes = [(a,b,f'M 180,{180+i*240} V {254+i*240}')
                  for i,(a,b) in enumerate(zip(list(nodes)[:8],list(nodes)[1:9]))]
        routes += [('checks','stop','M 320,580 H 344 V 2260 H 326'),
                   ('answer','stop','M 40,1060 H 16 V 2260 H 34'),
                   ('mutation','stop','M 320,1300 H 332 V 2160 H 220 V 2174')]
    else:
        pos = dict(zip(nodes, [(170,100),(510,100),(850,100),(850,350),(510,350),
            (170,350),(170,600),(510,600),(850,600),(510,860)]))
        routes = [('question','prepare','M 310,100 H 364'),
                  ('prepare','checks','M 650,100 H 704'),
                  ('checks','call','M 850,180 V 264'),
                  ('call','answer','M 710,350 H 656'),
                  ('answer','mutation','M 370,350 H 316'),
                  ('mutation','normalize','M 170,430 V 514'),
                  ('normalize','evaluate','M 310,600 H 364'),
                  ('evaluate','lead','M 650,600 H 704'),
                  ('checks','stop','M 990,100 H 1008 V 860 H 656'),
                  ('answer','stop','M 510,430 V 475 H 1008 V 860 H 656'),
                  ('mutation','stop','M 30,350 H 14 V 860 H 364')]
    return draw(narrow, 2360 if narrow else 960, nodes, pos, routes)


def holds(narrow):
    nodes = {
        'return': ('Check the returned answer', ('Evidence + allowed actions', 'Two separate results follow')),
        'evidence': ('1 · Evidence disposition', ('Usable, rejected or isolated', 'Record reasons + risks')),
        'review': ('2 · Required review status', ('Process / peer review', 'Pending or complete')),
        'both': ('Lead checks both results', ('Usable does not mean ready', 'Required review must finish')),
        'isolated': ('Keep unsafe evidence apart', ('Resolve boundaries first', 'Broader reuse is restricted')),
        'decision': ('Record permitted changes', ('Check evidence + authority', 'Do not implement held advice')),
    }
    if narrow:
        pos = dict(zip(nodes, [(180,100),(180,340),(180,860),(180,1120),(180,600),(180,1380)]))
        routes = [('return','evidence','M 180,180 V 254'),
                  ('return','review','M 320,100 H 344 V 860 H 326'),
                  ('evidence','both','M 40,340 H 16 V 1120 H 34'),
                  ('review','both','M 180,940 V 1034'),
                  ('evidence','isolated','M 180,420 V 514'),
                  ('both','decision','M 180,1200 V 1294')]
    else:
        pos = dict(zip(nodes, [(510,100),(170,350),(850,350),(510,610),(170,870),(510,870)]))
        routes = [('return','evidence','M 510,180 V 225 H 170 V 264'),
                  ('return','review','M 510,180 V 225 H 850 V 264'),
                  ('evidence','both','M 170,430 V 485 H 470 V 524'),
                  ('review','both','M 850,430 V 485 H 550 V 524'),
                  ('evidence','isolated','M 30,350 H 14 V 740 H 170 V 784'),
                  ('both','decision','M 510,690 V 784')]
    return draw(narrow, 1480 if narrow else 970, nodes, pos, routes)


def separate_reviews(narrow):
    nodes = {
        'plan': ('Lead prepares the plan', ('Scope + review questions', 'Approved material only')),
        'review-a': ('Reviewer A', ('Separate bounded assignment', 'Retain its original answer')),
        'evaluated-a': ('Check A’s return', ('Evidence, scope + holds', 'Retain its evaluation')),
        'review-b': ('Reviewer B', ('Separate bounded assignment', 'Retain its original answer')),
        'evaluated-b': ('Check B’s return', ('Evidence, scope + holds', 'Retain its evaluation')),
        'compare': ('Compare eligible findings', ('Agreement + disagreement', 'Keep excluded inputs apart')),
        'decision': ('One lead decides', ('Resolve material differences', 'Record what changes + why')),
    }
    if narrow:
        pos = {key:(180,100+i*240) for i,key in enumerate(nodes)}
        routes = [('plan','review-a','M 180,180 V 254'),
                  ('plan','review-b','M 320,100 H 344 V 820 H 326'),
                  ('review-a','evaluated-a','M 180,420 V 494'),
                  ('review-b','evaluated-b','M 180,900 V 974'),
                  ('evaluated-a','compare','M 40,580 H 16 V 1300 H 34'),
                  ('evaluated-b','compare','M 180,1140 V 1214'),
                  ('compare','decision','M 180,1380 V 1454')]
    else:
        pos = dict(zip(nodes, [(510,100),(170,340),(170,580),(850,340),(850,580),(510,820),(510,1060)]))
        routes = [('plan','review-a','M 510,180 V 220 H 170 V 254'),
                  ('plan','review-b','M 510,180 V 220 H 850 V 254'),
                  ('review-a','evaluated-a','M 170,420 V 494'),
                  ('review-b','evaluated-b','M 850,420 V 494'),
                  ('evaluated-a','compare','M 170,660 V 700 H 470 V 734'),
                  ('evaluated-b','compare','M 850,660 V 700 H 550 V 734'),
                  ('compare','decision','M 510,900 V 974')]
    return draw(narrow, 1640 if narrow else 1160, nodes, pos, routes)


def hooks(narrow):
    nodes = {
        'inspect': ('Inspect the installed client', ('Preview configuration first', 'Do not suppress context')),
        'support': ('Display hint?', ('Supported here?',)),
        'quiet': ('If supported · quiet option', ('Keep Beads command intact', 'Add presentation hint only')),
        'full': ('If unsupported · full text', ('Quiet attempt is rejected', 'Keep full-context display')),
        'delivery': ('Verify actual delivery', ('Host observes full context', 'Character count is not proof')),
        'adopt': ('Adopt only after proof', ('Full context still delivered', 'Check relevant lifecycle')),
        'fallback': ('If proof is missing or fails', ('Keep full-context display', 'Investigate before adoption')),
    }
    if narrow:
        pos = dict(zip(nodes, [(180,100),(180,360),(180,620),(180,860),(180,1120),(180,1380),(180,1640)]))
        routes = [('inspect','support','M 180,180 V 264'),
                  ('support','quiet','M 180,450 V 534'),
                  ('support','full','M 320,360 H 344 V 860 H 326'),
                  ('quiet','delivery','M 40,620 H 16 V 1120 H 34'),
                  ('delivery','adopt','M 180,1200 V 1294'),
                  ('delivery','fallback','M 320,1120 H 344 V 1640 H 326')]
    else:
        pos = dict(zip(nodes, [(510,100),(510,350),(170,610),(850,610),(170,870),(170,1130),(850,1130)]))
        routes = [('inspect','support','M 510,180 V 254'),
                  ('support','quiet','M 370,350 H 170 V 524'),
                  ('support','full','M 650,350 H 850 V 524'),
                  ('quiet','delivery','M 170,690 V 784'),
                  ('delivery','adopt','M 170,950 V 1044'),
                  ('delivery','fallback','M 310,870 H 850 V 1044')]
    return draw(narrow, 1740 if narrow else 1230, nodes, pos, routes, decisions=('support',))


def contractors(narrow):
    nodes = {
        'lead': ('Codex coordinates', ('Architecture + work graph', 'Limited scope per contractor')),
        'prepare': ('Prepare briefs + branches', ('Preparation is not a call', 'Historical assignments below')),
        'antigravity': ('Antigravity · documentation', ('Historical agy CLI work', 'Separate docs patch branch')),
        'claude': ('Claude Code · Pages', ('Historical claude CLI work', 'Separate Pages patch branch')),
        'integrate': ('Codex reviews + fixes', ('Fix attribution + paths', 'Prepare combined candidate')),
        'validate': ('Codex validates', ('Check the integrated result', 'Not contractor confidence')),
        'publication': ('Merge + publication', ('Historical Codex decision', 'No new permission implied')),
    }
    if narrow:
        pos = {key:(180,100+i*240) for i,key in enumerate(nodes)}
        routes = [('lead','prepare','M 180,180 V 254'),
                  ('prepare','antigravity','M 180,420 V 494'),
                  ('prepare','claude','M 320,340 H 344 V 820 H 326'),
                  ('antigravity','integrate','M 40,580 H 16 V 1060 H 34'),
                  ('claude','integrate','M 180,900 V 974'),
                  ('integrate','validate','M 180,1140 V 1214'),
                  ('validate','publication','M 180,1380 V 1454')]
    else:
        pos = dict(zip(nodes, [(510,100),(510,340),(170,580),(850,580),(510,820),(510,1060),(510,1300)]))
        routes = [('lead','prepare','M 510,180 V 254'),
                  ('prepare','antigravity','M 510,420 V 460 H 170 V 494'),
                  ('prepare','claude','M 510,420 V 460 H 850 V 494'),
                  ('antigravity','integrate','M 170,660 V 700 H 470 V 734'),
                  ('claude','integrate','M 850,660 V 700 H 550 V 734'),
                  ('integrate','validate','M 510,900 V 974'),
                  ('validate','publication','M 510,1140 V 1214')]
    return draw(narrow, 1640 if narrow else 1400, nodes, pos, routes)


def render_guide(kind, narrow=False):
    return {'sharing-boundaries':sharing, 'scoped-work-graph':scoped,
            'source-count-groups':groups, 'local-review':local_review,
            'evidence-and-holds':holds, 'separate-reviews':separate_reviews,
            'hook-delivery':hooks, 'historical-contractors':contractors}[kind](narrow)
