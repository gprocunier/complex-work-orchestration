"""Palette-only SVG styles; embedded images inherit the page's color scheme.

Keep geometry, presentation attributes and embedded brand payloads intact.
CSS selectors change authored diagram paint, never raster/vector logo bytes.
"""
from __future__ import annotations

# The originals remain a useful fallback for renderers without media queries.
FLOW_DARK = {
    '#151515': '#edf2f9', '#fff': '#1b2d44', '#6a6e73': '#8b9db4',
    '#fff4e5': '#332a1c', '#8f5200': '#efb46f',
    '#a60000': '#ff8795', '#760000': '#ffb1ba',
}
ILLUSTRATION_LIGHT = {
    '#0e1828': '#f7f9fc', '#142338': '#ffffff', '#1b2d44': '#edf2f7',
    '#f2f5fb': '#172434', '#b6c3d6': '#45576f', '#3a506b': '#73859b',
    '#dc364d': '#b51b34', '#70b7f2': '#1767a6', '#5ad6c1': '#087463',
    '#efb46f': '#805000', '#a9253d': '#ffe8ed', '#ffd7dd': '#8a1730',
    '#ffe2e6': '#773344', '#101e30': '#eef3f8', '#57718f': '#617892',
    '#8c6a49': '#906329',
}


def svg_theme_style(kind: str) -> str:
    """Return deterministic, self-contained CSS for a known diagram family."""
    if kind == 'flow':
        scheme, palette = 'dark', FLOW_DARK
    elif kind == 'illustration':
        scheme, palette = 'light', ILLUSTRATION_LIGHT
    else:
        raise ValueError(f'Unknown diagram family: {kind}')
    rules = []
    for original, themed in palette.items():
        for prop in ('fill', 'stroke'):
            # Branch-label halos must match the dark page, not the card fill.
            color = '#111923' if kind == 'flow' and prop == 'stroke' and original == '#fff' else themed
            rules.append(f'    [{prop}="{original}"] {{ {prop}: {color}; }}')
    return ('<style id="diagram-theme">\n'
            '  /* Inherited color-scheme also follows an explicit page selection. */\n'
            f'  @media (prefers-color-scheme: {scheme}) {{\n' + '\n'.join(rules) +
            '\n  }\n</style>')
