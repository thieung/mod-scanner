#!/usr/bin/env python3
"""Mark translatable text in the pages and regenerate the Vietnamese table in public/i18n.js.

Each English string in landing_strings.py is wrapped, wherever it is the whole text of
an element, in <span data-i18n="key">. Running it again changes nothing.
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).parent))
from importlib import import_module
strings = import_module('landing_strings')


def wrap(path, table):
    html = path.read_text(encoding='utf-8')
    missing = []
    for key, en, _ in sorted(table, key=lambda row: -len(row[1])):
        pattern = re.compile(r'(?<=>)' + re.escape(en) + r'(?=\s*<)')
        wrapped = f'<span data-i18n="{key}">'
        count = 0

        def repl(match):
            nonlocal count
            count += 1
            if html[: match.start()].endswith(wrapped):
                return match.group(0)
            return f'{wrapped}{en}</span>'

        html = pattern.sub(repl, html)
        if count == 0:
            missing.append(key)
    path.write_text(html, encoding='utf-8')
    return missing


missing = wrap(ROOT / 'public/index.html', strings.LANDING) + wrap(ROOT / 'public/scan.html', strings.SCAN)
if missing:
    sys.exit(f'not found in the pages: {", ".join(missing)}')

vi = {key: text for key, _, text in strings.LANDING + strings.SCAN}
js = (ROOT / 'public/i18n.js').read_text(encoding='utf-8')
start, end = '// <vi>', '// </vi>'
block = f'{start}\nconst VI = {json.dumps(vi, ensure_ascii=False, indent=2)}\n{end}'
js = re.sub(re.escape(start) + r'.*?' + re.escape(end), lambda _: block, js, flags=re.S)
(ROOT / 'public/i18n.js').write_text(js, encoding='utf-8')
print(f'{len(vi)} strings')
