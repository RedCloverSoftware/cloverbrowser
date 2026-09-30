"""Extract translatable strings (text domain 'cloverbrowser') from PHP + JS.
Returns entries: {key: {msgid, plural, ctx, comments, refs, js}} where key = ctx\x04msgid or msgid."""
import re, os, sys, json

FUNCS = {'__': 'S', '_e': 'S', 'esc_html__': 'S', 'esc_html_e': 'S', 'esc_attr__': 'S', 'esc_attr_e': 'S',
         '_x': 'X', 'esc_html_x': 'X', 'esc_attr_x': 'X', '_n': 'N', '_nx': 'NX'}
CALL = re.compile(r'(?<![\w$.>])(' + '|'.join(sorted(FUNCS, key=len, reverse=True)) + r')\s*\(')

def unq(lit):
    q = lit[0]; body = lit[1:-1]
    return re.sub(r'\\(.)', lambda m: m.group(1) if m.group(1) in (q, '\\') else '\\' + m.group(1), body)

def split_args(src, i):
    """src[i] is just after '('. Return (list of raw args, index after ')')."""
    args, depth, cur, j = [], 0, '', i
    while j < len(src):
        c = src[j]
        if c in '\'"':
            k = j + 1
            while src[k] != c:
                k += 2 if src[k] == '\\' else 1
            cur += src[j:k + 1]; j = k + 1; continue
        if src.startswith('/*', j):
            k = src.index('*/', j) + 2; j = k; continue
        if c in '([{': depth += 1
        elif c in ')]}':
            if depth == 0:
                args.append(cur.strip()); return args, j + 1
            depth -= 1
        elif c == ',' and depth == 0:
            args.append(cur.strip()); cur = ''; j += 1; continue
        cur += c; j += 1
    raise ValueError('unterminated call')

def lit(a):
    a = a.strip()
    if len(a) >= 2 and a[0] == a[-1] and a[0] in '\'"' and a.count(a[0]) - a.count('\\' + a[0]) == 2:
        return unq(a)
    return None

def extract(root):
    entries = {}
    for dp, _, fs in os.walk(root):
        if '/bin' in dp or '/languages' in dp: continue
        for f in sorted(fs):
            if not f.endswith(('.php', '.js')): continue
            path = os.path.join(dp, f); rel = os.path.relpath(path, root)
            src = open(path, encoding='utf-8').read()
            for m in CALL.finditer(src):
                kind = FUNCS[m.group(1)]
                args, _ = split_args(src, m.end())
                vals = [lit(a) for a in args]
                if kind == 'S': msgid, plural, ctx, dom = vals[0], None, None, vals[1] if len(vals) > 1 else None
                elif kind == 'X': msgid, plural, ctx, dom = vals[0], None, vals[1], vals[2] if len(vals) > 2 else None
                elif kind == 'N': msgid, plural, ctx, dom = vals[0], vals[1], None, vals[3] if len(vals) > 3 else None
                else: msgid, plural, ctx, dom = vals[0], vals[1], vals[3], vals[4] if len(vals) > 4 else None
                if dom != 'cloverbrowser':
                    raise SystemExit(f'{rel}: bad/missing text domain in {m.group(0)}{args}')
                if msgid is None or (kind in ('N', 'NX') and plural is None):
                    raise SystemExit(f'{rel}: non-literal msgid in {args}')
                line = src.count('\n', 0, m.start()) + 1
                # translator comment: nearest /* translators: ... */ within the preceding 300 chars
                before = src[max(0, m.start() - 300):m.start()]
                cm = list(re.finditer(r'/\*\s*translators:(.*?)\*/', before, re.S))
                comment = ' '.join(cm[-1].group(1).split()) if cm and before[cm[-1].end():].count('__(') + before[cm[-1].end():].count('_n(') == 0 else None
                key = (ctx + '\x04' if ctx else '') + msgid
                e = entries.setdefault(key, {'msgid': msgid, 'plural': plural, 'ctx': ctx, 'comments': set(), 'refs': [], 'js': False})
                if comment: e['comments'].add(comment)
                e['refs'].append(f'{rel}:{line}')
                if rel.endswith('.js'): e['js'] = True
    # Plugin header (shown on the Plugins screen)
    # Plugin Name is the brand "Cloverbrowser" and is intentionally not translated.
    with open(os.path.join(root, 'cloverbrowser.php'), encoding='utf-8') as fh:
        hm = re.search(r'^\s*\*\s*Description:\s*(.+?)\s*$', fh.read(), re.M)
    if hm:
        h = hm.group(1)
        entries.setdefault(h, {'msgid': h, 'plural': None, 'ctx': None, 'comments': {'Plugin header'}, 'refs': ['cloverbrowser.php'], 'js': False})
    return entries

if __name__ == '__main__':
    e = extract(sys.argv[1] if len(sys.argv) > 1 else '.')
    for k, v in e.items():
        print(json.dumps({'key': k, 'plural': v['plural'], 'js': v['js']}, ensure_ascii=False))
    print(len(e), 'entries', sum(1 for v in e.values() if v['plural']), 'plural', file=sys.stderr)
