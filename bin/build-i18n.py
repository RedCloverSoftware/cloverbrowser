#!/usr/bin/env python3
"""
Cloverbrowser translation build (developer tool — not loaded by WordPress).

    pip install polib
    python3 bin/build-i18n.py

1. Extracts every translatable string from the PHP + JS  -> languages/cloverbrowser.pot
2. Validates each languages/cloverbrowser-{locale}.po: no missing/stale strings,
   identical printf placeholders, correct number of plural forms.
3. Compiles  cloverbrowser-{locale}.mo                    (PHP, via load_textdomain)
   and       cloverbrowser-{locale}-{md5}.json            (JS, via wp_set_script_translations)
The .po files are the source of truth for translators.
"""
import hashlib, json, os, re, sys, datetime
import polib
sys.path.insert(0, os.path.dirname(__file__))
from extract import extract

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LANG = os.path.join(ROOT, 'languages')
DOMAIN = 'cloverbrowser'
# One JSON catalogue per script; the md5 of its path names the file (WordPress convention).
JS_FILES = ('assets/js/file-browser.js', 'assets/js/access-rules.js')

PLURALS = {
    'zh_CN': 'nplurals=1; plural=0;',
    'hi_IN': 'nplurals=2; plural=(n != 1);',
    'es_ES': 'nplurals=2; plural=(n != 1);',
    'ar':    'nplurals=6; plural=(n == 0) ? 0 : ((n == 1) ? 1 : ((n == 2) ? 2 : ((n % 100 >= 3 && n % 100 <= 10) ? 3 : ((n % 100 >= 11 && n % 100 <= 99) ? 4 : 5))));',
    'fr_FR': 'nplurals=2; plural=(n > 1);',
    'bn_BD': 'nplurals=2; plural=(n != 1);',
    'pt_BR': 'nplurals=2; plural=(n > 1);',
    'ru_RU': 'nplurals=3; plural=(n % 10 == 1 && n % 100 != 11) ? 0 : ((n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14)) ? 1 : 2);',
    'ur':    'nplurals=2; plural=(n != 1);',
}
PH = re.compile(r'%(?:\d+\$)?[sd%]')

def placeholders(s):
    """Multiset of placeholders; unnumbered ones compared by position."""
    return sorted(p for p in PH.findall(s) if p != '%%')

def key(e):
    return (e.msgctxt + '\x04' if e.msgctxt else '') + e.msgid

def header(locale=None):
    h = {
        'Project-Id-Version': 'Cloverbrowser',
        'POT-Creation-Date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M+0000'),
        'MIME-Version': '1.0',
        'Content-Type': 'text/plain; charset=UTF-8',
        'Content-Transfer-Encoding': '8bit',
        'X-Domain': DOMAIN,
    }
    if locale:
        h['Language'] = locale
        h['Plural-Forms'] = PLURALS[locale]
    return h

def build():
    entries = extract(ROOT)
    pot = polib.POFile(wrapwidth=0)
    pot.metadata = header()
    for k, e in entries.items():
        pot.append(polib.POEntry(
            msgid=e['msgid'], msgid_plural=e['plural'] or '', msgctxt=e['ctx'],
            msgstr='' if not e['plural'] else '', msgstr_plural={0: '', 1: ''} if e['plural'] else {},
            comment='translators: ' + ' / '.join(sorted(e['comments'])) if e['comments'] else '',
            occurrences=[tuple(r.split(':')) if ':' in r else (r, '') for r in e['refs']],
        ))
    pot.save(os.path.join(LANG, DOMAIN + '.pot'))

    errors = 0
    for locale, pf in PLURALS.items():
        path = os.path.join(LANG, f'{DOMAIN}-{locale}.po')
        if not os.path.exists(path):
            print('NO CATALOGUE', locale); errors += 1; continue
        po = polib.pofile(path, wrapwidth=0)
        nplurals = int(re.search(r'nplurals=(\d+)', pf).group(1))
        have = {key(e): e for e in po if not e.obsolete}
        for k, e in entries.items():
            t = have.get(k)
            label = f'{locale}: {k!r}'
            if t is None:
                print('MISSING', label); errors += 1; continue
            src_ph = placeholders(e['msgid'])
            if e['plural']:
                forms = [t.msgstr_plural.get(i, '') for i in range(nplurals)]
                if len(t.msgstr_plural) != nplurals or not all(forms):
                    print('PLURAL FORMS', label, len(t.msgstr_plural), 'expected', nplurals); errors += 1
                for f in forms:
                    # a form may drop the count only if the source has a single %s/%d (e.g. Arabic singular/dual)
                    if placeholders(f) != src_ph and not (len(src_ph) == 1 and placeholders(f) == []):
                        print('PLACEHOLDER', label, f); errors += 1
            else:
                if not t.msgstr:
                    print('EMPTY', label); errors += 1
                elif placeholders(t.msgstr) != src_ph:
                    print('PLACEHOLDER', label, repr(t.msgstr)); errors += 1
        stale = set(have) - set(entries)
        for k in stale:
            print('STALE (marking obsolete)', locale, repr(k)); have[k].obsolete = True
        # keep references/comments in sync with the code
        for k, e in entries.items():
            if k in have:
                have[k].occurrences = [tuple(r.split(':')) if ':' in r else (r, '') for r in e['refs']]
                have[k].comment = 'translators: ' + ' / '.join(sorted(e['comments'])) if e['comments'] else ''
                have[k].flags = [f for f in have[k].flags if f != 'fuzzy']
        po.metadata.update({'Language': locale, 'Plural-Forms': pf, 'X-Domain': DOMAIN,
                            'Content-Type': 'text/plain; charset=UTF-8'})
        po.save(path)
        po.save_as_mofile(os.path.join(LANG, f'{DOMAIN}-{locale}.mo'))

        # JS catalogues (Jed 1.x, as produced by `wp i18n make-json`), one per script
        counts = []
        for js_rel in JS_FILES:
            msgs = {'': {'domain': 'messages', 'lang': locale, 'plural-forms': pf}}
            for k, e in entries.items():
                t = have.get(k)
                if t is None or not any(r.split(':')[0] == js_rel for r in e['refs']):
                    continue
                msgs[k] = [t.msgstr_plural[i] for i in range(nplurals)] if e['plural'] else [t.msgstr]
            data = {
                'translation-revision-date': po.metadata.get('PO-Revision-Date', ''),
                'generator': 'cloverbrowser/bin/build-i18n.py',
                'source': js_rel,
                'domain': 'messages',
                'locale_data': {'messages': msgs},
            }
            js_md5 = hashlib.md5(js_rel.encode()).hexdigest()
            with open(os.path.join(LANG, f'{DOMAIN}-{locale}-{js_md5}.json'), 'w', encoding='utf-8') as fh:
                json.dump(data, fh, ensure_ascii=False, separators=(',', ':'))
            counts.append(f'{os.path.basename(js_rel)}={len(msgs) - 1}')
        print(f'{locale}: {len(entries)} strings; JS: ' + ', '.join(counts))
    if errors:
        sys.exit(f'{errors} problem(s)')

if __name__ == '__main__':
    build()
