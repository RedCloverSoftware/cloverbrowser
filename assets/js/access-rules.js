/**
 * Cloverbrowser — Settings screen (administrators only): access rules and trash.
 *
 * Same hardening as the browser: config pulled out of window/DOM, nonce kept
 * in this closure, native fetch/FormData/JSON captured, every state-changing
 * action requires a trusted user gesture, and all text goes into the DOM via
 * textContent (role names, paths and patterns are never parsed as HTML).
 * The server re-validates everything; this UI only prepares a draft.
 */
(function () {
    'use strict';

    const RAW = window.CloverbrowserConfig;
    const ROOT = document.getElementById('cloverbrowser-settings-root');
    if (!RAW || !ROOT) return;
    try { delete window.CloverbrowserConfig; } catch (e) { window.CloverbrowserConfig = undefined; }
    const cfgScript = document.getElementById('cloverbrowser-settings-js-before');
    if (cfgScript) cfgScript.remove();
    const CFG = Object.freeze(Object.assign({}, RAW));
    let NONCE = String(CFG.nonce || '');
    const NATIVE = Object.freeze({ fetch: window.fetch.bind(window), FormData: window.FormData, parse: JSON.parse, stringify: JSON.stringify });
    const { __, _n, sprintf } = window.wp.i18n;
    const trusted = (ev) => !!(ev && ev.isTrusted);

    const PERMS = ['view', 'download', 'edit', 'create', 'upload', 'rename', 'delete', 'chmod'];
    const WRITE_PERMS = ['edit', 'create', 'upload', 'rename', 'delete', 'chmod'];
    const UNITS = [['KB', 1024], ['MB', 1048576], ['GB', 1073741824]];

    /* ------------------------------------------------------------------ */
    /* Tiny DOM helper — text only; icons are static trusted SVG strings  */
    /* ------------------------------------------------------------------ */

    function h(tag, props, ...kids) {
        const el = document.createElement(tag);
        const p = props || {};
        if (p.class) el.className = p.class;
        if (p.text !== undefined) el.textContent = p.text;
        if (p.icon) el.insertAdjacentHTML('afterbegin', p.icon); // static constants only
        if (p.attrs) for (const [k, v] of Object.entries(p.attrs)) if (v !== false && v !== null && v !== undefined) el.setAttribute(k, v === true ? '' : String(v));
        if (p.props) Object.assign(el, p.props);
        if (p.on) for (const [k, fn] of Object.entries(p.on)) el.addEventListener(k, fn);
        for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
        return el;
    }

    const svg = (paths) => '<svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + paths + '</svg>';
    const ICONS = {
        globe: svg('<circle cx="8" cy="8" r="6.2"/><path d="M1.8 8h12.4M8 1.8c1.8 2 2.6 4 2.6 6.2S9.8 12.2 8 14.2C6.2 12.2 5.4 10.2 5.4 8S6.2 3.8 8 1.8z"/>'),
        user: svg('<circle cx="8" cy="5.5" r="2.7"/><path d="M2.8 14c.6-2.8 2.7-4.3 5.2-4.3s4.6 1.5 5.2 4.3"/>'),
        folder: svg('<path d="M1.8 4.2 3 3h3l1.2 1.5H14a.8.8 0 0 1 .8.8v7a.8.8 0 0 1-.8.8H2.6a.8.8 0 0 1-.8-.8V4.2z" fill="currentColor" stroke="none"/>'),
        trash: svg('<path d="M3 4.5h10"/><path d="M5 4.5V3h6v1.5"/><path d="M4.5 4.5 5.2 13h5.6l.7-8.5"/>'),
        plus: svg('<path d="M8 3v10M3 8h10"/>'),
        lock: svg('<rect x="3.5" y="7" width="9" height="7" rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>'),
        warn: svg('<path d="M8 2 14.5 13.5h-13z"/><path d="M8 6.5v3.2M8 11.6v.2"/>'),
        check: svg('<path d="m3 8.5 3.2 3L13 4.5"/>'),
        cross: svg('<path d="m4 4 8 8M12 4l-8 8"/>'),
        back: svg('<path d="M13 8H3"/><path d="m7 4-4 4 4 4"/>'),
        up: svg('<path d="M8 13V3"/><path d="m4 7 4-4 4 4"/>'),
        shield: svg('<path d="M8 1.8 13 4v4c0 3.2-2.1 5.5-5 7-2.9-1.5-5-3.8-5-7V4z"/>'),
        info: svg('<circle cx="8" cy="8" r="6.2"/><path d="M8 7.2v4M8 4.9v.2"/>'),
    };

    /* ------------------------------------------------------------------ */
    /* API                                                                */
    /* ------------------------------------------------------------------ */

    async function api(action, data) {
        const fd = new NATIVE.FormData();
        for (const [k, v] of Object.entries(data || {})) fd.append(k, String(v));
        fd.append('action', 'cloverbrowser_' + action);
        fd.append('nonce', NONCE);
        let res;
        try {
            res = await NATIVE.fetch(CFG.ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin', cache: 'no-store' });
        } catch (e) {
            throw new Error(__('Network error — the server may be busy or unreachable.', 'cloverbrowser'));
        }
        let json = null;
        try { json = NATIVE.parse(await res.text()); } catch (e) { /* not JSON */ }
        if (!json || typeof json !== 'object') {
            throw new Error(sprintf(
                /* translators: %d: HTTP status code */
                __('Unexpected server response (HTTP %d).', 'cloverbrowser'), res.status));
        }
        if (!json.success) throw new Error((json.data && json.data.message) || __('Request failed.', 'cloverbrowser'));
        return json.data || {};
    }
    setInterval(() => { api('nonce').then((d) => { if (d && typeof d.nonce === 'string') NONCE = d.nonce; }).catch(() => {}); }, 20 * 60 * 1000);

    /* ------------------------------------------------------------------ */
    /* State                                                              */
    /* ------------------------------------------------------------------ */

    const clone = (o) => NATIVE.parse(NATIVE.stringify(o));
    const S = {
        meta: null,        // roles, types, builtin, writeLocked
        draft: null,       // editable copy of the settings
        savedJson: '',
        sel: 'global',     // 'global' | role key
        warnings: [],
        saving: false,
        tab: location.hash === '#trash' ? 'trash' : 'access',
        trash: null,       // editable trash settings
        trashSaved: '',
        trashInfo: null,   // location, counts
    };

    function defaultRoleSet() {
        return {
            enabled: false,
            perms: { view: true, download: true, edit: false, create: false, upload: false, rename: false, delete: false, chmod: false },
            paths: [], types: [], rules: [], max_upload: 0, max_growth: 0,
        };
    }
    const roleSet = (key) => {
        if (!S.draft.roles[key]) S.draft.roles[key] = defaultRoleSet();
        return S.draft.roles[key];
    };
    const current = () => (S.sel === 'global' ? S.draft.global : roleSet(S.sel));
    const policyDirty = () => NATIVE.stringify(S.draft) !== S.savedJson;
    const trashDirty = () => !!S.trash && NATIVE.stringify(S.trash) !== S.trashSaved;
    const isDirty = () => policyDirty() || trashDirty();
    const roleMeta = (key) => S.meta.roles.find((r) => r.key === key);

    function changed() {
        els.dirty.hidden = !isDirty();
        els.save.disabled = S.saving || !isDirty();
        els.discard.disabled = S.saving || !isDirty();
        renderNav();
        renderLive();
        renderTrashLive();
    }

    /* ------------------------------------------------------------------ */
    /* Texts                                                              */
    /* ------------------------------------------------------------------ */

    const PERM_TEXT = {
        view: [__('Open files', 'cloverbrowser'), __('Read file contents in the viewer. Folders can always be browsed once access is enabled.', 'cloverbrowser')],
        download: [__('Download files', 'cloverbrowser'), __('Save copies of files to their computer.', 'cloverbrowser')],
        edit: [__('Edit & save files', 'cloverbrowser'), __('Change file contents in the editor (includes autosaved drafts and line-ending conversion).', 'cloverbrowser')],
        create: [__('Create files & folders', 'cloverbrowser'), __('Make new empty files and folders.', 'cloverbrowser')],
        upload: [__('Upload files', 'cloverbrowser'), __('Add files from their computer, and replace existing ones they may edit.', 'cloverbrowser')],
        rename: [__('Rename & move', 'cloverbrowser'), __('Rename files and folders within the folders they can access.', 'cloverbrowser')],
        delete: [__('Delete', 'cloverbrowser'), __('Remove files and folders, including everything inside a folder.', 'cloverbrowser')],
        chmod: [__('Change permissions', 'cloverbrowser'), __('Change Unix file modes (chmod). Rarely needed — keep off unless required.', 'cloverbrowser')],
    };
    const TYPE_DESC = {
        php: __('PHP files and any file containing PHP tags — even hidden inside an image. Anyone who can write PHP can take over the site.', 'cloverbrowser'),
        server_config: __('.htaccess, .user.ini, php.ini, web.config and .env files — they change how the server runs code or hold secrets.', 'cloverbrowser'),
        executable: __('Programs and scripts: binary executables, shell/Python/Perl scripts and anything starting with “#!”.', 'cloverbrowser'),
        web_active: __('HTML, SVG, JavaScript and XML — they can run scripts in visitors’ browsers.', 'cloverbrowser'),
        archive: __('ZIP, GZIP, TAR, 7-Zip, RAR and similar archives.', 'cloverbrowser'),
        image: __('JPEG, PNG, GIF, WebP, AVIF, TIFF and other images.', 'cloverbrowser'),
        media: __('MP3, MP4, WebM, WAV, OGG and other audio and video.', 'cloverbrowser'),
        document: __('PDF, Word, Excel, PowerPoint, OpenDocument and RTF.', 'cloverbrowser'),
        database: __('SQLite databases, SQL dumps and .bak backups — they often contain passwords.', 'cloverbrowser'),
        binary: __('Anything that is not plain text and not covered above.', 'cloverbrowser'),
    };
    const MATCH_TEXT = {
        contains: [__('Name contains', 'cloverbrowser'), __('secret', 'cloverbrowser'), __('Any file or folder whose name contains this text, in any folder. Not case-sensitive.', 'cloverbrowser')],
        name: [__('Name matches', 'cloverbrowser'), '*.bak', __('A name pattern: * matches any characters, ? matches one. Example: *.bak or wp-config*.', 'cloverbrowser')],
        path: [__('Exact path', 'cloverbrowser'), 'wp-content/debug.log', __('One specific file or folder, relative to the site root.', 'cloverbrowser')],
        tree: [__('Folder and contents', 'cloverbrowser'), 'wp-content/mu-plugins', __('A folder and everything inside it, relative to the site root.', 'cloverbrowser')],
    };
    const EFFECT_TEXT = {
        hide: __('Hidden & blocked', 'cloverbrowser'),
        readonly: __('Read-only', 'cloverbrowser'),
    };

    /* ------------------------------------------------------------------ */
    /* Toasts & modal (self-contained)                                    */
    /* ------------------------------------------------------------------ */

    const toastsEl = h('div', { class: 'fbx-toasts', attrs: { 'aria-live': 'polite' } });
    function toast(msg, kind, ms) {
        while (toastsEl.children.length >= 4) toastsEl.firstElementChild.remove();
        const t = h('div', { class: 'fbx-toast fbx-toast--' + (kind || 'info'), text: msg, attrs: { role: kind === 'error' ? 'alert' : 'status' } });
        toastsEl.append(t);
        const timer = setTimeout(() => t.remove(), ms || 4200);
        t.addEventListener('click', () => { clearTimeout(timer); t.remove(); });
    }

    const modalLayer = h('div', { class: 'fbx-modal-layer' });
    document.body.append(modalLayer);
    let closeModal = null;
    function modal(title, body, actions, wide) {
        if (closeModal) closeModal(null);
        return new Promise((resolve) => {
            const last = document.activeElement;
            const finish = (v) => {
                closeModal = null;
                document.removeEventListener('keydown', onKey, true);
                modalLayer.classList.remove('is-open');
                modalLayer.replaceChildren();
                resolve(v);
                if (last && last.isConnected) try { last.focus(); } catch (e) { /* noop */ }
            };
            const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); finish(null); } };
            const bar = h('div', { class: 'fbx-modal-actions' }, actions.map((a) => h('button', {
                class: 'fbx-btn' + (a.kind ? ' fbx-btn--' + a.kind : ''), text: a.label, attrs: { type: 'button' },
                on: { click: (ev) => { if (!trusted(ev)) return; const v = a.resolve ? a.resolve() : a.value; if (v !== undefined) finish(v); } },
            })));
            const panel = h('div', { class: 'fbx-modal' + (wide ? ' fba-modal-wide' : ''), attrs: { role: 'dialog', 'aria-modal': 'true', 'aria-label': title } },
                h('h3', { text: title }), h('div', { class: 'fbx-modal-body' }, body), bar);
            closeModal = finish;
            modalLayer.replaceChildren(panel);
            modalLayer.classList.add('is-open');
            document.addEventListener('keydown', onKey, true);
            modalLayer.onmousedown = (e) => { if (e.target === modalLayer) finish(null); };
            const f = panel.querySelector('input, select, button');
            if (f) f.focus();
        });
    }

    /* ------------------------------------------------------------------ */
    /* Folder picker (administrators browse without restrictions)         */
    /* ------------------------------------------------------------------ */

    async function pickFolder(startRel) {
        let cwd = '';
        const crumb = h('div', { class: 'fba-picker-crumb' });
        const list = h('div', { class: 'fba-picker-list', attrs: { role: 'listbox', 'aria-label': __('Folders', 'cloverbrowser') } });
        const chosen = h('code', { class: 'fba-picker-chosen' });
        const load = async (rel) => {
            list.replaceChildren(h('div', { class: 'fba-muted', text: __('Loading…', 'cloverbrowser') }));
            try {
                const d = await api('list', { path: rel });
                cwd = d.path || '';
                chosen.textContent = cwd === '' ? '/' : cwd;
                crumb.replaceChildren();
                const segs = cwd ? cwd.split('/') : [];
                crumb.append(h('button', { class: 'fba-link', text: CFG.rootLabel || '/', attrs: { type: 'button' }, on: { click: () => load('') } }));
                let acc = '';
                segs.forEach((seg) => {
                    acc = acc ? acc + '/' + seg : seg;
                    const target = acc;
                    crumb.append(' / ', h('button', { class: 'fba-link', text: seg, attrs: { type: 'button' }, on: { click: () => load(target) } }));
                });
                const dirs = (d.entries || []).filter((e) => e.is_dir).sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
                list.replaceChildren();
                if (cwd !== '') {
                    list.append(h('button', { class: 'fba-picker-item', icon: ICONS.up, attrs: { type: 'button' }, on: { click: () => load(cwd.includes('/') ? cwd.slice(0, cwd.lastIndexOf('/')) : '') } }, h('span', { text: '..' })));
                }
                dirs.forEach((e) => list.append(h('button', {
                    class: 'fba-picker-item', icon: ICONS.folder, attrs: { type: 'button', role: 'option' },
                    on: { click: () => load(e.rel) },
                }, h('span', { text: e.name }))));
                if (!dirs.length) list.append(h('div', { class: 'fba-muted', text: __('No subfolders.', 'cloverbrowser') }));
            } catch (e) {
                list.replaceChildren(h('div', { class: 'fba-error', text: e.message }));
            }
        };
        load(startRel || '');
        const body = h('div', { class: 'fba-picker' }, crumb, list, h('p', { class: 'fba-muted' }, __('Selected folder:', 'cloverbrowser'), ' ', chosen));
        return modal(__('Choose a folder', 'cloverbrowser'), body, [
            { label: __('Cancel', 'cloverbrowser'), value: null },
            { label: __('Use this folder', 'cloverbrowser'), kind: 'primary', resolve: () => (cwd === '' ? undefined : cwd) },
        ], true);
    }

    /* ------------------------------------------------------------------ */
    /* Layout                                                             */
    /* ------------------------------------------------------------------ */

    const els = {};
    function buildShell() {
        els.save = h('button', { class: 'fbx-btn fbx-btn--primary', text: __('Save changes', 'cloverbrowser'), attrs: { type: 'button', disabled: true }, on: { click: onSave } });
        els.discard = h('button', { class: 'fbx-btn', text: __('Discard', 'cloverbrowser'), attrs: { type: 'button', disabled: true }, on: { click: onDiscard } });
        els.dirty = h('span', { class: 'fbx-chip fbx-chip--warn', text: __('Unsaved changes', 'cloverbrowser'), attrs: { hidden: true } });
        els.nav = h('nav', { class: 'fba-nav', attrs: { 'aria-label': __('Roles', 'cloverbrowser') } });
        els.panel = h('div', { class: 'fba-panel' });
        els.notices = h('div', { class: 'fba-notices' });
        els.live = h('div', { class: 'fba-live' });
        const logo = h('span', { class: 'fbx-logo', attrs: { role: 'img', 'aria-label': 'Cloverbrowser' } });
        logo.innerHTML = LOGO; // static constant
        const tab = (key, label) => h('button', {
            class: 'fba-tab', text: label,
            attrs: { type: 'button', role: 'tab', id: 'fba-tab-' + key, 'aria-controls': 'fba-view-' + key },
            on: {
                click: () => setTab(key),
                keydown: (e) => {
                    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
                    e.preventDefault();
                    setTab(key === 'access' ? 'trash' : 'access');
                    els.tabs[S.tab].focus();
                },
            },
        });
        els.tabs = { access: tab('access', __('Access rules', 'cloverbrowser')), trash: tab('trash', __('Trash', 'cloverbrowser')) };
        els.accessView = h('div', { class: 'fba-view', attrs: { id: 'fba-view-access', role: 'tabpanel', 'aria-labelledby': 'fba-tab-access' } },
            h('div', { class: 'fba-intro' },
                h('p', { text: __('Administrators always have full access and are not affected by these rules. Every other role has no access until you enable it.', 'cloverbrowser') }),
                h('p', { text: __('The “All roles” rules apply to every enabled role. A role’s own rules can only add restrictions on top of them.', 'cloverbrowser') }),
                S.meta.writeLocked ? h('p', { class: 'fba-warnline', icon: ICONS.warn }, h('span', { text: __('File editing is disabled for this site (DISALLOW_FILE_EDIT / CLOVERBROWSER_READ_ONLY), so every role is read-only whatever you allow here.', 'cloverbrowser') })) : null),
            els.notices,
            h('div', { class: 'fba-main' }, els.nav, h('div', { class: 'fba-content' }, els.live, els.panel, buildTester())));
        els.trashView = h('div', { class: 'fba-view fba-trash-view', attrs: { id: 'fba-view-trash', role: 'tabpanel', 'aria-labelledby': 'fba-tab-trash' } });
        ROOT.replaceChildren(h('div', { class: 'fbx fba' },
            h('div', { class: 'fbx-statusbar fba-head' },
                logo,
                h('h2', { class: 'fba-title', text: __('Settings', 'cloverbrowser') }),
                h('div', { class: 'fba-tabs', attrs: { role: 'tablist', 'aria-label': __('Settings', 'cloverbrowser') } }, els.tabs.access, els.tabs.trash),
                h('span', { class: 'fbx-status-end' }, els.dirty, els.discard, els.save)),
            els.accessView,
            els.trashView,
            toastsEl));
        setTab(S.tab);
    }

    function setTab(key) {
        S.tab = key === 'trash' ? 'trash' : 'access';
        for (const k of ['access', 'trash']) {
            const on = S.tab === k;
            els.tabs[k].classList.toggle('is-active', on);
            els.tabs[k].setAttribute('aria-selected', on ? 'true' : 'false');
            els.tabs[k].tabIndex = on ? 0 : -1;
        }
        els.accessView.hidden = S.tab !== 'access';
        els.trashView.hidden = S.tab !== 'trash';
        try { history.replaceState(null, '', S.tab === 'trash' ? '#trash' : location.pathname + location.search); } catch (e) { /* noop */ }
    }

    function roleStatus(key) {
        const set = S.draft.roles[key];
        if (!set || !set.enabled) return ['off', __('No access', 'cloverbrowser')];
        const g = S.draft.global.perms;
        const eff = (p) => set.perms[p] && g[p];
        const writes = WRITE_PERMS.filter(eff).length;
        if (!eff('view') && !eff('download') && !writes) return ['off', __('Browse only', 'cloverbrowser')];
        if (!writes) return ['ro', __('Read-only', 'cloverbrowser')];
        if (writes === WRITE_PERMS.filter((p) => g[p]).length && eff('view') && eff('download')) return ['full', __('Full', 'cloverbrowser')];
        return ['custom', __('Custom', 'cloverbrowser')];
    }

    function renderNav() {
        const item = (key, icon, label, sub, pill) => h('button', {
            class: 'fba-nav-item' + (S.sel === key ? ' is-active' : ''),
            attrs: { type: 'button', 'aria-current': S.sel === key ? 'page' : false },
            on: { click: () => { S.sel = key; renderNav(); renderPanel(); renderLive(); } },
        }, h('span', { class: 'fba-nav-ico', icon }), h('span', { class: 'fba-nav-text' }, h('strong', { text: label }), sub ? h('small', { text: sub }) : null), pill);
        els.nav.replaceChildren(
            item('global', ICONS.globe, __('All roles', 'cloverbrowser'), __('Applies to every enabled role', 'cloverbrowser'), null),
            h('div', { class: 'fba-nav-sep', text: __('Roles', 'cloverbrowser') }),
            ...S.meta.roles.map((r) => {
                const [k, t] = roleStatus(r.key);
                return item(r.key, ICONS.user, r.label, sprintf(
                    /* translators: %s: number of users */
                    _n('%s user', '%s users', r.users, 'cloverbrowser'), r.users), h('span', { class: 'fba-pill fba-pill--' + k, text: t }));
            }),
            h('p', { class: 'fba-nav-note', text: __('Administrators are not listed: they always have full access.', 'cloverbrowser') }),
        );
    }

    /** Warnings that follow the draft live (the server repeats its own on save). */
    function renderLive() {
        const out = [];
        const g = S.draft.global;
        for (const r of S.meta.roles) {
            const set = S.draft.roles[r.key];
            if (!set || !set.enabled) continue;
            const writesCode = !g.types.includes('php') && !set.types.includes('php')
                && ['edit', 'upload', 'create', 'rename'].some((p) => set.perms[p] && g.perms[p]);
            if (writesCode) {
                out.push(sprintf(
                    /* translators: %s: role name */
                    __('%s can create or modify PHP code. Anyone who can write PHP can take over the whole site — block the “PHP code” type unless that is intended.', 'cloverbrowser'), r.label));
            }
            if (r.lowTrust) {
                out.push(sprintf(
                    /* translators: %s: role name */
                    __('%s is normally given to untrusted accounts. Make sure you really want it to reach server files.', 'cloverbrowser'), r.label));
            }
        }
        els.live.replaceChildren(...out.map((w) => h('div', { class: 'fba-warnline', icon: ICONS.warn }, h('span', { text: w }))));
    }

    function section(title, intro, ...content) {
        return h('section', { class: 'fba-section' }, h('h3', { text: title }), intro ? h('p', { class: 'fba-muted', text: intro }) : null, ...content);
    }

    function toggle(checked, disabled, onChange, labelText, desc, extra) {
        const input = h('input', { attrs: { type: 'checkbox', role: 'switch' }, props: { checked: !!checked, disabled: !!disabled }, on: { change: (e) => onChange(e.target.checked) } });
        return h('label', { class: 'fba-toggle' + (disabled ? ' is-disabled' : '') }, input, h('span', { class: 'fba-switch', attrs: { 'aria-hidden': 'true' } }),
            h('span', { class: 'fba-toggle-text' }, h('strong', { text: labelText }), desc ? h('small', { text: desc }) : null, extra || null));
    }

    function renderPanel() {
        const isGlobal = S.sel === 'global';
        const set = current();
        const g = S.draft.global;
        const meta = isGlobal ? null : roleMeta(S.sel);
        const parts = [];

        parts.push(h('div', { class: 'fba-panel-head' },
            h('h2', { text: isGlobal ? __('All roles', 'cloverbrowser') : meta.label }),
            h('p', { class: 'fba-muted', text: isGlobal
                ? __('Baseline rules for every non-administrator role that has access. Roles can be restricted further on their own pages.', 'cloverbrowser')
                : __('Rules for this role. They add to the “All roles” rules — they can never grant more than those allow.', 'cloverbrowser') })));

        // --- Access switch
        if (!isGlobal) {
            parts.push(section(__('Access', 'cloverbrowser'), null,
                toggle(set.enabled, false, (v) => { set.enabled = v; renderPanel(); changed(); },
                    sprintf(
                        /* translators: %s: role name */
                        __('Allow %s users to use Cloverbrowser', 'cloverbrowser'), meta.label),
                    __('When off, users with this role do not see Cloverbrowser at all.', 'cloverbrowser'))));
        }
        const body = h('div', { class: 'fba-body' + (!isGlobal && !set.enabled ? ' is-dimmed' : '') });
        if (!isGlobal && !set.enabled) {
            body.append(h('p', { class: 'fba-muted fba-dim-note', text: __('Access is off — you can still prepare these rules; they apply once access is enabled.', 'cloverbrowser') }));
        }

        // --- Permissions
        const presets = [
            [__('View only', 'cloverbrowser'), ['view']],
            [__('View & download', 'cloverbrowser'), ['view', 'download']],
            [__('Edit files', 'cloverbrowser'), ['view', 'download', 'edit', 'create', 'upload', 'rename']],
            [__('Everything', 'cloverbrowser'), PERMS],
        ];
        const presetBar = h('div', { class: 'fba-presets', attrs: { role: 'group', 'aria-label': __('Presets', 'cloverbrowser') } },
            h('span', { class: 'fba-muted', text: __('Presets:', 'cloverbrowser') }),
            presets.map(([label, list]) => h('button', {
                class: 'fbx-btn fbx-btn--sm', text: label, attrs: { type: 'button' },
                on: { click: () => { PERMS.forEach((p) => { set.perms[p] = list.includes(p); }); renderPanel(); changed(); } },
            })));
        const grid = h('div', { class: 'fba-perm-grid' }, PERMS.map((p) => {
            const blockedByGlobal = !isGlobal && !g.perms[p];
            return toggle(set.perms[p] && !blockedByGlobal, blockedByGlobal, (v) => { set.perms[p] = v; changed(); },
                PERM_TEXT[p][0], PERM_TEXT[p][1],
                blockedByGlobal ? h('em', { class: 'fba-tag', text: __('Not allowed for any role (All roles)', 'cloverbrowser') }) : null);
        }));
        body.append(section(__('What they can do', 'cloverbrowser'), null, presetBar, grid));

        // --- Folders
        const pathList = h('ul', { class: 'fba-paths' });
        const renderPaths = () => {
            pathList.replaceChildren();
            if (!set.paths.length) {
                pathList.append(h('li', { class: 'fba-empty', text: isGlobal
                    ? __('No folder limit: the whole site folder is reachable (minus protected items).', 'cloverbrowser')
                    : (g.paths.length ? __('No extra limit: the “All roles” folders apply.', 'cloverbrowser') : __('No folder limit: the whole site folder is reachable (minus protected items).', 'cloverbrowser')) }));
            }
            set.paths.forEach((p, i) => pathList.append(h('li', { class: 'fba-path' },
                h('span', { class: 'fba-path-ico', icon: ICONS.folder }), h('code', { text: p }),
                h('button', { class: 'fbx-btn fbx-btn--ghost fbx-btn--icon fbx-btn--sm', icon: ICONS.trash, attrs: { type: 'button', title: __('Remove', 'cloverbrowser'), 'aria-label': sprintf(
                    /* translators: %s: folder path */
                    __('Remove %s', 'cloverbrowser'), p) }, on: { click: () => { set.paths.splice(i, 1); renderPaths(); changed(); } } }))));
        };
        renderPaths();
        const manual = h('input', { class: 'fba-input', attrs: { type: 'text', placeholder: 'wp-content/uploads', 'aria-label': __('Folder path', 'cloverbrowser'), spellcheck: 'false' } });
        const addPath = (raw) => {
            const v = String(raw || '').trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
            if (!v || v.split('/').some((seg) => seg === '..' || seg === '.')) { toast(__('Enter a folder path relative to the site root.', 'cloverbrowser'), 'warn'); return; }
            if (!set.paths.includes(v)) set.paths.push(v);
            manual.value = '';
            renderPaths();
            changed();
        };
        manual.addEventListener('keydown', (e) => { if (e.key === 'Enter' && trusted(e)) { e.preventDefault(); addPath(manual.value); } });
        body.append(section(__('Where they can go', 'cloverbrowser'),
            isGlobal ? __('Limit every role to these folders and everything inside them. Leave empty for no limit.', 'cloverbrowser')
                : __('Limit this role to these folders. When “All roles” also has folders, only the overlap is reachable.', 'cloverbrowser'),
            pathList,
            h('div', { class: 'fba-row' },
                h('button', { class: 'fbx-btn', icon: ICONS.folder, attrs: { type: 'button' }, on: { click: async (ev) => { if (!trusted(ev)) return; const r = await pickFolder(set.paths[set.paths.length - 1] || ''); if (r) addPath(r); } } }, h('span', { text: __('Choose folder…', 'cloverbrowser') })),
                manual,
                h('button', { class: 'fbx-btn', icon: ICONS.plus, attrs: { type: 'button' }, on: { click: () => addPath(manual.value) } }, h('span', { text: __('Add', 'cloverbrowser') })))));

        // --- File types
        const typeGrid = h('div', { class: 'fba-types' }, S.meta.types.map((t) => {
            const byGlobal = !isGlobal && g.types.includes(t.key);
            const on = byGlobal || set.types.includes(t.key);
            const input = h('input', { attrs: { type: 'checkbox' }, props: { checked: on, disabled: byGlobal }, on: { change: (e) => {
                if (e.target.checked) { if (!set.types.includes(t.key)) set.types.push(t.key); } else set.types = set.types.filter((x) => x !== t.key);
                card.classList.toggle('is-on', e.target.checked);
                changed();
            } } });
            const card = h('label', { class: 'fba-type' + (on ? ' is-on' : '') + (byGlobal ? ' is-disabled' : '') + (t.key === 'php' ? ' is-critical' : '') }, input,
                h('span', { class: 'fba-type-text' }, h('strong', { text: t.label }), h('small', { text: TYPE_DESC[t.key] || '' }),
                    byGlobal ? h('em', { class: 'fba-tag', text: __('Blocked for all roles', 'cloverbrowser') }) : null));
            return card;
        }));
        body.append(section(__('Blocked file types', 'cloverbrowser'),
            __('Blocked files cannot be opened, downloaded, edited, uploaded or created. Types are recognised by their content (file headers and embedded code), not just by the name.', 'cloverbrowser'),
            typeGrid));

        // --- Rules
        const rulesBox = h('div', { class: 'fba-rules' });
        const renderRules = () => {
            rulesBox.replaceChildren();
            const table = h('div', { class: 'fba-rule-table', attrs: { role: 'table' } },
                h('div', { class: 'fba-rule fba-rule--head', attrs: { role: 'row' } },
                    h('span', { text: __('Match', 'cloverbrowser'), attrs: { role: 'columnheader' } }),
                    h('span', { text: __('Pattern or path', 'cloverbrowser'), attrs: { role: 'columnheader' } }),
                    h('span', { text: __('Effect', 'cloverbrowser'), attrs: { role: 'columnheader' } }),
                    h('span', { attrs: { role: 'columnheader' } })));
            if (isGlobal) {
                S.meta.builtin.forEach((r) => table.append(h('div', { class: 'fba-rule is-builtin', attrs: { role: 'row' } },
                    h('span', { text: MATCH_TEXT[r.m][0] }), h('code', { text: r.p }), h('span', { text: EFFECT_TEXT[r.e] }),
                    h('span', { class: 'fba-tag', icon: ICONS.lock, attrs: { title: __('Built in: always protected from non-administrators.', 'cloverbrowser') } }, h('span', { text: __('Always', 'cloverbrowser') })))));
            } else if (g.rules.length || S.meta.builtin.length) {
                table.append(h('div', { class: 'fba-rule is-builtin fba-rule--note', attrs: { role: 'row' } }, h('span', { text: g.rules.length ? sprintf(
                    /* translators: %s: number of rules */
                    _n('Plus %s rule from “All roles” and the built-in protections.', 'Plus %s rules from “All roles” and the built-in protections.', g.rules.length, 'cloverbrowser'), g.rules.length)
                    : __('Plus the built-in protections.', 'cloverbrowser') })));
            }
            set.rules.forEach((r, i) => {
                const help = h('small', { class: 'fba-rule-help', text: MATCH_TEXT[r.m][2] });
                const pat = h('input', { class: 'fba-input', attrs: { type: 'text', placeholder: MATCH_TEXT[r.m][1], spellcheck: 'false', 'aria-label': __('Pattern or path', 'cloverbrowser'), maxlength: 255 }, props: { value: r.p } });
                const err = h('small', { class: 'fba-error' });
                const validate = () => {
                    const v = pat.value.trim();
                    let msg = '';
                    if (!v) msg = __('Required.', 'cloverbrowser');
                    else if ((r.m === 'contains' || r.m === 'name') && v.includes('/')) msg = __('Name rules match a single name — use “Exact path” or “Folder and contents” for paths.', 'cloverbrowser');
                    err.textContent = msg;
                    pat.classList.toggle('is-invalid', !!msg);
                };
                pat.addEventListener('input', () => { r.p = pat.value; validate(); changed(); });
                validate();
                const matchSel = h('select', { class: 'fba-select', attrs: { 'aria-label': __('Match', 'cloverbrowser') }, on: { change: (e) => { r.m = e.target.value; renderRules(); changed(); } } },
                    Object.keys(MATCH_TEXT).map((m) => h('option', { text: MATCH_TEXT[m][0], props: { value: m, selected: r.m === m } })));
                const effSel = h('select', { class: 'fba-select', attrs: { 'aria-label': __('Effect', 'cloverbrowser') }, on: { change: (e) => { r.e = e.target.value; changed(); } } },
                    Object.keys(EFFECT_TEXT).map((k) => h('option', { text: EFFECT_TEXT[k], props: { value: k, selected: r.e === k } })));
                table.append(h('div', { class: 'fba-rule', attrs: { role: 'row' } },
                    matchSel, h('span', { class: 'fba-rule-pat' }, pat, err, help), effSel,
                    h('button', { class: 'fbx-btn fbx-btn--ghost fbx-btn--icon fbx-btn--sm', icon: ICONS.trash, attrs: { type: 'button', title: __('Remove', 'cloverbrowser'), 'aria-label': __('Remove rule', 'cloverbrowser') }, on: { click: () => { set.rules.splice(i, 1); renderRules(); changed(); } } })));
            });
            if (!set.rules.length) table.append(h('div', { class: 'fba-empty', text: __('No rules yet.', 'cloverbrowser') }));
            rulesBox.append(table, h('button', { class: 'fbx-btn', icon: ICONS.plus, attrs: { type: 'button' }, on: { click: () => {
                set.rules.push({ m: 'contains', p: '', e: 'hide' });
                renderRules();
                changed();
                const inputs = rulesBox.querySelectorAll('.fba-rule-pat input');
                if (inputs.length) inputs[inputs.length - 1].focus();
            } } }, h('span', { text: __('Add rule', 'cloverbrowser') })));
        };
        renderRules();
        body.append(section(__('Protected files & folders', 'cloverbrowser'),
            __('“Hidden & blocked” items are not listed and cannot be opened. “Read-only” items are visible but cannot be changed. A rule that matches a folder also covers everything inside it.', 'cloverbrowser'),
            rulesBox));

        // --- Limits
        const limitRow = (key, label, desc) => {
            const bytes = set[key] || 0;
            let unit = UNITS[1];
            for (const u of UNITS) if (bytes && bytes % u[1] === 0) unit = u;
            const num = h('input', { class: 'fba-input fba-num', attrs: { type: 'number', min: 0, step: 'any', inputmode: 'decimal', placeholder: '0', 'aria-label': label }, props: { value: bytes ? String(+(bytes / unit[1]).toFixed(3)) : '' } });
            const sel = h('select', { class: 'fba-select', attrs: { 'aria-label': __('Unit', 'cloverbrowser') } }, UNITS.map((u) => h('option', { text: u[0], props: { value: String(u[1]), selected: u === unit } })));
            const update = () => {
                const n = parseFloat(num.value);
                set[key] = Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n * Number(sel.value)), 1099511627776) : 0;
                changed();
            };
            num.addEventListener('input', update);
            sel.addEventListener('change', update);
            return h('div', { class: 'fba-limit' }, h('span', { class: 'fba-toggle-text' }, h('strong', { text: label }), h('small', { text: desc })), h('span', { class: 'fba-limit-input' }, num, sel));
        };
        body.append(section(__('Size limits', 'cloverbrowser'),
            isGlobal ? __('Leave empty or 0 for no limit (the server’s own upload limit still applies).', 'cloverbrowser')
                : __('Leave empty or 0 for no extra limit. When both are set, the smaller one applies.', 'cloverbrowser'),
            limitRow('max_upload', __('Largest upload', 'cloverbrowser'), __('Maximum size of each uploaded file.', 'cloverbrowser')),
            limitRow('max_growth', __('Largest growth per save', 'cloverbrowser'), __('How much bigger a file may become in one editor save.', 'cloverbrowser'))));

        parts.push(body);
        els.panel.replaceChildren(...parts);
    }

    /* ------------------------------------------------------------------ */
    /* Access tester                                                      */
    /* ------------------------------------------------------------------ */

    const ACTION_TEXT = {
        list: __('Browse folder', 'cloverbrowser'), view: __('Open', 'cloverbrowser'), download: __('Download', 'cloverbrowser'),
        edit: __('Edit & save', 'cloverbrowser'), create: __('Create inside', 'cloverbrowser'), upload: __('Upload into', 'cloverbrowser'),
        rename: __('Rename & move', 'cloverbrowser'), delete: __('Delete', 'cloverbrowser'), chmod: __('Change permissions', 'cloverbrowser'),
    };
    function buildTester() {
        const roleSel = h('select', { class: 'fba-select', attrs: { 'aria-label': __('Role', 'cloverbrowser') } });
        const path = h('input', { class: 'fba-input', attrs: { type: 'text', placeholder: 'wp-content/uploads', spellcheck: 'false', 'aria-label': __('Path to test', 'cloverbrowser') } });
        const out = h('div', { class: 'fba-test-out', attrs: { 'aria-live': 'polite' } });
        const fillRoles = () => roleSel.replaceChildren(...S.meta.roles.map((r) => h('option', { text: r.label, props: { value: r.key } })));
        const run = async (ev) => {
            if (ev && !trusted(ev)) return;
            out.replaceChildren(h('div', { class: 'fba-muted', text: __('Checking…', 'cloverbrowser') }));
            try {
                const d = await api('policy_test', { policy: NATIVE.stringify(S.draft), role: roleSel.value, path: path.value.trim() });
                if (d.error) { out.replaceChildren(h('div', { class: 'fba-error', text: d.error })); return; }
                const rows = [];
                if (!d.access) rows.push(h('div', { class: 'fba-warnline', icon: ICONS.warn }, h('span', { text: __('This role has no access at all (access is switched off).', 'cloverbrowser') })));
                rows.push(h('p', { class: 'fba-muted' },
                    h('code', { text: d.path === '' ? '/' : d.path }), ' — ',
                    d.is_file ? __('file', 'cloverbrowser') : __('folder', 'cloverbrowser'),
                    d.types && d.types.length ? ' — ' + sprintf(
                        /* translators: %s: detected file types */
                        __('detected as: %s', 'cloverbrowser'), d.types.join(', ')) : ''));
                rows.push(h('ul', { class: 'fba-test-list' }, d.results.map((r) => h('li', { class: r.allowed ? 'is-yes' : 'is-no' },
                    h('span', { class: 'fba-test-ico', icon: r.allowed ? ICONS.check : ICONS.cross }),
                    h('strong', { text: ACTION_TEXT[r.action] || r.action }),
                    r.allowed ? h('span', { class: 'fba-muted', text: __('Allowed', 'cloverbrowser') }) : h('span', { class: 'fba-muted', text: r.reason })))));
                out.replaceChildren(...rows);
            } catch (e) {
                out.replaceChildren(h('div', { class: 'fba-error', text: e.message }));
            }
        };
        path.addEventListener('keydown', (e) => { if (e.key === 'Enter' && trusted(e)) { e.preventDefault(); run(e); } });
        els.fillTesterRoles = fillRoles;
        return h('section', { class: 'fba-section fba-tester' },
            h('h3', { text: __('Test access', 'cloverbrowser') }),
            h('p', { class: 'fba-muted', text: __('Check what a role could do with a file or folder — using the rules on this screen, even before you save them.', 'cloverbrowser') }),
            h('div', { class: 'fba-row' },
                roleSel, path,
                h('button', { class: 'fbx-btn', icon: ICONS.folder, attrs: { type: 'button', title: __('Choose folder…', 'cloverbrowser'), 'aria-label': __('Choose folder…', 'cloverbrowser') }, on: { click: async (ev) => { if (!trusted(ev)) return; const r = await pickFolder(path.value.trim()); if (r) path.value = r; } } }),
                h('button', { class: 'fbx-btn fbx-btn--primary', text: __('Test', 'cloverbrowser'), attrs: { type: 'button' }, on: { click: run } })),
            out);
    }

    /* ------------------------------------------------------------------ */
    /* Trash settings                                                     */
    /* ------------------------------------------------------------------ */

    function daysInput(key, label) {
        const err = h('small', { class: 'fba-error' });
        const input = h('input', { class: 'fba-input fba-num', attrs: { type: 'number', min: 1, max: 3650, step: 1, inputmode: 'numeric', 'aria-label': label }, props: { value: String(S.trash[key]) } });
        const validate = () => {
            const v = Number(input.value);
            const ok = input.value.trim() !== '' && Number.isInteger(v) && v >= 1 && v <= 3650;
            input.classList.toggle('is-invalid', !ok);
            err.textContent = ok ? '' : __('Enter a number of days between 1 and 3650.', 'cloverbrowser');
            if (ok) S.trash[key] = v;
            changed();
        };
        input.addEventListener('input', validate);
        return h('div', { class: 'fba-limit' },
            h('span', { class: 'fba-toggle-text' }, h('strong', { text: label }), err),
            h('span', { class: 'fba-limit-input' }, input, h('span', { class: 'fba-unit', text: __('days', 'cloverbrowser') })));
    }

    function renderTrash() {
        if (!S.trash) return;
        const t = S.trash;
        const info = S.trashInfo || {};
        const parts = [];

        parts.push(h('div', { class: 'fba-panel-head' },
            h('h2', { text: __('Trash', 'cloverbrowser') }),
            h('p', { class: 'fba-muted', text: __('Deleted files and folders can be kept for a while so they can be restored. There are two levels, and each can be switched on separately.', 'cloverbrowser') })));
        els.trashLive = h('div', { class: 'fba-live' });
        parts.push(els.trashLive);

        parts.push(section(__('Personal trash', 'cloverbrowser'), null,
            toggle(t.user_enabled, false, (v) => { t.user_enabled = v; renderTrash(); changed(); },
                __('Give every user their own trash', 'cloverbrowser'),
                __('Each user’s deletions go to their own Trash, where they can restore them, remove them or empty it. They only ever see their own items.', 'cloverbrowser')),
            h('div', { class: t.user_enabled ? '' : 'is-dimmed' }, daysInput('user_days', __('Keep items in a user’s trash for', 'cloverbrowser')))));

        parts.push(section(__('Site trash', 'cloverbrowser'), null,
            toggle(t.global_enabled, false, (v) => { t.global_enabled = v; renderTrash(); changed(); },
                __('Keep every deletion in the site trash', 'cloverbrowser'),
                __('A safety net for administrators: everything any user deletes is kept here, even after they empty their own trash. Only administrators can see it, restore from it or empty it.', 'cloverbrowser')),
            h('div', { class: t.global_enabled ? '' : 'is-dimmed' }, daysInput('global_days', __('Keep items in the site trash for', 'cloverbrowser')))));

        const radio = (value, label, desc, recommended) => {
            const input = h('input', { attrs: { type: 'radio', name: 'fba-purge' }, props: { checked: t.user_purge === value, disabled: !t.user_enabled }, on: { change: () => { t.user_purge = value; changed(); } } });
            return h('label', { class: 'fba-radio' + (!t.user_enabled ? ' is-disabled' : '') }, input,
                h('span', { class: 'fba-toggle-text' },
                    h('strong', null, label, recommended ? h('em', { class: 'fba-tag fba-tag--ok', text: __('Recommended', 'cloverbrowser') }) : null),
                    h('small', { text: desc })));
        };
        parts.push(section(__('Permanent deletion', 'cloverbrowser'),
            __('Who may delete an item for good before the site trash’s retention period is over.', 'cloverbrowser'),
            h('div', { class: 'fba-radios', attrs: { role: 'radiogroup', 'aria-label': __('Permanent deletion', 'cloverbrowser') } },
                radio(false, __('Administrators only', 'cloverbrowser'),
                    __('Users can remove items from their own trash, but the site trash keeps its copy until it expires.', 'cloverbrowser'), true),
                radio(true, __('Also the user who deleted the item', 'cloverbrowser'),
                    __('In their own trash, a user can right-click an item and choose “Permanently delete”, which also removes it from the site trash. They can never empty the site trash.', 'cloverbrowser'), false)),
            !t.user_enabled ? h('p', { class: 'fba-muted', text: __('Requires the personal trash: users can only reach this option from their own trash.', 'cloverbrowser') }) : null));

        // Storage & status
        const where = info.location
            ? h('p', { class: 'fba-muted' }, __('Stored in:', 'cloverbrowser'), ' ', h('code', { text: info.location }))
            : h('p', { class: 'fba-muted', text: __('The trash folder is created on the first deletion.', 'cloverbrowser') });
        const safety = !info.location ? null : info.outside
            ? h('p', { class: 'fba-okline', icon: ICONS.shield }, h('span', { text: __('Outside the public web root: the web server cannot serve these files.', 'cloverbrowser') }))
            : h('p', { class: 'fba-warnline', icon: ICONS.info }, h('span', { text: __('Inside the web root, protected by deny rules (.htaccess / web.config), a random folder name, random item names and private file permissions. On nginx, add a rule denying access to this folder, or define CLOVERBROWSER_TRASH_DIR in wp-config.php as a folder outside the web root.', 'cloverbrowser') }));
        parts.push(section(__('Storage', 'cloverbrowser'), null,
            where, safety,
            h('p', { class: 'fba-muted', text: sprintf(
                /* translators: 1: number of items, 2: total size */
                _n('The site currently holds %1$s trashed item (%2$s).', 'The site currently holds %1$s trashed items (%2$s).', info.count || 0, 'cloverbrowser'),
                String(info.count || 0), info.sizeText || '0 B') }),
            h('p', { class: 'fba-muted', text: __('Retention changes also apply to items already in the trash: items outside the new periods are deleted at the next hourly cleanup.', 'cloverbrowser') }),
            CFG.browserUrl && (t.global_enabled || info.count) ? h('div', { class: 'fba-row' },
                h('a', { class: 'fbx-btn fbx-btn--sm', text: __('Open site trash', 'cloverbrowser'), attrs: { href: CFG.browserUrl + '#site-trash' } })) : null));

        els.trashView.replaceChildren(h('div', { class: 'fba-trash-panel' }, ...parts));
        renderTrashLive();
    }

    function renderTrashLive() {
        if (!els.trashLive || !S.trash) return;
        const t = S.trash;
        const out = [];
        if (!t.user_enabled && !t.global_enabled) {
            out.push(__('Both trashes are off: every deletion is permanent and cannot be undone.', 'cloverbrowser'));
        } else if (!t.global_enabled) {
            out.push(__('Without the site trash, an item is gone for good as soon as its owner removes it from their trash.', 'cloverbrowser'));
        }
        if (t.global_enabled && t.user_enabled && t.user_purge) {
            out.push(__('Users can permanently delete their own items, so the site trash is no longer a complete record of deletions.', 'cloverbrowser'));
        }
        els.trashLive.replaceChildren(...out.map((w) => h('div', { class: 'fba-warnline', icon: ICONS.warn }, h('span', { text: w }))));
    }

    /* ------------------------------------------------------------------ */
    /* Save / discard                                                     */
    /* ------------------------------------------------------------------ */

    function renderNotices() {
        els.notices.replaceChildren(...S.warnings.map((w) => h('div', { class: 'fba-warnline', icon: ICONS.warn }, h('span', { text: w }))));
    }

    function onSave(ev) {
        if (trusted(ev)) doSave();
    }

    async function doSave() {
        if (S.saving) return;
        const bad = ROOT.querySelector('.fba-input.is-invalid');
        if (bad) {
            if (els.trashView.contains(bad)) setTab('trash'); else setTab('access');
            bad.focus();
            toast(__('Fix the highlighted field first.', 'cloverbrowser'), 'warn');
            return;
        }
        S.saving = true;
        changed();
        const saved = [];
        try {
            if (policyDirty()) {
                const d = await api('policy_save', { policy: NATIVE.stringify(S.draft) });
                S.draft = clone(d.settings);
                S.savedJson = NATIVE.stringify(S.draft);
                S.warnings = d.warnings || [];
                renderNotices();
                renderPanel();
                saved.push(__('Access rules saved.', 'cloverbrowser'));
            }
            if (trashDirty()) {
                const d = await api('trash_settings_save', { settings: NATIVE.stringify(S.trash) });
                S.trashInfo = d;
                S.trash = clone(d.settings);
                S.trashSaved = NATIVE.stringify(S.trash);
                renderTrash();
                saved.push(__('Trash settings saved.', 'cloverbrowser'));
            }
            if (saved.length) toast(saved.join(' '), 'success');
        } catch (e) {
            toast(e.message, 'error', 7000);
        } finally {
            S.saving = false;
            changed();
        }
    }

    async function onDiscard(ev) {
        if (!trusted(ev)) return;
        const ok = await modal(__('Discard changes?', 'cloverbrowser'), h('p', { text: __('Your unsaved changes will be lost.', 'cloverbrowser') }), [
            { label: __('Cancel', 'cloverbrowser'), value: null },
            { label: __('Discard', 'cloverbrowser'), kind: 'danger', value: true },
        ]);
        if (!ok) return;
        S.draft = NATIVE.parse(S.savedJson);
        if (S.trashSaved) S.trash = NATIVE.parse(S.trashSaved);
        renderPanel();
        renderTrash();
        changed();
    }

    window.addEventListener('beforeunload', (e) => {
        if (S.draft && isDirty()) { e.preventDefault(); e.returnValue = ''; }
    });
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S') && trusted(e)) {
            e.preventDefault();
            if (els.save && !els.save.disabled) doSave();
        }
    });

    /* ------------------------------------------------------------------ */
    /* Boot                                                               */
    /* ------------------------------------------------------------------ */

    // Cloverbrowser wordmark: markup of the plugin's own SVG asset, provided by the server.
    const LOGO = typeof CFG.logo === 'string' ? CFG.logo : '';

    (async () => {
        try {
            const [d, t] = await Promise.all([api('policy_get'), api('trash_settings_get')]);
            S.meta = { roles: d.roles || [], types: d.types || [], builtin: d.builtin || [], writeLocked: !!d.writeLocked };
            S.draft = clone(d.settings);
            S.savedJson = NATIVE.stringify(S.draft);
            S.trashInfo = t;
            S.trash = clone(t.settings);
            S.trashSaved = NATIVE.stringify(S.trash);
            buildShell();
            els.fillTesterRoles();
            renderNav();
            renderPanel();
            renderTrash();
            changed();
        } catch (e) {
            ROOT.replaceChildren(h('div', { class: 'notice notice-error inline' }, h('p', { text: e.message })));
        }
    })();
})();
