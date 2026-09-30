/**
 * Cloverbrowser — file browser component.
 * Vanilla JS, scoped to #cloverbrowser-root. One AJAX request per operation,
 * with per-operation busy indicators, toasts, modals, debounced draft
 * autosave, and stale-response guards for jank-free browsing.
 *
 * Anti-scripting hardening (realistic, low-cost measures — a determined
 * extension with full page access can never be stopped completely):
 *  - No globals: the config is copied into this closure, deleted from
 *    window and its <script> element removed from the DOM; the nonce is
 *    only held in a closure variable and rotated via our own endpoint.
 *  - fetch / XMLHttpRequest / FormData / JSON.parse are captured at start-up,
 *    so later monkey-patching cannot observe or alter our requests.
 *  - Every action requires a trusted user gesture (event.isTrusted): script
 *    calls such as element.click() or synthetic key/drop events are ignored.
 *  - What a row acts on lives in a WeakMap, not in DOM attributes, so
 *    tampering with the markup cannot redirect a user's click to another file.
 */
(function () {
    'use strict';

    const RAW = window.CloverbrowserConfig;
    const ROOT = document.getElementById('cloverbrowser-root');
    if (!RAW || !ROOT) return;
    try { delete window.CloverbrowserConfig; } catch (e) { window.CloverbrowserConfig = undefined; }
    const cfgScript = document.getElementById('cloverbrowser-app-js-before');
    if (cfgScript) cfgScript.remove();
    const CFG = Object.freeze(Object.assign({}, RAW));
    let NONCE = String(CFG.nonce || '');
    const NATIVE = Object.freeze({
        fetch: window.fetch.bind(window),
        FormData: window.FormData,
        XHR: window.XMLHttpRequest,
        parse: JSON.parse,
    });
    const PERMS = Object.freeze(Object.assign({}, CFG.perms || {}));
    const RESTRICTED = !!CFG.restricted;
    const SERVER_EOL_NAME = CFG.serverEol || 'lf';
    const SERVER_EOL = SERVER_EOL_NAME === 'crlf' ? '\r\n' : SERVER_EOL_NAME === 'cr' ? '\r' : '\n';
    const EOL_LABEL = { lf: 'LF', crlf: 'CRLF', cr: 'CR' };

    // Translations come from wp.i18n (script dependency `wp-i18n`), fed by
    // wp_set_script_translations() with the user's locale — or the site
    // locale when the user has no personal language preference.
    const { __, _n, _x, sprintf } = window.wp.i18n;
    const esc = (str) => String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    const KEEP_OPEN = Symbol('keep-open');
    const CAN_WRITE = !!CFG.canWrite;
    /** Permission check for the UI (the server enforces everything again). */
    const can = (p) => (['view', 'download'].includes(p) ? !!PERMS[p] : CAN_WRITE && !!PERMS[p]);
    const trusted = (ev) => !!(ev && ev.isTrusted);

    // Trash configuration (the server re-checks every trash action).
    const TRASH = Object.freeze(Object.assign({ user: false, site: false, userDays: 0, siteDays: 0, canPurge: false, isAdmin: false, count: 0 }, CFG.trash || {}));
    const TRASH_ON = !!(TRASH.user || TRASH.site);
    let trashCount = TRASH.count | 0;
    // Administrators land in the site trash when personal trash is off.
    const TRASH_VIEW = TRASH.user || (TRASH.isAdmin && TRASH.site);
    const TRASH_TABS = TRASH.isAdmin && TRASH.user && TRASH.site;
    const SHOW_TRASH_BTN = TRASH_VIEW && (TRASH.isAdmin || PERMS.delete || trashCount > 0);
    // CFG.codeEditor is null when the user disabled syntax highlighting in their profile.
    const NO_CM = !CFG.codeEditor ||
        !(window.wp && window.wp.codeEditor && typeof window.wp.codeEditor.initialize === 'function');

    // All of these modes ship in core's bundled codemirror.min.js.
    const MODES = {
        php: 'application/x-httpd-php', phtml: 'application/x-httpd-php', inc: 'application/x-httpd-php',
        js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'jsx',
        ts: { name: 'javascript', typescript: true }, tsx: { name: 'jsx', typescript: true },
        json: { name: 'javascript', json: true }, map: { name: 'javascript', json: true },
        css: 'css', scss: 'text/x-scss', less: 'text/x-less', sass: 'sass',
        html: 'htmlmixed', htm: 'htmlmixed', xml: 'xml', svg: 'xml', xsl: 'xml',
        md: 'markdown', markdown: 'markdown',
        sql: 'text/x-sql', sh: 'shell', bash: 'shell', yml: 'yaml', yaml: 'yaml',
    };

    /* ------------------------------------------------------------------ */
    /* State                                                              */
    /* ------------------------------------------------------------------ */

    const state = {
        cwd: '',
        entries: [],
        total: 0,
        truncated: false,
        sort: { key: 'name', dir: 1 },
        shown: 500,
        listSeq: 0,          // guards folder listings against stale responses
        fileSeq: 0,          // guards file opens (independent of listings)
        file: null,          // { rel, name, size, perms, writable, mtime, modified, hash, eol }
        cm: null,            // wp.codeEditor instance
        dirty: false,        // editor differs from what is on disk
        saving: false,
        lastAutosaved: '',
    };
    let autoTimer = null;
    let draftPromise = null;
    let softTimer = null;
    let busyCount = 0;

    /* ------------------------------------------------------------------ */
    /* Icons (static inline SVG strings — never user content)             */
    /* ------------------------------------------------------------------ */

    const svg = (paths) =>
        '<svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" ' +
        'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + paths + '</svg>';

    const ICONS = {
        folder: svg('<path d="M1.8 4.2 3 3h3l1.2 1.5H14a.8.8 0 0 1 .8.8v7a.8.8 0 0 1-.8.8H2.6a.8.8 0 0 1-.8-.8V4.2z" fill="currentColor" stroke="none"/>'),
        file: svg('<path d="M4 1.8h5l3 3v9.4H4z"/><path d="M9 1.8v3h3"/>'),
        link: svg('<path d="M6.5 9.5 9.5 6.5"/><path d="m5 8-1.5-1.5a2.3 2.3 0 0 1 3.2-3.2L8 4.6"/><path d="m11 8 1.5 1.5a2.3 2.3 0 0 1-3.2 3.2L8 11.4"/>'),
        up: svg('<path d="M8 13V3"/><path d="m4 7 4-4 4 4"/>'),
        refresh: svg('<path d="M13 8a5 5 0 1 1-1.5-3.6"/><path d="M13 2.5V5h-2.5"/>'),
        close: svg('<path d="m4 4 8 8M12 4l-8 8"/>'),
        download: svg('<path d="M8 2.5v7"/><path d="m5 7 3 3 3-3"/><path d="M2.8 13.5h10.4"/>'),
        edit: svg('<path d="M3 13h2.5L12 6.5 9.5 4 3 10.5z"/><path d="m9 3.2 1.3-1.3 3.5 3.5-1.3 1.3"/>'),
        perms: svg('<path d="M8 1.8 13 4v4c0 3.2-2.1 5.5-5 7-2.9-1.5-5-3.8-5-7V4z"/>'),
        rename: svg('<path d="M2.5 8h11"/><path d="m10 5 3 3-3 3"/>'),
        trash: svg('<path d="M3 4.5h10"/><path d="M5 4.5V3h6v1.5"/><path d="M4.5 4.5 5.2 13h5.6l.7-8.5"/><path d="M7 7v3.5M9 7v3.5"/>'),
        upload: svg('<path d="M8 12.5v-9"/><path d="m4.5 6.5 3.5-3.5 3.5 3.5"/><path d="M2.8 15h10.4"/>'),
        lock: svg('<rect x="3.5" y="7" width="9" height="7" rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>'),
        eye: svg('<path d="M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8 12.1 12.5 8 12.5 1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>'),
        restore: svg('<path d="M3.5 6.5h6.2a3.3 3.3 0 0 1 0 6.6H6.5"/><path d="m6 3.5-3 3 3 3"/>'),
        more: svg('<circle cx="3.5" cy="8" r="1.1" fill="currentColor" stroke="none"/><circle cx="8" cy="8" r="1.1" fill="currentColor" stroke="none"/><circle cx="12.5" cy="8" r="1.1" fill="currentColor" stroke="none"/>'),
        back: svg('<path d="M13 8H3"/><path d="m7 4-4 4 4 4"/>'),
        gear: svg('<circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4"/>'),
    };

    // Wordmark markup from the plugin's own SVG asset (provided by the server, never user content).
    const LOGO = typeof CFG.logo === 'string' ? CFG.logo : '';

    /* ------------------------------------------------------------------ */
    /* Markup + refs                                                      */
    /* ------------------------------------------------------------------ */

    const writeTools = (can('create') || can('upload')) ? `
                <span class="fbx-vsep"></span>` +
        (can('create') ? `
                <button type="button" class="fbx-btn" data-act="mkdir">${esc(__('New folder', 'cloverbrowser'))}</button>
                <button type="button" class="fbx-btn" data-act="mkfile">${esc(__('New file', 'cloverbrowser'))}</button>` : '') +
        (can('upload') ? `
                <button type="button" class="fbx-btn fbx-btn--primary" data-act="upload">${ICONS.upload}<span>${esc(__('Upload', 'cloverbrowser'))}</span></button>` : '') : '';

    const editActions = can('edit') ? `
                    <button type="button" class="fbx-btn" data-act="revert">${esc(__('Revert', 'cloverbrowser'))}</button>
                    <button type="button" class="fbx-btn fbx-btn--primary" data-act="save">${esc(__('Save', 'cloverbrowser'))}</button>` : '';

    // Width of the row-action column = the buttons this user can actually get.
    const ACT_COUNT = Math.max(1, [can('download'), !!PERMS.view, can('chmod'), can('rename'), can('delete')].filter(Boolean).length);
    const actWidth = (btn) => ACT_COUNT * btn + (ACT_COUNT - 1) * 4;

    ROOT.innerHTML = `
<div class="fbx" style="--fbx-act-w:${actWidth(32)}px;--fbx-act-w-narrow:${actWidth(28)}px">
    <div class="fbx-statusbar">
        <span class="fbx-logo" role="img" aria-label="Cloverbrowser">${LOGO}</span>
        <span class="fbx-busy" hidden><span class="fbx-spinner"></span></span>
        <span class="fbx-status-text" role="status">${esc(__('Ready', 'cloverbrowser'))}</span>
        <span class="fbx-status-end">
        ${RESTRICTED ? `<span class="fbx-chip fbx-chip--info" title="${esc(__('Your access is limited by rules set by an administrator.', 'cloverbrowser'))}">${esc(__('Limited access', 'cloverbrowser'))}</span>` : ''}
        ${CAN_WRITE ? '' : `<span class="fbx-chip fbx-chip--warn" title="${esc(CFG.readOnlyReason || '')}">${esc(__('Read-only', 'cloverbrowser'))}</span>`}
        ${SHOW_TRASH_BTN ? `<button type="button" class="fbx-btn fbx-btn--ghost fbx-btn--sm fbx-trash-btn" data-act="trash">${ICONS.trash}<span>${esc(__('Trash', 'cloverbrowser'))}</span><span class="fbx-count" aria-hidden="true" hidden></span></button>` : ''}
        ${CFG.accessUrl ? `<a class="fbx-btn fbx-btn--ghost fbx-btn--sm" href="${esc(CFG.accessUrl)}">${ICONS.gear}<span>${esc(__('Settings', 'cloverbrowser'))}</span></a>` : ''}
        </span>
    </div>
    <div class="fbx-toolbar">
        <nav class="fbx-crumb" aria-label="${esc(__('Current folder', 'cloverbrowser'))}"></nav>
        <div class="fbx-tools">
            <button type="button" class="fbx-btn fbx-btn--ghost fbx-btn--icon" data-act="up" title="${esc(__('Parent folder', 'cloverbrowser'))}" aria-label="${esc(__('Parent folder', 'cloverbrowser'))}">${ICONS.up}</button>
            <button type="button" class="fbx-btn fbx-btn--ghost fbx-btn--icon" data-act="refresh" title="${esc(__('Refresh', 'cloverbrowser'))}" aria-label="${esc(__('Refresh', 'cloverbrowser'))}">${ICONS.refresh}</button>${writeTools}
        </div>
    </div>
    <div class="fbx-main">
        <section class="fbx-list-pane" aria-label="${esc(__('Folder contents', 'cloverbrowser'))}">
            <div class="fbx-list-head">
                <button type="button" class="fbx-col fbx-col--name" data-sort="name">${esc(_x('Name', 'column header', 'cloverbrowser'))}</button>
                <button type="button" class="fbx-col fbx-col--size" data-sort="size">${esc(_x('Size', 'column header', 'cloverbrowser'))}</button>
                <button type="button" class="fbx-col fbx-col--perms" data-sort="perms">${esc(_x('Mode', 'column header: permission mode', 'cloverbrowser'))}</button>
                <button type="button" class="fbx-col fbx-col--mtime" data-sort="mtime">${esc(_x('Modified', 'column header: last modified date', 'cloverbrowser'))}</button>
                <span class="fbx-col fbx-col--act"></span>
            </div>
            <div class="fbx-rows"></div>
            <div class="fbx-list-foot"></div>
            <div class="fbx-drop" hidden><span>${esc(__('Drop files to upload to this folder', 'cloverbrowser'))}</span></div>
        </section>
        <section class="fbx-editor-pane" aria-label="${esc(__('File editor', 'cloverbrowser'))}" hidden>
            <header class="fbx-editor-head">
                <div class="fbx-editor-title">
                    <span class="fbx-filename"></span>
                    <span class="fbx-chips"></span>
                    <span class="fbx-draft-ind" hidden></span>
                </div>
                <div class="fbx-editor-actions">${editActions}
                    <button type="button" class="fbx-btn fbx-btn--ghost fbx-btn--icon" data-act="close" title="${esc(__('Close editor', 'cloverbrowser'))}" aria-label="${esc(__('Close editor', 'cloverbrowser'))}">${ICONS.close}</button>
                </div>
            </header>
            <div class="fbx-eol" role="status" hidden>
                <span class="fbx-eol-text"></span>
                <button type="button" class="fbx-btn fbx-btn--sm" data-act="eolconvert"></button>
                <button type="button" class="fbx-btn fbx-btn--ghost fbx-btn--icon fbx-btn--sm" data-act="eoldismiss" title="${esc(__('Dismiss', 'cloverbrowser'))}" aria-label="${esc(__('Dismiss', 'cloverbrowser'))}">${ICONS.close}</button>
            </div>
            <div class="fbx-editor-body">
                <textarea class="fbx-code" spellcheck="false" aria-label="${esc(__('File contents', 'cloverbrowser'))}"></textarea>
            </div>
        </section>
    </div>
    <section class="fbx-trash" aria-labelledby="fbx-trash-title" hidden>
        <div class="fbx-trash-head">
            <button type="button" class="fbx-btn fbx-btn--ghost fbx-btn--sm" data-act="trashback">${ICONS.back}<span>${esc(__('Back to files', 'cloverbrowser'))}</span></button>
            <h2 class="fbx-trash-title" id="fbx-trash-title"></h2>
            ${TRASH_TABS ? `<div class="fbx-tabs" role="tablist" aria-label="${esc(__('Trash', 'cloverbrowser'))}">
                <button type="button" role="tab" class="fbx-tab" data-act="trashtab" data-tab="mine">${esc(__('My trash', 'cloverbrowser'))}</button>
                <button type="button" role="tab" class="fbx-tab" data-act="trashtab" data-tab="site">${esc(__('Site trash', 'cloverbrowser'))}</button>
            </div>` : ''}
            <span class="fbx-trash-end">
                <button type="button" class="fbx-btn fbx-btn--ghost fbx-btn--icon fbx-btn--sm" data-act="trashrefresh" title="${esc(__('Refresh', 'cloverbrowser'))}" aria-label="${esc(__('Refresh', 'cloverbrowser'))}">${ICONS.refresh}</button>
                <button type="button" class="fbx-btn fbx-btn--sm fbx-btn--danger-outline" data-act="trashempty"></button>
            </span>
        </div>
        <p class="fbx-trash-note"></p>
        <div class="fbx-trash-list">
            <div class="fbx-trash-cols" aria-hidden="true">
                <span>${esc(_x('Name', 'column header', 'cloverbrowser'))}</span>
                <span class="fbx-tcol--deleted">${esc(__('Deleted', 'cloverbrowser'))}</span>
                <span class="fbx-tcol--until">${esc(__('Kept until', 'cloverbrowser'))}</span>
                <span class="fbx-tcol--size">${esc(_x('Size', 'column header', 'cloverbrowser'))}</span>
                <span></span>
            </div>
            <div class="fbx-trash-rows" role="list"></div>
        </div>
        <div class="fbx-trash-foot"></div>
    </section>
    <div class="fbx-upload-strip" hidden>
        <span class="fbx-upload-name"></span>
        <span class="fbx-progress"><span class="fbx-progress-bar"></span></span>
    </div>
    <div class="fbx-toasts" aria-live="polite"></div>
    <iframe class="fbx-dl-frame" name="fbx-dl-frame" title="${esc(__('Download helper', 'cloverbrowser'))}" tabindex="-1" aria-hidden="true"></iframe>
</div>
<input type="file" class="fbx-file-input" multiple hidden>`;

    const $ = (sel) => ROOT.querySelector(sel);
    const els = {
        busy: $('.fbx-busy'),
        status: $('.fbx-status-text'),
        crumb: $('.fbx-crumb'),
        listPane: $('.fbx-list-pane'),
        rows: $('.fbx-rows'),
        foot: $('.fbx-list-foot'),
        drop: $('.fbx-drop'),
        cols: Array.from(ROOT.querySelectorAll('.fbx-col[data-sort]')),
        editorPane: $('.fbx-editor-pane'),
        fileName: $('.fbx-filename'),
        chips: $('.fbx-chips'),
        draftInd: $('.fbx-draft-ind'),
        code: $('.fbx-code'),
        saveBtn: $('[data-act="save"]'),
        revertBtn: $('[data-act="revert"]'),
        eol: $('.fbx-eol'),
        eolText: $('.fbx-eol-text'),
        eolBtn: $('[data-act="eolconvert"]'),
        tools: {
            up: $('[data-act="up"]'),
            mkdir: $('[data-act="mkdir"]'),
            mkfile: $('[data-act="mkfile"]'),
            upload: $('[data-act="upload"]'),
        },
        toasts: $('.fbx-toasts'),
        fileInput: $('.fbx-file-input'),
        strip: $('.fbx-upload-strip'),
        stripName: $('.fbx-upload-name'),
        stripBar: $('.fbx-progress-bar'),
        dlFrame: $('.fbx-dl-frame'),
        toolbar: $('.fbx-toolbar'),
        main: $('.fbx-main'),
        trashBtn: $('[data-act="trash"]'),
        trashCount: $('.fbx-trash-btn .fbx-count'),
        trash: $('.fbx-trash'),
        trashTitle: $('.fbx-trash-title'),
        trashNote: $('.fbx-trash-note'),
        trashRows: $('.fbx-trash-rows'),
        trashFoot: $('.fbx-trash-foot'),
        trashEmpty: $('[data-act="trashempty"]'),
        trashTabs: Array.from(ROOT.querySelectorAll('.fbx-tab')),
        trashCols: $('.fbx-trash-cols'),
    };

    const modalLayer = document.createElement('div');
    modalLayer.className = 'fbx-modal-layer';
    document.body.append(modalLayer);

    /* ------------------------------------------------------------------ */
    /* Small utilities                                                    */
    /* ------------------------------------------------------------------ */

    const baseName = (p) => p.slice(p.lastIndexOf('/') + 1);
    const parentDir = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
    const joinPath = (dir, name) => (dir ? dir + '/' + name : name);
    const isUnder = (p, base) => p === base || p.startsWith(base + '/');
    const extOf = (p) => {
        const b = baseName(p);
        const i = b.lastIndexOf('.');
        return i > 0 ? b.slice(i + 1).toLowerCase() : '';
    };
    const padPerms = (p) => String(p).padStart(4, '0');
    const byteLen = (s) => new Blob([s]).size;

    const NUM_LOCALE = (document.documentElement.lang || 'en').replace('_', '-');
    function fmtNum(n, digits) {
        try {
            return new Intl.NumberFormat(NUM_LOCALE, { maximumFractionDigits: digits, minimumFractionDigits: digits }).format(n);
        } catch (e) {
            return n.toFixed(digits);
        }
    }
    function fmtSize(b) {
        /* translators: %s: file size in bytes */
        if (!b || b < 1024) return sprintf(__('%s B', 'cloverbrowser'), fmtNum(b || 0, 0));
        const u = [
            /* translators: %s: file size in kilobytes */
            __('%s KB', 'cloverbrowser'),
            /* translators: %s: file size in megabytes */
            __('%s MB', 'cloverbrowser'),
            /* translators: %s: file size in gigabytes */
            __('%s GB', 'cloverbrowser'),
            /* translators: %s: file size in terabytes */
            __('%s TB', 'cloverbrowser'),
        ];
        let i = -1;
        do { b /= 1024; i++; } while (b >= 1024 && i < 3);
        return sprintf(u[i], fmtNum(b, b >= 100 ? 0 : 1));
    }

    function validName(v) {
        if (!v) return __('Enter a name.', 'cloverbrowser');
        if (/[\\/]/.test(v) || v === '.' || v === '..') return __('Names cannot contain slashes or be “.” / “..”.', 'cloverbrowser');
        if (/[\u0000-\u001F\u007F]/.test(v)) return __('Names cannot contain control characters.', 'cloverbrowser');
        return null;
    }

    function setStatus(text) { els.status.textContent = text; }

    function busyStart(label) {
        busyCount++;
        els.busy.hidden = false;
        setStatus(label || __('Working…', 'cloverbrowser'));
    }
    function busyEnd() {
        busyCount = Math.max(0, busyCount - 1);
        if (busyCount === 0) {
            els.busy.hidden = true;
            setStatus(__('Ready', 'cloverbrowser'));
        }
    }

    /* ------------------------------------------------------------------ */
    /* API (fetch — one request per operation, JSON errors with codes)    */
    /* ------------------------------------------------------------------ */

    async function api(action, data) {
        const fd = new NATIVE.FormData();
        if (data) {
            for (const [k, v] of Object.entries(data)) {
                if (v !== undefined && v !== null) fd.append(k, String(v));
            }
        }
        fd.append('action', 'cloverbrowser_' + action);
        fd.append('nonce', NONCE);

        let res;
        try {
            res = await NATIVE.fetch(CFG.ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin', cache: 'no-store' });
        } catch (e) {
            throw Object.assign(new Error(__('Network error — the server may be busy or unreachable.', 'cloverbrowser')), { code: 'fbf_network' });
        }
        let json = null;
        try { json = NATIVE.parse(await res.text()); } catch (e) { /* fatal / HTML error page / "0" */ }
        if (!json || typeof json !== 'object') {
            throw Object.assign(new Error(sprintf(
                /* translators: %d: HTTP status code */
                __('Unexpected server response (HTTP %d).', 'cloverbrowser'), res.status)), { code: 'fbf_bad_response' });
        }
        if (!json.success) {
            throw Object.assign(new Error((json.data && json.data.message) || __('Request failed.', 'cloverbrowser')), { code: (json.data && json.data.code) || null });
        }
        return json.data || {};
    }

    // Keep the nonce fresh during long sessions. Rotated through our own
    // authenticated endpoint (never broadcast through heartbeat events).
    setInterval(() => {
        api('nonce').then((d) => { if (d && typeof d.nonce === 'string') NONCE = d.nonce; }).catch(() => {});
    }, 20 * 60 * 1000);

    /* ------------------------------------------------------------------ */
    /* Toasts & modals                                                    */
    /* ------------------------------------------------------------------ */

    /** action: optional { label, run } — shown as a button (e.g. "Undo"). */
    function toast(msg, kind, ms, action) {
        while (els.toasts.children.length >= 5) els.toasts.firstElementChild.remove();
        const t = document.createElement('div');
        t.className = 'fbx-toast fbx-toast--' + (kind || 'info');
        t.setAttribute('role', kind === 'error' ? 'alert' : 'status');
        const text = document.createElement('span');
        text.className = 'fbx-toast-text';
        text.textContent = msg;
        t.append(text);
        els.toasts.append(t);
        const dismiss = () => { clearTimeout(timer); if (t.parentNode) t.remove(); };
        const timer = setTimeout(dismiss, ms || (action ? 9000 : 4200));
        if (action) {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'fbx-toast-act';
            b.textContent = action.label;
            b.addEventListener('click', (ev) => {
                ev.stopPropagation();
                if (!trusted(ev)) return;
                dismiss();
                action.run();
            });
            t.append(b);
        }
        t.addEventListener('click', dismiss);
    }

    let closeActiveModal = null;
    const isModalOpen = () => modalLayer.classList.contains('is-open');

    function modal(opts) {
        if (closeActiveModal) closeActiveModal(null); // never orphan an unresolved promise
        return new Promise((resolve) => {
            const panel = document.createElement('div');
            panel.className = 'fbx-modal';
            panel.setAttribute('role', 'dialog');
            panel.setAttribute('aria-modal', 'true');

            const h = document.createElement('h3');
            h.id = 'fbx-modal-title';
            h.textContent = opts.title;
            panel.setAttribute('aria-labelledby', h.id);
            panel.append(h);

            const body = document.createElement('div');
            body.className = 'fbx-modal-body';
            if (typeof opts.body === 'string') {
                const p = document.createElement('p');
                p.textContent = opts.body;
                body.append(p);
            } else if (opts.body instanceof Node) {
                body.append(opts.body);
            }
            panel.append(body);

            const bar = document.createElement('div');
            bar.className = 'fbx-modal-actions';
            let done = false;
            const lastFocus = document.activeElement;

            const finish = (v) => {
                if (done) return;
                done = true;
                closeActiveModal = null;
                document.removeEventListener('keydown', onKey, true);
                modalLayer.classList.remove('is-open');
                modalLayer.replaceChildren();
                modalLayer.onmousedown = null;
                resolve(v);
                if (lastFocus && lastFocus.isConnected) { try { lastFocus.focus(); } catch (e) { /* noop */ } }
            };
            const onKey = (e) => {
                if (e.key === 'Escape') {
                    e.preventDefault();
                    e.stopPropagation();
                    finish(null);
                } else if (e.key === 'Tab') { // simple focus trap
                    const f = Array.from(panel.querySelectorAll('button, input, textarea, select, [tabindex]:not([tabindex="-1"])'))
                        .filter((el) => !el.disabled && el.offsetParent !== null);
                    if (!f.length) return;
                    const first = f[0];
                    const last = f[f.length - 1];
                    if (!panel.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
                    else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
                }
            };

            const actions = opts.actions || [{ label: __('OK', 'cloverbrowser'), kind: 'primary', value: true }];
            const invoke = (a) => {
                const v = typeof a.resolve === 'function' ? a.resolve() : (a.value !== undefined ? a.value : null);
                if (v === KEEP_OPEN) return;
                finish(v);
            };
            actions.forEach((a) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'fbx-btn' + (a.kind === 'primary' ? ' fbx-btn--primary' : a.kind === 'danger' ? ' fbx-btn--danger' : '');
                b.textContent = a.label;
                b.addEventListener('click', (ev) => {
                    if (!trusted(ev)) return; // scripted clicks cannot confirm dialogs
                    invoke(a);
                });
                bar.append(b);
            });
            panel.append(bar);

            closeActiveModal = finish;
            modalLayer.replaceChildren(panel);
            modalLayer.classList.add('is-open');
            document.addEventListener('keydown', onKey, true);
            modalLayer.onmousedown = (e) => { if (e.target === modalLayer) finish(null); };

            const first = panel.querySelector('input:not([type="checkbox"]), textarea, button');
            if (first) first.focus();
            if (opts.onOpen) opts.onOpen({ panel, finish, submit: () => invoke(actions[actions.length - 1]) });
        });
    }

    function confirmModal(title, message, opts) {
        const o = opts || {};
        return modal({
            title,
            body: message,
            actions: [
                { label: __('Cancel', 'cloverbrowser'), value: null },
                { label: o.okLabel || __('Confirm', 'cloverbrowser'), kind: o.danger ? 'danger' : 'primary', value: true },
            ],
        });
    }

    function promptModal(opts) {
        const wrap = document.createElement('label');
        wrap.className = 'fbx-field';
        const lab = document.createElement('span');
        lab.textContent = opts.label;
        const input = document.createElement('input');
        input.type = 'text';
        input.value = opts.value || '';
        input.spellcheck = false;
        input.autocomplete = 'off';
        const err = document.createElement('div');
        err.className = 'fbx-field-err';
        err.setAttribute('role', 'alert');
        wrap.append(lab, input, err);

        return modal({
            title: opts.title,
            body: wrap,
            actions: [
                { label: __('Cancel', 'cloverbrowser'), value: null },
                {
                    label: __('OK', 'cloverbrowser'), kind: 'primary',
                    resolve: () => {
                        const v = input.value.trim();
                        const msg = opts.validate ? opts.validate(v) : null;
                        if (msg) { err.textContent = msg; return KEEP_OPEN; }
                        return v === '' ? null : v;
                    },
                },
            ],
            onOpen({ submit }) {
                input.focus();
                // Select the base name only ("index" of "index.php"), like file managers do.
                const dot = input.value.lastIndexOf('.');
                if (dot > 0) input.setSelectionRange(0, dot); else input.select();
                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' && trusted(e)) {
                        e.preventDefault();
                        submit();
                    }
                });
            },
        });
    }

    /* ------------------------------------------------------------------ */
    /* Directory listing                                                  */
    /* ------------------------------------------------------------------ */

    /** Open a folder (resets scroll and paging). */
    function navigate(rel) {
        return loadList(rel, true);
    }

    /** Re-list the current folder, keeping scroll position and paging. */
    function refresh() {
        return loadList(state.cwd, false);
    }

    async function loadList(target, isNav) {
        const seq = ++state.listSeq;
        const scrollTop = isNav ? 0 : els.rows.scrollTop;
        busyStart(target
            /* translators: %s: folder name */
            ? sprintf(__('Loading %s…', 'cloverbrowser'), baseName(target))
            : __('Loading root…', 'cloverbrowser'));
        try {
            const data = await api('list', { path: target });
            if (seq !== state.listSeq) return; // a newer listing superseded this one
            state.cwd = data.path || '';
            state.entries = data.entries || [];
            state.total = data.total || state.entries.length;
            state.truncated = !!data.truncated;
            state.dirNav = !!data.nav;
            state.dirProtected = !!data.protected;
            if (isNav) state.shown = 500;
            updateToolbar();
            renderCrumb();
            renderList();
            els.rows.scrollTop = scrollTop;
        } catch (e) {
            if (seq === state.listSeq) toast(e.message, 'error', 6500);
        } finally {
            busyEnd();
        }
    }

    /** Enable/disable toolbar actions for the current folder. */
    function updateToolbar() {
        const blocked = state.dirNav || state.dirProtected;
        const why = state.dirNav
            ? __('Open one of the folders you have access to first.', 'cloverbrowser')
            : __('This folder is protected: your role can only read it.', 'cloverbrowser');
        for (const k of ['mkdir', 'mkfile', 'upload']) {
            const b = els.tools[k];
            if (!b) continue;
            b.disabled = blocked;
            if (blocked) b.title = why; else b.removeAttribute('title');
        }
        if (els.tools.up) els.tools.up.disabled = state.cwd === '';
    }

    function refreshSoft() {
        clearTimeout(softTimer);
        softTimer = setTimeout(() => refresh(), 400);
    }

    function renderCrumb() {
        els.crumb.replaceChildren();
        const rootBtn = document.createElement('button');
        rootBtn.type = 'button';
        rootBtn.textContent = CFG.rootLabel || _x('root', 'top-level folder', 'cloverbrowser');
        rootBtn.addEventListener('click', () => navigate(''));
        els.crumb.append(rootBtn);
        let acc = '';
        for (const seg of (state.cwd ? state.cwd.split('/') : [])) {
            acc = acc ? acc + '/' + seg : seg;
            const target = acc;
            const sep = document.createElement('span');
            sep.className = 'fbx-crumb-sep';
            sep.textContent = '/';
            const b = document.createElement('button');
            b.type = 'button';
            b.textContent = seg;
            b.addEventListener('click', () => navigate(target));
            els.crumb.append(sep, b);
        }
        const last = els.crumb.lastElementChild;
        if (last) last.setAttribute('aria-current', 'location');
    }

    function sortedEntries() {
        const key = state.sort.key;
        const dir = state.sort.dir;
        const permVal = (x) => parseInt(x.perms, 8) || 0;
        return state.entries.slice().sort((a, b) => {
            if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
            let r;
            if (key === 'name') {
                r = a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
            } else if (key === 'perms') {
                r = permVal(a) - permVal(b);
            } else {
                r = (a[key] || 0) - (b[key] || 0);
            }
            if (r === 0 && key !== 'name') r = a.name.localeCompare(b.name, undefined, { numeric: true });
            return r * dir;
        });
    }

    function actBtn(act, icon, title, danger) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'fbx-row-btn' + (danger ? ' fbx-act--danger' : '');
        b.dataset.act = act;
        b.title = title;
        b.setAttribute('aria-label', title);
        b.innerHTML = icon;
        return b;
    }

    // Row → entry. Authoritative for every action; the data-* attributes on
    // rows are informational only and are never read back.
    const rowData = new WeakMap();

    function buildRow(e) {
        const row = document.createElement('div');
        rowData.set(row, Object.freeze(Object.assign({}, e)));
        row.className = 'fbx-row' + (e.is_dir ? ' fbx-row--dir' : '') + (e.broken ? ' fbx-row--broken' : '')
            + (e.locked ? ' fbx-row--locked' : '') + (e.nav ? ' fbx-row--nav' : '');
        row.tabIndex = 0;
        row.setAttribute('aria-label', sprintf(e.is_dir
            /* translators: %s: folder name */
            ? __('Open folder %s', 'cloverbrowser')
            /* translators: %s: file name */
            : __('Open file %s', 'cloverbrowser'), e.name));
        row.dataset.rel = e.rel; // informational only (see rowData)
        if (e.is_link && e.link_target) {
            row.title = '→ ' + e.link_target + (e.broken ? ' ' + __('(broken link)', 'cloverbrowser') : '');
        }

        const name = document.createElement('div');
        name.className = 'fbx-cell fbx-name';
        const ico = document.createElement('span');
        ico.className = 'fbx-ico';
        ico.innerHTML = e.is_link ? ICONS.link : (e.is_dir ? ICONS.folder : ICONS.file);
        const label = document.createElement('span');
        label.textContent = e.name;
        label.title = e.name;
        name.append(ico, label);
        const badge = (icon, text) => {
            const b = document.createElement('span');
            b.className = 'fbx-badge';
            b.innerHTML = icon; // static SVG
            b.title = text;
            b.setAttribute('aria-label', text);
            b.setAttribute('role', 'img');
            name.append(b);
        };
        if (e.locked) {
            badge(ICONS.lock, sprintf(
                /* translators: %s: file type name, e.g. "PHP code" */
                __('Blocked file type for your role: %s', 'cloverbrowser'), e.locked_reason || ''));
        } else if (e.protected) {
            badge(ICONS.eye, __('Protected: your role can only read this.', 'cloverbrowser'));
        }
        row.append(name);

        const size = document.createElement('div');
        size.className = 'fbx-cell fbx-cell--num fbx-cell--size';
        size.textContent = e.is_dir ? '—' : fmtSize(e.size || 0);
        row.append(size);

        const pr = document.createElement('div');
        pr.className = 'fbx-cell fbx-cell--perms';
        pr.textContent = padPerms(e.perms || '000');
        if (e.owner) pr.title = (e.owner || '?') + ':' + (e.group || '?') + (e.writable ? '' : ' — ' + __('not writable by PHP', 'cloverbrowser'));
        row.append(pr);

        const mt = document.createElement('div');
        mt.className = 'fbx-cell fbx-cell--num fbx-cell--mtime';
        mt.textContent = e.modified || '';
        row.append(mt);

        const act = document.createElement('div');
        act.className = 'fbx-cell fbx-row-act';
        const fixed = e.nav || e.root || e.protected; // cannot be changed by this user
        const openable = !e.is_dir && !e.broken && !e.locked;
        // Fixed slots (one per action this user can ever have) keep icons in columns.
        const slots = [
            [can('download'), openable, () => actBtn('download', ICONS.download, __('Download', 'cloverbrowser'))],
            [!!PERMS.view, openable, () => actBtn('edit', ICONS.edit, can('edit') && !e.protected ? __('Open in editor', 'cloverbrowser') : __('View', 'cloverbrowser'))],
            [can('chmod'), !fixed && !e.broken, () => actBtn('perms', ICONS.perms, __('Change permissions', 'cloverbrowser'))],
            [can('rename'), !fixed, () => actBtn('rename', ICONS.rename, __('Rename', 'cloverbrowser'))],
            [can('delete'), !fixed, () => actBtn('delete', ICONS.trash, __('Delete', 'cloverbrowser'), true)],
        ];
        for (const [userCan, applies, make] of slots) {
            if (!userCan) continue;
            act.append(applies ? make() : Object.assign(document.createElement('span'), { className: 'fbx-row-slot' }));
        }
        row.append(act);

        return row;
    }

    function renderList() {
        els.cols.forEach((c) => {
            const active = c.dataset.sort === state.sort.key;
            c.classList.toggle('is-sorted', active);
            c.classList.toggle('is-desc', active && state.sort.dir === -1);
            if (active) c.setAttribute('aria-sort', state.sort.dir === 1 ? 'ascending' : 'descending');
            else c.removeAttribute('aria-sort');
        });

        const sorted = sortedEntries();
        const scrollTop = els.rows.scrollTop;
        const frag = document.createDocumentFragment();
        const count = Math.min(sorted.length, state.shown);

        if (count === 0) {
            const empty = document.createElement('div');
            empty.className = 'fbx-empty';
            empty.textContent = __('This folder is empty.', 'cloverbrowser');
            frag.append(empty);
        }
        for (let i = 0; i < count; i++) frag.append(buildRow(sorted[i]));

        els.rows.replaceChildren(frag);
        els.rows.scrollTop = scrollTop;

        els.foot.replaceChildren();
        const info = document.createElement('span');
        let text = count === sorted.length
            /* translators: %s: number of items in the folder */
            ? sprintf(_n('%s item', '%s items', sorted.length, 'cloverbrowser'), fmtNum(sorted.length, 0))
            /* translators: 1: number of items shown, 2: total number of items */
            : sprintf(_n('%1$s of %2$s shown', '%1$s of %2$s shown', sorted.length, 'cloverbrowser'), fmtNum(count, 0), fmtNum(sorted.length, 0));
        if (state.truncated) {
            text += ' — ' + sprintf(
                /* translators: 1: total number of entries in the folder, 2: number of entries listed */
                _n('folder has %1$s entries; only the first %2$s are listed', 'folder has %1$s entries; only the first %2$s are listed', state.total, 'cloverbrowser'),
                fmtNum(state.total, 0), fmtNum(sorted.length, 0)
            );
        }
        info.textContent = text;
        els.foot.append(info);
        if (count < sorted.length) {
            const more = document.createElement('button');
            more.type = 'button';
            more.className = 'fbx-btn fbx-btn--ghost';
            more.textContent = __('Show more', 'cloverbrowser');
            more.addEventListener('click', () => {
                state.shown += 500;
                renderList();
            });
            els.foot.append(more);
        }
    }

    els.cols.forEach((c) => {
        c.addEventListener('click', () => {
            const k = c.dataset.sort;
            if (state.sort.key === k) state.sort.dir *= -1;
            else { state.sort.key = k; state.sort.dir = 1; }
            renderList();
        });
    });

    /* ------------------------------------------------------------------ */
    /* Row actions                                                        */
    /* ------------------------------------------------------------------ */

    function rowAct(act, row) {
        const e = rowData.get(row);
        if (!e) return;
        const rel = e.rel;
        const name = e.name;
        const isDir = !!e.is_dir;
        const perms = e.perms || '0';
        if (e.broken && (act === 'open' || act === 'edit' || act === 'download')) {
            toast(sprintf(
                /* translators: %s: symbolic link target path */
                __('Broken symbolic link → %s', 'cloverbrowser'), e.link_target || '?'), 'warn');
            return;
        }
        if (!isDir && e.locked && act !== 'rename' && act !== 'delete' && act !== 'perms') {
            toast(sprintf(
                /* translators: %s: file type name, e.g. "PHP code" */
                __('Blocked file type for your role: %s', 'cloverbrowser'), e.locked_reason || ''), 'warn');
            return;
        }
        if (!isDir && act === 'open' && !PERMS.view) {
            if (can('download')) downloadFile(rel, name);
            else toast(__('Your role is not allowed to open files.', 'cloverbrowser'), 'warn');
            return;
        }
        switch (act) {
            case 'open': if (isDir) navigate(rel); else openFile(rel); break;
            case 'download': downloadFile(rel, name); break;
            case 'edit': openFile(rel); break;
            case 'perms': chmodDialog(rel, name, isDir, perms); break;
            case 'rename': renameDialog(rel, name); break;
            case 'delete': deleteDialog(rel, name, isDir); break;
        }
    }

    // Downloads are a POST into a hidden iframe: the nonce never appears in a
    // URL (history, logs, Referer) and an error never navigates away from the
    // editor. Successful attachments don't fire "load"; error pages do.
    let dlPending = false;
    els.dlFrame.addEventListener('load', () => {
        if (!dlPending) return;
        dlPending = false;
        let msg = '';
        try { msg = (els.dlFrame.contentDocument.body.textContent || '').trim(); } catch (e) { /* noop */ }
        toast(msg
            /* translators: %s: error message */
            ? sprintf(__('Download failed: %s', 'cloverbrowser'), msg.slice(0, 300))
            : __('Download failed.', 'cloverbrowser'), 'error', 7000);
        setStatus(__('Ready', 'cloverbrowser'));
    });

    function downloadFile(rel, name) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = CFG.ajaxUrl;
        form.target = 'fbx-dl-frame';
        form.hidden = true;
        for (const [k, v] of [['action', 'cloverbrowser_download'], ['nonce', NONCE], ['path', rel]]) {
            const i = document.createElement('input');
            i.type = 'hidden';
            i.name = k;
            i.value = v;
            form.append(i);
        }
        document.body.append(form);
        dlPending = true;
        form.submit();
        form.remove();
        toast(sprintf(
            /* translators: %s: file name */
            __('Download started — %s', 'cloverbrowser'), name || baseName(rel)), 'info', 2500);
    }

    /* ------------------------------------------------------------------ */
    /* File editor: open / mount / autosave / save / revert / close       */
    /* ------------------------------------------------------------------ */

    /** Ask what to do with unsaved edits before the editor is replaced. Resolves true to proceed. */
    async function leaveCurrentFile() {
        if (!state.file || !state.dirty) return true;
        const file = state.file;
        const choice = await modal({
            title: __('Unsaved changes', 'cloverbrowser'),
            body: sprintf(
                /* translators: %s: file name */
                __('“%s” has unsaved changes. Keep them as a draft (restorable next time you open the file) or discard them?', 'cloverbrowser'),
                file.name
            ),
            actions: [
                { label: __('Cancel', 'cloverbrowser'), value: null },
                { label: __('Discard changes', 'cloverbrowser'), kind: 'danger', value: 'discard' },
                { label: __('Keep as draft', 'cloverbrowser'), kind: 'primary', value: 'keep' },
            ],
        });
        if (!choice || state.file !== file) return !!choice;
        if (choice === 'discard') {
            clearTimeout(autoTimer);
            if (draftPromise) await draftPromise;
            try { await api('draft_discard', { path: file.rel }); } catch (e) { /* nothing to discard */ }
            state.dirty = false;
            return true;
        }
        const ok = await flushDraft();
        if (!ok) {
            toast(__('Could not store the draft — your edits are still in the editor.', 'cloverbrowser'), 'error', 7000);
            return false;
        }
        state.dirty = false; // safely stored as a draft
        return true;
    }

    async function openFile(rel) {
        if (state.file && state.file.rel === rel) { focusEditor(); return; }
        if (!(await leaveCurrentFile())) return;

        const seq = ++state.fileSeq;
        const name = baseName(rel);
        busyStart(sprintf(
            /* translators: %s: file name */
            __('Opening %s…', 'cloverbrowser'), name));
        try {
            let data;
            try {
                data = await api('read', { path: rel });
            } catch (e) {
                if (seq !== state.fileSeq) return;
                if (e.code === 'fbf_binary' || e.code === 'fbf_too_big' || e.code === 'fbf_encoding') {
                    const want = await modal({
                        title: __('Cannot open in editor', 'cloverbrowser'),
                        body: e.message,
                        actions: [
                            { label: __('Close', 'cloverbrowser'), value: null },
                            { label: __('Download instead', 'cloverbrowser'), kind: 'primary', value: true },
                        ],
                    });
                    if (want) downloadFile(rel, name);
                } else if (e.code === 'fbf_not_found') {
                    toast(__('File no longer exists — refreshing.', 'cloverbrowser'), 'warn');
                    refreshSoft();
                } else {
                    toast(e.message, 'error', 6500);
                }
                return;
            }
            if (seq !== state.fileSeq) return;

            if (data.draft) {
                const d = data.draft;
                const msg = (d.author
                    /* translators: 1: date and time, 2: user display name, 3: draft size */
                    ? sprintf(__('An autosaved draft exists for this file (saved %1$s by %2$s, %3$s).', 'cloverbrowser'), d.modified, d.author, fmtSize(d.size))
                    /* translators: 1: date and time, 2: draft size */
                    : sprintf(__('An autosaved draft exists for this file (saved %1$s, %2$s).', 'cloverbrowser'), d.modified, fmtSize(d.size))) +
                    (d.stale ? ' ' + __('Warning: the file has changed on disk since that draft was made.', 'cloverbrowser') : '') +
                    ' ' + __('Which version do you want?', 'cloverbrowser');
                const choice = await modal({
                    title: __('Unsaved draft found', 'cloverbrowser'),
                    body: msg,
                    actions: [
                        { label: __('Open original', 'cloverbrowser'), value: 'original' },
                        { label: __('Delete draft', 'cloverbrowser'), value: 'discard', kind: 'danger' },
                        { label: __('Restore draft', 'cloverbrowser'), value: 'draft', kind: 'primary' },
                    ],
                });
                if (choice === null || seq !== state.fileSeq) return;
                if (choice === 'discard') {
                    try {
                        await api('draft_discard', { path: rel });
                        toast(__('Draft deleted.', 'cloverbrowser'), 'success');
                    } catch (e2) {
                        toast(sprintf(
                            /* translators: %s: error message */
                            __('Could not delete draft: %s', 'cloverbrowser'), e2.message), 'error');
                    }
                }
                if (choice === 'draft') {
                    try {
                        const dr = await api('draft_read', { path: rel });
                        data.draftContent = dr.content;
                    } catch (e2) {
                        toast(__('Could not read draft — opening the original instead.', 'cloverbrowser') + ' ' + e2.message, 'error');
                    }
                }
            }
            if (seq !== state.fileSeq) return;
            mountEditor(rel, data);
        } finally {
            busyEnd();
        }
    }

    function focusEditor() {
        if (state.cm) state.cm.codemirror.focus();
        else els.code.focus();
    }

    function mountEditor(rel, data) {
        teardownEditor(); // clean slate — no leaked listeners or CM instances

        const restored = typeof data.draftContent === 'string';
        const content = restored ? data.draftContent : data.content;

        state.file = {
            rel: rel,
            name: baseName(rel),
            size: data.size || 0,
            perms: data.perms || '000',
            writable: !!data.writable,
            mtime: data.mtime || 0,
            modified: data.modified || '',
            hash: data.hash || '',
            eol: data.eol || 'none',          // 'none' | 'lf' | 'crlf' | 'cr' | 'mixed'
            editable: can('edit') && !data.protected,
        };

        els.editorPane.hidden = false;
        els.fileName.textContent = state.file.name;
        els.fileName.title = rel;
        renderChips();
        setDraftInd(null);

        els.code.value = content;
        els.code.readOnly = !state.file.editable;
        if (els.saveBtn) els.saveBtn.hidden = !state.file.editable;
        if (els.revertBtn) els.revertBtn.hidden = !state.file.editable;
        state.eolDismissed = false;
        renderEol();
        if (NO_CM) {
            // Plain textarea (syntax highlighting disabled in the user's profile, or CodeMirror unavailable).
            els.code.oninput = onEditChange;
        } else {
            const base = CFG.codeEditor;
            const settings = Object.assign({}, base, {
                codemirror: Object.assign({}, base.codemirror || {}, {
                    mode: MODES[extOf(rel)] || 'text/plain',
                    lineNumbers: true,
                    lineWrapping: true,
                    indentUnit: 4,
                    tabSize: 4,
                    readOnly: !state.file.editable,
                    lint: false,
                }),
            });
            delete settings.csslint;
            delete settings.jshint;
            delete settings.htmlhint;
            state.cm = window.wp.codeEditor.initialize(els.code, settings);
            state.cm.codemirror.on('change', onEditChange);
            state.cm.codemirror.refresh();
        }
        state.lastAutosaved = restored ? editorContent() : null;
        state.dirty = restored && editorContent() !== data.content;
        if (restored) setDraftInd(state.dirty ? __('Draft restored — not saved to disk yet', 'cloverbrowser') : __('Draft matches file', 'cloverbrowser'), state.dirty ? 'busy' : 'ok');
        focusEditor();
    }

    function teardownEditor() {
        if (state.cm) {
            try { state.cm.codemirror.toTextArea(); } catch (e) { /* noop */ }
            state.cm = null;
        }
        clearTimeout(autoTimer);
        state.file = null;
        state.dirty = false;
        state.lastAutosaved = '';
        els.code.oninput = null;
        els.code.value = '';
        els.editorPane.hidden = true;
        els.eol.hidden = true;
        setDraftInd(null);
    }

    const eolKindLabel = (k) => ({
        crlf: __('Windows (CRLF)', 'cloverbrowser'),
        cr: __('classic Mac (CR)', 'cloverbrowser'),
        lf: __('Unix (LF)', 'cloverbrowser'),
        mixed: __('mixed', 'cloverbrowser'),
    }[k] || k);

    /** Banner offering to convert a file's line endings to the server's. */
    function renderEol() {
        const f = state.file;
        const differs = f && f.eol !== 'none' && f.eol !== SERVER_EOL_NAME;
        if (!differs || state.eolDismissed) {
            els.eol.hidden = true;
            return;
        }
        els.eolText.textContent = sprintf(
            /* translators: 1: line-ending style of the file, e.g. "Windows (CRLF)", 2: the server's style, e.g. "Unix (LF)" */
            __('This file uses %1$s line endings. Saving converts them to %2$s, this server’s format.', 'cloverbrowser'),
            eolKindLabel(f.eol), eolKindLabel(SERVER_EOL_NAME)
        );
        els.eolBtn.textContent = sprintf(
            /* translators: %s: line-ending name, e.g. "LF" */
            __('Convert to %s now', 'cloverbrowser'), EOL_LABEL[SERVER_EOL_NAME]);
        els.eolBtn.hidden = !f.editable;
        els.eol.hidden = false;
    }

    async function convertEol() {
        const f = state.file;
        if (!f || !f.editable) return;
        if (state.dirty) {
            toast(__('Save or discard your edits first — saving converts the line endings anyway.', 'cloverbrowser'), 'warn', 6000);
            return;
        }
        const rel = f.rel;
        busyStart(__('Converting line endings…', 'cloverbrowser'));
        try {
            await api('convert_eol', { path: rel });
            toast(sprintf(
                /* translators: 1: file name, 2: line-ending name, e.g. "LF" */
                __('%1$s now uses %2$s line endings.', 'cloverbrowser'), f.name, EOL_LABEL[SERVER_EOL_NAME]), 'success');
            teardownEditor();
            await openFile(rel);
            refreshSoft();
        } catch (e) {
            toast(e.message, 'error', 6500);
        } finally {
            busyEnd();
        }
    }

    function renderChips() {
        const f = state.file;
        els.chips.replaceChildren();
        if (!f) return;
        const add = (text, cls, title) => {
            const s = document.createElement('span');
            s.className = 'fbx-chip' + (cls ? ' fbx-chip--' + cls : '');
            s.textContent = text;
            if (title) s.title = title;
            els.chips.append(s);
        };
        add(fmtSize(f.size));
        add(padPerms(f.perms), 'ltr');
        if (f.modified) add(f.modified, 'ltr');
        if (f.eol !== 'none') {
            add(EOL_LABEL[f.eol] || __('mixed', 'cloverbrowser'), f.eol === SERVER_EOL_NAME ? 'ltr' : 'warn',
                sprintf(
                    /* translators: %s: line-ending style, e.g. "Windows (CRLF)" */
                    __('Line endings: %s', 'cloverbrowser'), eolKindLabel(f.eol)));
        }
        if (!f.editable) add(__('view only', 'cloverbrowser'), 'warn');
        else if (!f.writable) add(__('read-only for PHP', 'cloverbrowser'), 'warn');
    }

    function setDraftInd(text, kind) {
        const el = els.draftInd;
        if (!text) {
            el.hidden = true;
            el.textContent = '';
            el.className = 'fbx-draft-ind';
            return;
        }
        el.hidden = false;
        el.textContent = text;
        el.className = 'fbx-draft-ind' + (kind ? ' is-' + kind : '');
    }

    /** Current editor text — always in the server's native line endings. */
    function editorContent() {
        if (state.cm) return state.cm.codemirror.getValue(SERVER_EOL);
        const v = els.code.value; // textareas normalise to \n
        return SERVER_EOL === '\n' ? v : v.replace(/\r\n|\r|\n/g, SERVER_EOL);
    }

    function onEditChange() {
        if (!state.file || !state.file.editable) return;
        state.dirty = true;
        setDraftInd(__('Editing — draft autosave pending…', 'cloverbrowser'), 'busy');
        scheduleAutosave();
    }

    function scheduleAutosave() {
        clearTimeout(autoTimer);
        autoTimer = setTimeout(performAutosave, 1500);
    }

    /** Store the current text as a server-side draft. Resolves true on success / nothing to do. */
    function performAutosave() {
        if (!state.file || !state.dirty) return Promise.resolve(true);
        if (draftPromise) { scheduleAutosave(); return draftPromise; } // one in flight: retry after it
        const file = state.file;
        const content = editorContent();
        if (content === state.lastAutosaved) return Promise.resolve(true);

        setDraftInd(__('Saving draft…', 'cloverbrowser'), 'busy');
        draftPromise = api('draft_save', { path: file.rel, content: content, base_hash: file.hash })
            .then(() => {
                if (state.file === file) {
                    state.lastAutosaved = content;
                    setDraftInd(sprintf(
                        /* translators: %s: time of day */
                        __('Draft saved %s', 'cloverbrowser'), new Date().toLocaleTimeString(NUM_LOCALE)), 'ok');
                }
                return true;
            })
            .catch((e) => {
                if (state.file === file) {
                    setDraftInd(__('Draft save failed', 'cloverbrowser'), 'err');
                    toast(sprintf(
                        /* translators: %s: error message */
                        __('Autosave failed: %s', 'cloverbrowser'), e.message), 'error', 6000);
                }
                return false;
            })
            .finally(() => { draftPromise = null; });
        return draftPromise;
    }

    /** Wait for any in-flight autosave, then store the latest text. */
    async function flushDraft() {
        clearTimeout(autoTimer);
        if (draftPromise) await draftPromise;
        if (!state.file) return true;
        if (editorContent() === state.lastAutosaved) return true;
        return performAutosave();
    }

    async function saveFile(force) {
        const file = state.file;
        if (!file || state.saving) return;
        if (!file.editable) {
            toast(__('Read-only mode:', 'cloverbrowser') + ' ' + (CFG.readOnlyReason || __('saving is disabled.', 'cloverbrowser')), 'warn', 6000);
            return;
        }
        if (!file.writable) {
            toast(sprintf(
                /* translators: %s: octal permission mode, e.g. 0644 */
                __('The PHP process cannot write this file (mode %s). Adjust permissions first.', 'cloverbrowser'), padPerms(file.perms)), 'warn', 6000);
            return;
        }
        clearTimeout(autoTimer);

        const content = editorContent();
        if (CFG.maxEdit && byteLen(content) > CFG.maxEdit) {
            toast(sprintf(
                /* translators: %s: size limit, e.g. 2 MB */
                __('Content is larger than the %s editor limit; not saved.', 'cloverbrowser'), fmtSize(CFG.maxEdit)), 'error', 7000);
            return;
        }
        if (CFG.maxGrowth > 0 && byteLen(content) - (file.size || 0) > CFG.maxGrowth) {
            toast(sprintf(
                /* translators: %s: allowed size increase, e.g. 50 KB */
                __('This edit makes the file too much larger: your role may grow a file by at most %s per save.', 'cloverbrowser'), fmtSize(CFG.maxGrowth)), 'error', 7000);
            return;
        }
        let allowEmpty = false;
        if (content === '' && (file.size || 0) > 0) {
            const ok = await confirmModal(
                __('Save empty file?', 'cloverbrowser'),
                __('This will replace the file’s current contents with nothing. Continue?', 'cloverbrowser'),
                { okLabel: __('Save empty', 'cloverbrowser'), danger: true }
            );
            if (!ok || state.file !== file) return;
            allowEmpty = true;
        }

        let retryForce = false;
        state.saving = true;
        busyStart(sprintf(
            /* translators: %s: file name */
            __('Saving %s…', 'cloverbrowser'), file.name));
        if (els.saveBtn) els.saveBtn.disabled = true;
        try {
            const payload = { path: file.rel, content: content, base_hash: file.hash };
            if (allowEmpty) payload.allow_empty = '1';
            if (force) payload.force = '1';
            if (draftPromise) await draftPromise; // don't let a late draft write race the save
            const res = await api('save', payload);
            file.size = res.size || 0;
            file.hash = res.hash || '';
            file.mtime = res.mtime || 0;
            file.modified = res.modified || '';
            if (res.eol) file.eol = res.eol;
            if (state.file === file) {
                renderEol();
                state.lastAutosaved = content;
                state.dirty = editorContent() !== content; // edits typed while saving stay dirty
                if (state.dirty) { setDraftInd(__('Edited since last save', 'cloverbrowser'), 'busy'); scheduleAutosave(); }
                else setDraftInd(null);
                renderChips();
            }
            toast(sprintf(
                /* translators: %s: file name */
                __('Saved %s', 'cloverbrowser'), file.name), 'success');
            refreshSoft();
        } catch (e) {
            if (e.code === 'fbf_conflict') {
                const choice = await modal({
                    title: __('File changed on disk', 'cloverbrowser'),
                    body: sprintf(
                        /* translators: %s: file name */
                        __('“%s” was modified by something else after you opened it. Overwriting will discard those changes.', 'cloverbrowser'),
                        file.name
                    ),
                    actions: [
                        { label: __('Cancel', 'cloverbrowser'), value: null },
                        { label: __('Overwrite', 'cloverbrowser'), kind: 'danger', value: true },
                    ],
                });
                retryForce = !!choice && state.file === file;
            } else {
                toast(sprintf(
                    /* translators: %s: error message */
                    __('Save failed: %s', 'cloverbrowser'), e.message), 'error', 7000);
            }
        } finally {
            state.saving = false;
            if (els.saveBtn) els.saveBtn.disabled = false;
            busyEnd();
        }
        if (retryForce) saveFile(true);
    }

    async function revertFile() {
        if (!state.file) return;
        const ok = await confirmModal(
            __('Revert changes', 'cloverbrowser'),
            __('Discard your edits and the autosaved draft, then reload the file from disk?', 'cloverbrowser'),
            { okLabel: __('Revert', 'cloverbrowser'), danger: true }
        );
        if (!ok || !state.file) return;
        const rel = state.file.rel;
        clearTimeout(autoTimer);
        if (draftPromise) await draftPromise;
        try { await api('draft_discard', { path: rel }); } catch (e) { /* no draft — fine */ }
        teardownEditor();
        await openFile(rel);
    }

    async function closeFile() {
        if (!state.file) return;
        if (!(await leaveCurrentFile())) return;
        teardownEditor();
    }

    /* ------------------------------------------------------------------ */
    /* Chmod / rename / delete dialogs                                    */
    /* ------------------------------------------------------------------ */

    async function chmodDialog(rel, name, isDir, permsStr) {
        const cur = parseInt(permsStr, 8) || 0;
        const special = cur & 0o7000;
        const shifts = { owner: 6, group: 3, world: 0 };
        const bits = [['read', 4], ['write', 2], ['exec', 1]];

        const wrap = document.createElement('div');
        wrap.className = 'fbx-chmod';
        const info = document.createElement('p');
        info.textContent = sprintf(
            /* translators: 1: octal permission mode, 2: path */
            __('Current mode: %1$s — %2$s', 'cloverbrowser'), padPerms(permsStr), rel || '/');
        wrap.append(info);

        const boxes = {};
        const grid = document.createElement('div');
        grid.className = 'fbx-chmod-grid';
        grid.append(Object.assign(document.createElement('span'), { className: 'fbx-chmod-h' }));
        [_x('Read', 'permission', 'cloverbrowser'), _x('Write', 'permission', 'cloverbrowser'), _x('Execute', 'permission', 'cloverbrowser')].forEach((t) => {
            grid.append(Object.assign(document.createElement('span'), { className: 'fbx-chmod-h', textContent: t }));
        });
        const groupLabels = {
            owner: _x('owner', 'permission class', 'cloverbrowser'),
            group: _x('group', 'permission class', 'cloverbrowser'),
            world: _x('world', 'permission class', 'cloverbrowser'),
        };
        const bitLabels = {
            read: _x('Read', 'permission', 'cloverbrowser'),
            write: _x('Write', 'permission', 'cloverbrowser'),
            exec: _x('Execute', 'permission', 'cloverbrowser'),
        };
        for (const g of ['owner', 'group', 'world']) {
            grid.append(Object.assign(document.createElement('span'), { className: 'fbx-chmod-h', textContent: groupLabels[g] }));
            boxes[g] = {};
            for (const [p, val] of bits) {
                const cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.checked = !!((cur >> shifts[g]) & val);
                cb.setAttribute('aria-label', groupLabels[g] + ' — ' + bitLabels[p]);
                cb.dataset.bit = g + '-' + p;
                boxes[g][p] = cb;
                grid.append(cb);
            }
        }
        wrap.append(grid);

        const octRow = document.createElement('label');
        octRow.className = 'fbx-checkline';
        const oct = document.createElement('input');
        oct.type = 'text';
        oct.spellcheck = false;
        oct.inputMode = 'numeric';
        oct.maxLength = 4;
        oct.value = padPerms((cur & 0o7777).toString(8));
        octRow.append(document.createTextNode(__('Mode (octal, e.g. 0644):', 'cloverbrowser') + ' '), oct);
        wrap.append(octRow);

        let rec = null;
        if (isDir) {
            rec = document.createElement('input');
            rec.type = 'checkbox';
            const line = document.createElement('label');
            line.className = 'fbx-checkline';
            line.append(rec, document.createTextNode(' ' + __('Apply recursively to all contents (symlinks skipped; capped server-side)', 'cloverbrowser')));
            wrap.append(line);
        }
        if (special) {
            const note = document.createElement('p');
            note.className = 'fbx-inline-note';
            note.textContent = __('Note: special bits (setuid/setgid/sticky) are currently set. The leading digit controls them.', 'cloverbrowser');
            wrap.append(note);
        }

        const syncBoxes = () => {
            const s = oct.value.trim();
            if (!/^[0-7]{3,4}$/.test(s)) return;
            const v = parseInt(s.slice(-3), 8);
            for (const g in boxes) for (const [p, val] of bits) boxes[g][p].checked = !!((v >> shifts[g]) & val);
        };
        const syncOct = () => {
            let v = 0;
            for (const g in boxes) for (const [p, val] of bits) if (boxes[g][p].checked) v |= val << shifts[g];
            const s = oct.value.trim();
            const sp = /^[0-7]{4}$/.test(s) ? s[0] : '0'; // keep the special-bits digit
            oct.value = sp + v.toString(8).padStart(3, '0');
        };
        oct.addEventListener('input', syncBoxes);
        for (const g in boxes) for (const p in boxes[g]) boxes[g][p].addEventListener('change', syncOct);

        const v = await modal({
            title: sprintf(
                /* translators: %s: file or folder name */
                __('Permissions — %s', 'cloverbrowser'), name),
            body: wrap,
            actions: [
                { label: __('Cancel', 'cloverbrowser'), value: null },
                {
                    label: __('Apply', 'cloverbrowser'), kind: 'primary',
                    resolve: () => {
                        const s = oct.value.trim();
                        if (!/^[0-7]{3,4}$/.test(s)) {
                            toast(__('Enter a valid octal mode like 0644.', 'cloverbrowser'), 'error');
                            return KEEP_OPEN;
                        }
                        return { mode: s, recursive: !!(rec && rec.checked) };
                    },
                },
            ],
        });
        if (!v) return;

        busyStart(__('Applying permissions…', 'cloverbrowser'));
        try {
            const res = await api('chmod', { path: rel, mode: v.mode, recursive: v.recursive ? '1' : '0' });
            const parts = [sprintf(
                /* translators: %s: number of files/folders whose permissions changed */
                _n('Permissions updated — %s item changed', 'Permissions updated — %s items changed', res.changed, 'cloverbrowser'),
                fmtNum(res.changed, 0)
            )];
            if (res.failed) {
                /* translators: %s: number of items that failed */
                parts.push(sprintf(_n('%s failed', '%s failed', res.failed, 'cloverbrowser'), fmtNum(res.failed, 0)));
            }
            if (res.skipped) {
                /* translators: %s: number of symbolic links skipped */
                parts.push(sprintf(_n('%s symlink skipped', '%s symlinks skipped', res.skipped, 'cloverbrowser'), fmtNum(res.skipped, 0)));
            }
            toast(parts.join(_x(', ', 'list separator', 'cloverbrowser')), res.failed ? 'warn' : 'success');
            if (state.file && state.file.rel === rel) {
                state.file.writable = !!res.writable;
                if (res.perms) state.file.perms = String(res.perms);
                renderChips();
            }
            refreshSoft();
        } catch (e) {
            toast(e.message, 'error', 6500);
        } finally {
            busyEnd();
        }
    }

    async function renameDialog(rel, name) {
        const v = await promptModal({
            title: __('Rename', 'cloverbrowser'),
            label: __('New name (kept in the same folder)', 'cloverbrowser'),
            value: name,
            validate: validName,
        });
        if (!v || v === name) return;
        const to = joinPath(parentDir(rel), v);
        busyStart(__('Renaming…', 'cloverbrowser'));
        try {
            const res = await api('rename', { from: rel, to: to });
            const newRel = res.rel || to;
            // The open file (or a folder containing it) was renamed: follow it.
            if (state.file && isUnder(state.file.rel, rel)) {
                state.file.rel = newRel + state.file.rel.slice(rel.length);
                state.file.name = baseName(state.file.rel);
                els.fileName.textContent = state.file.name;
                els.fileName.title = state.file.rel;
            }
            toast(sprintf(
                /* translators: %s: new file or folder name */
                __('Renamed to %s', 'cloverbrowser'), v), 'success');
            refreshSoft();
        } catch (e) {
            toast(e.message, 'error', 6500);
        } finally {
            busyEnd();
        }
    }

    /** Scope an "Undo" of a fresh deletion restores from (null = the user cannot undo). */
    const undoScope = () => (TRASH.user ? 'mine' : (TRASH.isAdmin && TRASH.site ? 'site' : null));

    async function deleteDialog(rel, name, isDir) {
        const wrap = document.createElement('div');
        const p = document.createElement('p');
        const note = document.createElement('p');
        note.className = 'fbx-muted';
        wrap.append(p, note);
        let perm = null;
        let rec = null;
        let okBtn = null;
        const recLine = document.createElement('label');
        recLine.className = 'fbx-checkline';

        const describe = () => {
            const toTrash = TRASH_ON && !(perm && perm.checked);
            if (toTrash) {
                p.textContent = sprintf(isDir
                    /* translators: %s: folder name */
                    ? __('Move the folder “%s” and everything in it to the trash?', 'cloverbrowser')
                    /* translators: %s: file name */
                    : __('Move “%s” to the trash?', 'cloverbrowser'), name);
                if (TRASH.user) {
                    note.textContent = sprintf(
                        /* translators: %s: number of days */
                        _n('You can restore it from your Trash for %s day.', 'You can restore it from your Trash for %s days.', TRASH.userDays, 'cloverbrowser'), fmtNum(TRASH.userDays, 0));
                } else if (TRASH.isAdmin) {
                    note.textContent = sprintf(
                        /* translators: %s: number of days */
                        _n('It is kept in the site trash for %s day.', 'It is kept in the site trash for %s days.', TRASH.siteDays, 'cloverbrowser'), fmtNum(TRASH.siteDays, 0));
                } else {
                    note.textContent = sprintf(
                        /* translators: %s: number of days */
                        _n('An administrator can restore it for %s day.', 'An administrator can restore it for %s days.', TRASH.siteDays, 'cloverbrowser'), fmtNum(TRASH.siteDays, 0));
                }
            } else {
                p.textContent = sprintf(isDir
                    /* translators: %s: folder name */
                    ? __('Delete folder “%s”? This cannot be undone.', 'cloverbrowser')
                    /* translators: %s: file name */
                    : __('Delete file “%s”? This cannot be undone.', 'cloverbrowser'), name);
                note.textContent = TRASH_ON ? __('It will not go to the trash.', 'cloverbrowser') : '';
            }
            note.hidden = !note.textContent;
            recLine.hidden = !(isDir && !toTrash);
            if (okBtn) okBtn.textContent = toTrash ? __('Move to trash', 'cloverbrowser') : __('Delete permanently', 'cloverbrowser');
        };

        if (TRASH_ON && TRASH.isAdmin) {
            perm = document.createElement('input');
            perm.type = 'checkbox';
            const line = document.createElement('label');
            line.className = 'fbx-checkline';
            line.append(perm, document.createTextNode(' ' + __('Delete permanently (skip the trash)', 'cloverbrowser')));
            wrap.append(line);
            perm.addEventListener('change', describe);
        }
        if (isDir) {
            rec = document.createElement('input');
            rec.type = 'checkbox';
            recLine.append(rec, document.createTextNode(' ' + __('Also delete everything inside it (capped server-side)', 'cloverbrowser')));
            wrap.append(recLine);
        }
        describe();
        const ok = await modal({
            title: isDir ? __('Delete folder', 'cloverbrowser') : __('Delete file', 'cloverbrowser'),
            body: wrap,
            actions: [
                { label: __('Cancel', 'cloverbrowser'), value: null },
                { label: TRASH_ON ? __('Move to trash', 'cloverbrowser') : __('Delete', 'cloverbrowser'), kind: 'danger', value: true },
            ],
            onOpen: ({ panel }) => {
                const btns = panel.querySelectorAll('.fbx-modal-actions .fbx-btn');
                okBtn = btns[btns.length - 1];
                describe();
            },
        });
        if (!ok) return;
        const permanent = !!(perm && perm.checked);

        busyStart(sprintf(
            /* translators: %s: file or folder name */
            __('Deleting %s…', 'cloverbrowser'), name));
        try {
            const res = await api('delete', { path: rel, recursive: rec && rec.checked ? '1' : '0', permanent: permanent ? '1' : '0' });
            if (state.file && isUnder(state.file.rel, rel)) teardownEditor();
            if (res.trashed) {
                setTrashCount(res.trashCount);
                const scope = undoScope();
                const item = res.item || {};
                toast(sprintf(
                    /* translators: %s: file or folder name */
                    __('Moved %s to the trash', 'cloverbrowser'), name), 'success', 0,
                scope && item.id ? { label: __('Undo', 'cloverbrowser'), run: () => restoreItem(item, scope) } : null);
            } else {
                toast(res.deleted > 1
                    /* translators: 1: folder name, 2: number of items deleted */
                    ? sprintf(_n('Deleted %1$s (%2$s item)', 'Deleted %1$s (%2$s items)', res.deleted, 'cloverbrowser'), name, fmtNum(res.deleted, 0))
                    /* translators: %s: file or folder name */
                    : sprintf(__('Deleted %s', 'cloverbrowser'), name), 'success');
            }
            refreshSoft();
        } catch (e) {
            toast(e.message, 'error', 6500);
            refreshSoft(); // a partial recursive delete changes the listing
        } finally {
            busyEnd();
        }
    }

    /* ------------------------------------------------------------------ */
    /* Toolbar: new folder / new file / upload                            */
    /* ------------------------------------------------------------------ */

    async function toolbarAct(act) {
        switch (act) {
            case 'up':
                if (state.cwd) navigate(parentDir(state.cwd));
                break;

            case 'refresh':
                refresh();
                break;

            case 'mkdir': {
                const dir = state.cwd;
                const v = await promptModal({ title: __('New folder', 'cloverbrowser'), label: __('Folder name', 'cloverbrowser'), validate: validName });
                if (!v) return;
                busyStart(__('Creating folder…', 'cloverbrowser'));
                try {
                    await api('mkdir', { dir: dir, name: v });
                    toast(sprintf(
                        /* translators: %s: folder name */
                        __('Folder created: %s', 'cloverbrowser'), v), 'success');
                    refreshSoft();
                } catch (e) {
                    toast(e.message, 'error', 6500);
                } finally {
                    busyEnd();
                }
                break;
            }

            case 'mkfile': {
                const dir = state.cwd;
                const v = await promptModal({ title: __('New file', 'cloverbrowser'), label: __('File name', 'cloverbrowser'), validate: validName });
                if (!v) return;
                busyStart(__('Creating file…', 'cloverbrowser'));
                try {
                    const res = await api('newfile', { dir: dir, name: v });
                    toast(sprintf(
                        /* translators: %s: file name */
                        __('File created: %s', 'cloverbrowser'), v), 'success');
                    refreshSoft();
                    openFile(res.rel || joinPath(dir, v)); // jump straight into the editor
                } catch (e) {
                    toast(e.message, 'error', 6500);
                } finally {
                    busyEnd();
                }
                break;
            }

            case 'upload':
                // Only a trusted click on Upload arms the next file selection (see the change handler).
                pickerArmedUntil = Date.now() + 10 * 60 * 1000;
                els.fileInput.click();
                break;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Uploads (XHR for progress; strictly one file at a time)            */
    /* ------------------------------------------------------------------ */

    function uploadProgress(name, frac) {
        els.strip.hidden = false;
        els.stripName.textContent = name;
        els.stripBar.style.width = Math.round((frac || 0) * 100) + '%';
    }
    function uploadDone() {
        els.strip.hidden = true;
        els.stripBar.style.width = '0%';
    }

    /** Line-ending kind of a text file chosen for upload (null = binary / too big / empty). */
    async function sniffEol(file) {
        if (!file.size || file.size > (CFG.eolMax || 0)) return null;
        let buf;
        try { buf = new Uint8Array(await file.arrayBuffer()); } catch (e) { return null; }
        const head = Math.min(buf.length, 8192);
        let ctrl = 0;
        for (let i = 0; i < head; i++) {
            const b = buf[i];
            if (b === 0) return null;
            if (b < 9 || (b > 13 && b < 32)) ctrl++;
        }
        if (head && ctrl / head >= 0.05) return null;
        let crlf = 0; let lf = 0; let cr = 0;
        for (let i = 0; i < buf.length; i++) {
            if (buf[i] === 13) {
                if (buf[i + 1] === 10) { crlf++; i++; } else cr++;
            } else if (buf[i] === 10) lf++;
        }
        const kinds = [crlf && 'crlf', lf && 'lf', cr && 'cr'].filter(Boolean);
        return kinds.length === 0 ? 'none' : kinds.length > 1 ? 'mixed' : kinds[0];
    }

    function uploadFile(dir, file, overwrite, convertEol) {
        return new Promise((resolve, reject) => {
            const fd = new NATIVE.FormData();
            fd.append('action', 'cloverbrowser_upload');
            fd.append('nonce', NONCE);
            fd.append('dir', dir);
            fd.append('overwrite', overwrite ? '1' : '0');
            fd.append('convert_eol', convertEol ? '1' : '0');
            fd.append('file', file, file.name);

            const xhr = new NATIVE.XHR();
            xhr.open('POST', CFG.ajaxUrl, true);
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) uploadProgress(file.name, e.loaded / e.total);
            };
            xhr.onload = () => {
                let json = null;
                try { json = NATIVE.parse(xhr.responseText); } catch (e) { /* fatal error page */ }
                if (json && json.success) return resolve(json.data || {});
                const err = new Error((json && json.data && json.data.message) ||
                    (xhr.status === 413
                        ? __('File is larger than the web server accepts.', 'cloverbrowser')
                        /* translators: %d: HTTP status code */
                        : sprintf(__('Upload failed (HTTP %d).', 'cloverbrowser'), xhr.status)));
                err.code = json && json.data && json.data.code;
                reject(err);
            };
            xhr.onerror = () => reject(Object.assign(new Error(__('Network error during upload.', 'cloverbrowser')), { code: 'fbf_network' }));
            xhr.send(fd);
        });
    }

    let uploading = false;
    async function handleFiles(fileList) {
        let files = Array.from(fileList);
        if (!files.length || !can('upload')) return;
        if (state.dirNav || state.dirProtected) {
            toast(state.dirNav
                ? __('Open one of the folders you have access to first.', 'cloverbrowser')
                : __('This folder is protected: your role can only read it.', 'cloverbrowser'), 'warn', 6000);
            return;
        }
        if (uploading) { toast(__('An upload is already in progress.', 'cloverbrowser'), 'warn'); return; }
        if (CFG.maxUpload > 0) {
            const tooBig = files.filter((f) => f.size > CFG.maxUpload);
            for (const f of tooBig) {
                toast(sprintf(
                    /* translators: 1: file name, 2: maximum upload size */
                    __('%1$s is larger than the %2$s your role may upload.', 'cloverbrowser'), f.name, fmtSize(CFG.maxUpload)), 'error', 7000);
            }
            files = files.filter((f) => f.size <= CFG.maxUpload);
            if (!files.length) return;
        }
        uploading = true;
        const dir = state.cwd; // the whole batch goes where it was dropped, even if you navigate away
        try {
            // Offer to convert text files whose line endings differ from the server's.
            const kinds = await Promise.all(files.map(sniffEol));
            const differ = files.filter((f, i) => kinds[i] && kinds[i] !== 'none' && kinds[i] !== SERVER_EOL_NAME);
            let convert = false;
            if (differ.length) {
                const names = differ.slice(0, 5).map((f, i) => '• ' + f.name + ' — ' + eolKindLabel(kinds[files.indexOf(f)]));
                if (differ.length > 5) {
                    names.push(sprintf(
                        /* translators: %s: number of further files */
                        _n('…and %s more', '…and %s more', differ.length - 5, 'cloverbrowser'), fmtNum(differ.length - 5, 0)));
                }
                const body = document.createElement('div');
                const p = document.createElement('p');
                p.textContent = sprintf(
                    /* translators: 1: number of files, 2: the server's line-ending style, e.g. "Unix (LF)" */
                    _n('%1$s file uses line endings that differ from this server’s %2$s format:', '%1$s files use line endings that differ from this server’s %2$s format:', differ.length, 'cloverbrowser'),
                    fmtNum(differ.length, 0), eolKindLabel(SERVER_EOL_NAME));
                const list = document.createElement('p');
                list.className = 'fbx-modal-list';
                list.textContent = names.join('\n');
                body.append(p, list);
                const choice = await modal({
                    title: __('Convert line endings?', 'cloverbrowser'),
                    body,
                    actions: [
                        { label: __('Cancel upload', 'cloverbrowser'), value: null },
                        { label: __('Keep as they are', 'cloverbrowser'), value: 'keep' },
                        {
                            label: sprintf(
                                /* translators: %s: line-ending name, e.g. "LF" */
                                __('Convert to %s', 'cloverbrowser'), EOL_LABEL[SERVER_EOL_NAME]),
                            kind: 'primary', value: 'convert',
                        },
                    ],
                });
                if (!choice) return;
                convert = choice === 'convert';
            }
            for (const f of files) { // one at a time — never saturate the server
                let overwrite = false;
                const convertThis = convert && differ.includes(f);
                for (;;) {
                    try {
                        uploadProgress(f.name, 0);
                        const res = await uploadFile(dir, f, overwrite, convertThis);
                        toast(sprintf(
                            /* translators: %s: file name */
                            __('Uploaded %s', 'cloverbrowser'), res.name || f.name), 'success');
                        break;
                    } catch (e) {
                        if (e.code === 'fbf_exists' && !overwrite) {
                            const ok = await confirmModal(
                                __('File exists', 'cloverbrowser'),
                                sprintf(
                                    /* translators: %s: file name */
                                    __('“%s” already exists in this folder. Overwrite it?', 'cloverbrowser'), f.name),
                                { okLabel: __('Overwrite', 'cloverbrowser'), danger: true }
                            );
                            if (ok) { overwrite = true; continue; }
                            break; // skip this file
                        }
                        toast(sprintf(
                            /* translators: 1: file name, 2: error message */
                            __('Upload failed (%1$s): %2$s', 'cloverbrowser'), f.name, e.message), 'error', 7000);
                        break;
                    }
                }
            }
        } finally {
            uploading = false;
            uploadDone();
            if (dir === state.cwd) refreshSoft();
        }
    }

    /* ------------------------------------------------------------------ */
    /* Trash (personal + site)                                            */
    /* ------------------------------------------------------------------ */

    const tstate = { open: false, scope: TRASH.user ? 'mine' : 'site', items: [], seq: 0, listStale: false };
    // Row → item. Ids live only here, never in the DOM.
    const trowData = new WeakMap();

    function setTrashCount(n) {
        if (typeof n === 'number' && n >= 0) trashCount = n;
        if (!els.trashBtn) return;
        els.trashCount.hidden = trashCount <= 0;
        els.trashCount.textContent = trashCount > 99 ? '99+' : fmtNum(trashCount, 0);
        els.trashBtn.setAttribute('aria-label', trashCount > 0
            ? sprintf(
                /* translators: %s: number of items */
                _n('Trash, %s item', 'Trash, %s items', trashCount, 'cloverbrowser'), fmtNum(trashCount, 0))
            : __('Trash', 'cloverbrowser'));
    }

    function openTrash(scope) {
        if (!TRASH_VIEW) return;
        if (scope === 'site' && !(TRASH.isAdmin && TRASH.site)) scope = 'mine';
        if (scope === 'mine' && !TRASH.user) scope = 'site';
        closeMenu();
        tstate.open = true;
        tstate.scope = scope;
        els.toolbar.hidden = true;
        els.main.hidden = true;
        els.trash.hidden = false;
        if (els.trashBtn) els.trashBtn.setAttribute('aria-pressed', 'true');
        loadTrash();
    }

    function closeTrash() {
        closeMenu();
        tstate.open = false;
        els.trash.hidden = true;
        els.toolbar.hidden = false;
        els.main.hidden = false;
        if (els.trashBtn) { els.trashBtn.setAttribute('aria-pressed', 'false'); els.trashBtn.focus(); }
        if (tstate.listStale) { tstate.listStale = false; refresh(); }
    }

    async function loadTrash() {
        const seq = ++tstate.seq;
        const scope = tstate.scope;
        busyStart(__('Loading trash…', 'cloverbrowser'));
        if (tstate.shownScope !== scope) {
            // Switching between "My trash" and "Site trash": never show the other list's rows meanwhile.
            tstate.items = [];
            els.trashRows.replaceChildren(Object.assign(document.createElement('div'), { className: 'fbx-empty', textContent: __('Loading…', 'cloverbrowser') }));
            els.trashFoot.textContent = '';
        }
        renderTrashChrome();
        try {
            const d = await api('trash_list', { scope });
            if (seq !== tstate.seq) return;
            tstate.items = Array.isArray(d.items) ? d.items : [];
            tstate.shownScope = scope;
            setTrashCount(d.trashCount);
            renderTrash(d);
        } catch (e) {
            if (seq === tstate.seq) {
                els.trashRows.replaceChildren(Object.assign(document.createElement('div'), { className: 'fbx-empty', textContent: e.message }));
            }
        } finally {
            busyEnd();
        }
    }

    function renderTrashChrome() {
        const site = tstate.scope === 'site';
        els.trashTitle.textContent = site ? __('Site trash', 'cloverbrowser') : __('Trash', 'cloverbrowser');
        els.trashTabs.forEach((t) => {
            const on = (t.dataset.tab === 'site') === site; // static markup; the server checks the scope
            t.classList.toggle('is-active', on);
            t.setAttribute('aria-selected', on ? 'true' : 'false');
            t.tabIndex = on ? 0 : -1;
        });
        els.trashEmpty.textContent = site ? __('Empty site trash', 'cloverbrowser') : __('Empty trash', 'cloverbrowser');
        els.trashEmpty.hidden = !CAN_WRITE;
        els.trash.classList.toggle('is-site', site);
        let note;
        if (site) {
            note = sprintf(
                /* translators: %s: number of days */
                _n('Every deletion on this site is kept here for %s day, even after users empty their own trash. Only administrators can see this trash.',
                    'Every deletion on this site is kept here for %s days, even after users empty their own trash. Only administrators can see this trash.', TRASH.siteDays, 'cloverbrowser'),
                fmtNum(TRASH.siteDays, 0));
        } else {
            note = sprintf(
                /* translators: %s: number of days */
                _n('Items you delete are kept here for %s day, then deleted automatically.', 'Items you delete are kept here for %s days, then deleted automatically.', TRASH.userDays, 'cloverbrowser'),
                fmtNum(TRASH.userDays, 0));
            if (TRASH.site) {
                note += ' ' + sprintf(
                    /* translators: %s: number of days */
                    _n('Administrators also keep a copy of every deletion for %s day.', 'Administrators also keep a copy of every deletion for %s days.', TRASH.siteDays, 'cloverbrowser'),
                    fmtNum(TRASH.siteDays, 0));
            }
            note += ' ' + __('Right-click an item for more options.', 'cloverbrowser');
        }
        els.trashNote.textContent = note;
    }

    function trashRow(it) {
        const site = tstate.scope === 'site';
        const row = document.createElement('div');
        trowData.set(row, Object.freeze(Object.assign({}, it)));
        row.className = 'fbx-trow' + (it.dir ? ' fbx-trow--dir' : '');
        row.tabIndex = 0;
        row.setAttribute('role', 'listitem');
        row.setAttribute('aria-label', it.name);
        row.setAttribute('aria-haspopup', 'menu');

        const from = it.path.includes('/') ? it.path.slice(0, it.path.lastIndexOf('/')) : '';
        const cell = (cls, main, sub, subTitle) => {
            const c = document.createElement('div');
            c.className = 'fbx-tcell ' + cls;
            const m = document.createElement('span');
            m.className = 'fbx-tmain';
            m.textContent = main;
            c.append(m);
            if (sub) {
                const s2 = document.createElement('small');
                s2.textContent = sub;
                if (subTitle) s2.title = subTitle;
                c.append(s2);
            }
            return c;
        };

        const name = document.createElement('div');
        name.className = 'fbx-tcell fbx-tname';
        const ico = document.createElement('span');
        ico.className = 'fbx-ico';
        ico.innerHTML = it.link ? ICONS.link : (it.dir ? ICONS.folder : ICONS.file); // static SVG
        const txt = document.createElement('span');
        txt.className = 'fbx-tname-text';
        const n = document.createElement('span');
        n.className = 'fbx-tmain';
        n.textContent = it.name;
        n.title = it.name;
        const loc = document.createElement('small');
        loc.textContent = from === ''
            ? sprintf(
                /* translators: %s: name of the site's top folder */
                __('in %s', 'cloverbrowser'), CFG.rootLabel || '/')
            : sprintf(
                /* translators: %s: folder path the item was deleted from */
                __('in %s', 'cloverbrowser'), from);
        loc.title = it.path;
        txt.append(n, loc);
        name.append(ico, txt);
        row.append(name);

        row.append(cell('fbx-tcell--deleted', it.deletedText || '', site && it.by ? sprintf(
            /* translators: %s: user display name */
            __('by %s', 'cloverbrowser'), it.by) : ''));
        const until = site ? (it.expiresText || '') : (it.userUntilText || '');
        const sub = site ? (it.inUser ? __('Also in their own trash', 'cloverbrowser') : __('Site trash only', 'cloverbrowser')) : '';
        row.append(cell('fbx-tcell--until', until, sub));
        const size = it.dir
            ? sprintf(
                /* translators: %s: number of items in a folder */
                _n('%s item', '%s items', it.count, 'cloverbrowser'), (it.approx ? '>' : '') + fmtNum(it.count, 0))
            : fmtSize(it.size || 0);
        row.append(cell('fbx-tcell--size', size, it.dir ? fmtSize(it.size || 0) + (it.approx ? '+' : '') : ''));

        const act = document.createElement('div');
        act.className = 'fbx-tcell fbx-tact';
        if (CAN_WRITE && (site || PERMS.delete)) {
            const r = document.createElement('button');
            r.type = 'button';
            r.className = 'fbx-btn fbx-btn--sm';
            r.dataset.act = 'trestore';
            r.innerHTML = ICONS.restore; // static SVG
            const rl = document.createElement('span');
            rl.textContent = __('Restore', 'cloverbrowser');
            r.append(rl);
            r.setAttribute('aria-label', sprintf(
                /* translators: %s: file or folder name */
                __('Restore %s', 'cloverbrowser'), it.name));
            act.append(r);
        }
        const more = document.createElement('button');
        more.type = 'button';
        more.className = 'fbx-row-btn';
        more.dataset.act = 'tmore';
        more.innerHTML = ICONS.more; // static SVG
        more.title = __('More actions', 'cloverbrowser');
        more.setAttribute('aria-label', sprintf(
            /* translators: %s: file or folder name */
            __('More actions for %s', 'cloverbrowser'), it.name));
        more.setAttribute('aria-haspopup', 'menu');
        act.append(more);
        row.append(act);
        return row;
    }

    function renderTrash(d) {
        const site = tstate.scope === 'site';
        // Keep keyboard users in the list when a re-render replaces the focused row.
        const ae = document.activeElement;
        const hadFocus = ae === document.body || els.trashRows.contains(ae);
        const focusIdx = els.trashRows.contains(ae) ? Array.prototype.indexOf.call(els.trashRows.children, ae.closest('.fbx-trow')) : (tstate.lastIdx | 0);
        els.trashCols.querySelector('.fbx-tcol--until').textContent = site ? __('Kept until', 'cloverbrowser') : __('Deletes on', 'cloverbrowser');
        els.trashRows.replaceChildren();
        if (!tstate.items.length) {
            const empty = document.createElement('div');
            empty.className = 'fbx-empty fbx-trash-empty';
            empty.innerHTML = ICONS.trash; // static SVG
            const t = document.createElement('p');
            t.textContent = site ? __('The site trash is empty.', 'cloverbrowser') : __('Your trash is empty.', 'cloverbrowser');
            empty.append(t);
            els.trashRows.append(empty);
        } else {
            const frag = document.createDocumentFragment();
            tstate.items.forEach((it) => frag.append(trashRow(it)));
            els.trashRows.append(frag);
            if (hadFocus && !isModalOpen() && !menu && tstate.open) {
                const rows = els.trashRows.children;
                const target = rows[Math.max(0, Math.min(focusIdx, rows.length - 1))];
                if (target) target.focus({ preventScroll: true });
            }
        }
        els.trashEmpty.disabled = !tstate.items.length;
        els.trashFoot.textContent = tstate.items.length
            ? sprintf(
                /* translators: 1: number of items, 2: total size */
                _n('%1$s item · %2$s', '%1$s items · %2$s', tstate.items.length, 'cloverbrowser'), fmtNum(tstate.items.length, 0), fmtSize((d && d.size) || 0))
            : '';
    }

    /* ---- context menu ---- */

    let menu = null;
    function closeMenu() {
        if (!menu) return;
        const m = menu;
        menu = null;
        m.cleanup();
        m.el.remove();
        if (m.returnFocus && m.returnFocus.isConnected) try { m.returnFocus.focus(); } catch (e) { /* noop */ }
    }

    function openMenu(items, x, y, returnFocus) {
        closeMenu();
        const el = document.createElement('div');
        el.className = 'fbx-menu';
        el.setAttribute('role', 'menu');
        if (document.documentElement.dir === 'rtl') el.dir = 'rtl';
        const buttons = [];
        items.forEach((it) => {
            if (it === '-') {
                const sep = document.createElement('div');
                sep.className = 'fbx-menu-sep';
                sep.setAttribute('role', 'separator');
                el.append(sep);
                return;
            }
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'fbx-menu-item' + (it.danger ? ' is-danger' : '');
            b.setAttribute('role', 'menuitem');
            b.tabIndex = -1;
            if (it.icon) b.innerHTML = it.icon; // static SVG
            const l = document.createElement('span');
            l.textContent = it.label;
            b.append(l);
            if (it.disabled) { b.disabled = true; b.setAttribute('aria-disabled', 'true'); if (it.hint) b.title = it.hint; }
            b.addEventListener('click', (ev) => {
                if (!trusted(ev) || it.disabled) return; // scripted clicks do nothing
                closeMenu();
                it.run();
            });
            el.append(b);
            buttons.push(b);
        });
        document.body.append(el);
        // Keep inside the viewport.
        const r = el.getBoundingClientRect();
        const left = Math.max(8, Math.min(x, window.innerWidth - r.width - 8));
        const top = Math.max(8, Math.min(y, window.innerHeight - r.height - 8));
        el.style.left = left + 'px';
        el.style.top = top + 'px';

        const enabled = () => buttons.filter((b) => !b.disabled);
        const onKey = (e) => {
            const list = enabled();
            const i = list.indexOf(document.activeElement);
            if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeMenu(); }
            else if (e.key === 'ArrowDown') { e.preventDefault(); (list[(i + 1) % list.length] || list[0]).focus(); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); (list[(i - 1 + list.length) % list.length] || list[0]).focus(); }
            else if (e.key === 'Home') { e.preventDefault(); list[0] && list[0].focus(); }
            else if (e.key === 'End') { e.preventDefault(); list[list.length - 1] && list[list.length - 1].focus(); }
            else if (e.key === 'Tab') { e.preventDefault(); closeMenu(); }
        };
        const onDown = (e) => { if (!el.contains(e.target)) { const m = menu; if (m) m.returnFocus = null; closeMenu(); } };
        const onAway = () => closeMenu();
        document.addEventListener('keydown', onKey, true);
        document.addEventListener('mousedown', onDown, true);
        window.addEventListener('resize', onAway);
        window.addEventListener('blur', onAway);
        els.trashRows.addEventListener('scroll', onAway, { passive: true });
        menu = {
            el, returnFocus,
            cleanup: () => {
                document.removeEventListener('keydown', onKey, true);
                document.removeEventListener('mousedown', onDown, true);
                window.removeEventListener('resize', onAway);
                window.removeEventListener('blur', onAway);
                els.trashRows.removeEventListener('scroll', onAway);
            },
        };
        const first = enabled()[0];
        if (first) first.focus();
    }

    function trashMenuItems(it) {
        const site = tstate.scope === 'site';
        const items = [];
        const canRestore = CAN_WRITE && (site || PERMS.delete);
        items.push({ label: __('Restore', 'cloverbrowser'), icon: ICONS.restore, disabled: !canRestore,
            hint: __('Your role is not allowed to do that.', 'cloverbrowser'), run: () => restoreItem(it, tstate.scope) });
        if (!site) {
            items.push({ label: __('Remove from my trash', 'cloverbrowser'), icon: ICONS.close, disabled: !CAN_WRITE, run: () => removeItem(it) });
        }
        if (site || TRASH.canPurge) {
            items.push('-');
            items.push({ label: __('Permanently delete', 'cloverbrowser'), icon: ICONS.trash, danger: true, disabled: !CAN_WRITE, run: () => purgeItem(it, tstate.scope) });
        }
        return items;
    }

    function openRowMenu(row, x, y, focusBack) {
        const it = trowData.get(row);
        if (!it) return;
        tstate.lastIdx = Array.prototype.indexOf.call(els.trashRows.children, row);
        row.classList.add('is-menu');
        openMenu(trashMenuItems(it), x, y, focusBack || row);
        const m = menu;
        if (m) {
            const prev = m.cleanup;
            m.cleanup = () => { prev(); row.classList.remove('is-menu'); };
        }
    }

    /* ---- trash actions ---- */

    function afterTrashChange(d) {
        if (d && typeof d.trashCount === 'number') setTrashCount(d.trashCount);
        tstate.listStale = true;
        if (tstate.open) loadTrash();
    }

    async function restoreItem(it, scope) {
        busyStart(sprintf(
            /* translators: %s: file or folder name */
            __('Restoring %s…', 'cloverbrowser'), it.name));
        try {
            const d = await api('trash_restore', { id: it.id, scope });
            toast(d.renamed
                ? sprintf(
                    /* translators: 1: original name, 2: new name (the original name was taken) */
                    __('Restored %1$s as %2$s (the original name is in use)', 'cloverbrowser'), it.name, d.name)
                : sprintf(
                    /* translators: %s: file or folder name */
                    __('Restored %s', 'cloverbrowser'), it.name), 'success', 6000);
            afterTrashChange(d);
            if (!tstate.open) { tstate.listStale = false; refreshSoft(); }
        } catch (e) {
            toast(e.message, 'error', 7000);
            if (tstate.open) loadTrash();
        } finally {
            busyEnd();
        }
    }

    async function removeItem(it) {
        const body = document.createElement('div');
        const p1 = document.createElement('p');
        p1.textContent = sprintf(
            /* translators: %s: file or folder name */
            __('Remove “%s” from your trash?', 'cloverbrowser'), it.name);
        const p2 = document.createElement('p');
        p2.className = 'fbx-muted';
        p2.textContent = TRASH.site
            ? __('It stays in the site trash for the rest of its retention period, where an administrator can still restore it.', 'cloverbrowser')
            : __('It will be deleted permanently. This cannot be undone.', 'cloverbrowser');
        body.append(p1, p2);
        const ok = await modal({ title: __('Remove from my trash', 'cloverbrowser'), body, actions: [
            { label: __('Cancel', 'cloverbrowser'), value: null },
            { label: __('Remove', 'cloverbrowser'), kind: 'danger', value: true },
        ] });
        if (!ok) return;
        busyStart(__('Working…', 'cloverbrowser'));
        try {
            const d = await api('trash_remove', { id: it.id });
            toast(sprintf(
                /* translators: %s: file or folder name */
                __('Removed %s from your trash', 'cloverbrowser'), it.name), 'success');
            afterTrashChange(d);
        } catch (e) {
            toast(e.message, 'error', 7000);
        } finally {
            busyEnd();
        }
    }

    async function purgeItem(it, scope) {
        const ok = await confirmModal(__('Permanently delete', 'cloverbrowser'), sprintf(scope === 'site'
            /* translators: %s: file or folder name */
            ? __('Permanently delete “%s”? It is removed from the site trash and from its owner’s trash. This cannot be undone.', 'cloverbrowser')
            /* translators: %s: file or folder name */
            : __('Permanently delete “%s”? It is removed from your trash and from the site trash. This cannot be undone.', 'cloverbrowser'), it.name),
        { okLabel: __('Delete permanently', 'cloverbrowser'), danger: true });
        if (!ok) return;
        busyStart(__('Working…', 'cloverbrowser'));
        try {
            const d = await api('trash_purge', { id: it.id, scope });
            toast(sprintf(
                /* translators: %s: file or folder name */
                __('Permanently deleted %s', 'cloverbrowser'), it.name), 'success');
            afterTrashChange(d);
        } catch (e) {
            toast(e.message, 'error', 7000);
        } finally {
            busyEnd();
        }
    }

    async function emptyTrash() {
        const site = tstate.scope === 'site';
        const n = tstate.items.length;
        if (!n) return;
        const msg = site
            ? sprintf(
                /* translators: %s: number of items */
                _n('Permanently delete the %s item in the site trash, including items still in users’ own trash? This cannot be undone.',
                    'Permanently delete all %s items in the site trash, including items still in users’ own trash? This cannot be undone.', n, 'cloverbrowser'), fmtNum(n, 0))
            : sprintf(
                /* translators: %s: number of items */
                _n('Remove the %s item from your trash?', 'Remove all %s items from your trash?', n, 'cloverbrowser'), fmtNum(n, 0))
                + ' ' + (TRASH.site
                    ? __('Administrators can still restore them from the site trash for the rest of its retention period.', 'cloverbrowser')
                    : __('They will be deleted permanently. This cannot be undone.', 'cloverbrowser'));
        const ok = await confirmModal(site ? __('Empty site trash', 'cloverbrowser') : __('Empty trash', 'cloverbrowser'), msg,
            { okLabel: site ? __('Delete everything', 'cloverbrowser') : __('Empty trash', 'cloverbrowser'), danger: true });
        if (!ok) return;
        busyStart(__('Working…', 'cloverbrowser'));
        try {
            const d = await api('trash_empty', { scope: tstate.scope });
            toast(site ? __('The site trash is empty.', 'cloverbrowser') : __('Your trash is empty.', 'cloverbrowser'), 'success');
            if (d.failed) toast(__('Some items could not be deleted (check permissions).', 'cloverbrowser'), 'warn', 7000);
            afterTrashChange(d);
        } catch (e) {
            toast(e.message, 'error', 7000);
        } finally {
            busyEnd();
        }
    }

    if (TRASH_VIEW) {
        // Right-click (or the keyboard's menu key / Shift+F10) on an item.
        els.trashRows.addEventListener('contextmenu', (ev) => {
            const row = ev.target.closest('.fbx-trow');
            if (!row) return;
            ev.preventDefault();
            if (!trusted(ev)) return;
            if (ev.button === -1 || (ev.clientX === 0 && ev.clientY === 0)) {
                const r = row.getBoundingClientRect();
                openRowMenu(row, r.left + 24, r.top + r.height - 4);
            } else {
                openRowMenu(row, ev.clientX, ev.clientY);
            }
        });
        els.trashRows.addEventListener('keydown', (ev) => {
            if (!ev.target.classList.contains('fbx-trow') || !trusted(ev)) return;
            if ((ev.key === 'F10' && ev.shiftKey) || ev.key === 'Enter' || ev.key === ' ') {
                ev.preventDefault();
                const r = ev.target.getBoundingClientRect();
                openRowMenu(ev.target, r.left + 24, r.top + r.height - 4);
            } else if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
                ev.preventDefault();
                const next = ev.key === 'ArrowDown' ? ev.target.nextElementSibling : ev.target.previousElementSibling;
                if (next && next.classList.contains('fbx-trow')) next.focus();
            }
        });
        els.trash.addEventListener('keydown', (ev) => {
            if (ev.key === 'Escape' && !menu && !isModalOpen() && trusted(ev)) { ev.preventDefault(); closeTrash(); }
        });
        // Tabs: arrow keys move between "My trash" and "Site trash".
        els.trashTabs.forEach((t) => t.addEventListener('keydown', (ev) => {
            if (!trusted(ev) || (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight')) return;
            ev.preventDefault();
            const other = els.trashTabs.find((x) => x !== t);
            if (other) { other.focus(); openTrash(other.dataset.tab === 'site' ? 'site' : 'mine'); }
        }));
        setTrashCount(trashCount);
    }

    /* ------------------------------------------------------------------ */
    /* Event wiring                                                       */
    /* ------------------------------------------------------------------ */

    ROOT.addEventListener('click', (ev) => {
        if (!trusted(ev)) return; // element.click() from scripts/extensions does nothing
        const btn = ev.target.closest('[data-act]');
        if (btn && ROOT.contains(btn)) {
            if (btn.disabled) return;
            const act = btn.dataset.act;
            switch (act) {
                case 'up': case 'refresh': case 'mkdir': case 'mkfile': case 'upload':
                    return void toolbarAct(act);
                case 'save': return void saveFile(false);
                case 'revert': return void revertFile();
                case 'close': return void closeFile();
                case 'eolconvert': return void convertEol();
                case 'eoldismiss': state.eolDismissed = true; return void renderEol();
                case 'trash': return void (tstate.open ? closeTrash() : openTrash(TRASH.user ? 'mine' : 'site'));
                case 'trashback': return void closeTrash();
                case 'trashtab': return void openTrash(btn.dataset.tab === 'site' ? 'site' : 'mine');
                case 'trashrefresh': return void loadTrash();
                case 'trashempty': return void emptyTrash();
                case 'trestore': case 'tmore': {
                    const trow = btn.closest('.fbx-trow');
                    const it = trow && trowData.get(trow);
                    if (!it) return;
                    if (act === 'trestore') return void restoreItem(it, tstate.scope);
                    const r = btn.getBoundingClientRect();
                    return void openRowMenu(trow, r.right - 4, r.bottom + 4, btn);
                }
            }
            const row = btn.closest('.fbx-row');
            if (row) return void rowAct(act, row);
            return;
        }
        const row = ev.target.closest('.fbx-row');
        if (row) rowAct('open', row);
    });

    els.rows.addEventListener('keydown', (ev) => {
        // Only when the row itself has focus — Enter/Space on an action button must reach the button.
        if (!ev.target.classList.contains('fbx-row') || !trusted(ev)) return;
        if (ev.key === 'Enter' || ev.key === ' ') {
            ev.preventDefault();
            rowAct('open', ev.target);
        } else if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
            ev.preventDefault();
            const next = ev.key === 'ArrowDown' ? ev.target.nextElementSibling : ev.target.previousElementSibling;
            if (next && next.classList.contains('fbx-row')) next.focus();
        }
    });

    // A file selection counts only if it is a real (trusted) event, or follows
    // the user's own click on Upload. A script that stuffs files into the input
    // and dispatches "change" on its own is ignored.
    let pickerArmedUntil = 0;
    els.fileInput.addEventListener('change', (ev) => {
        const armed = Date.now() < pickerArmedUntil;
        pickerArmedUntil = 0;
        if ((trusted(ev) || armed) && els.fileInput.files && els.fileInput.files.length) handleFiles(els.fileInput.files);
        els.fileInput.value = '';
    });

    // Drag & drop upload onto the list pane. dragenter/dragleave fire for every
    // child element, so track depth instead of hiding on the first dragleave
    // (the old logic left the overlay stuck on screen). Only real file drags count.
    let dragDepth = 0;
    const hasFiles = (e) => !!(e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files'));
    const resetDrag = () => { dragDepth = 0; els.drop.hidden = true; };

    if (can('upload')) {
        els.listPane.addEventListener('dragenter', (e) => {
            if (!hasFiles(e)) return;
            e.preventDefault();
            dragDepth++;
            els.drop.hidden = false;
        });
        els.listPane.addEventListener('dragover', (e) => {
            if (!hasFiles(e)) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
        });
        els.listPane.addEventListener('dragleave', (e) => {
            if (!hasFiles(e)) return;
            dragDepth = Math.max(0, dragDepth - 1);
            if (dragDepth === 0) els.drop.hidden = true;
        });
        els.listPane.addEventListener('drop', (e) => {
            if (!hasFiles(e)) return;
            e.preventDefault();
            e.stopPropagation();
            resetDrag();
            if (trusted(e)) handleFiles(e.dataTransfer.files); // synthetic drops are ignored
        });
    }
    // A file dropped anywhere else on the component must not make the browser
    // navigate away to it (the editor handles its own drops).
    const blockStrayDrop = (e) => {
        if (!hasFiles(e) || e.defaultPrevented || e.target.closest('.CodeMirror')) return;
        if (can('upload') && els.listPane.contains(e.target)) return;
        e.preventDefault();
        if (e.type === 'dragover') e.dataTransfer.dropEffect = 'none';
    };
    ROOT.addEventListener('dragover', blockStrayDrop);
    ROOT.addEventListener('drop', blockStrayDrop);
    window.addEventListener('dragend', resetDrag);
    window.addEventListener('drop', resetDrag);
    window.addEventListener('blur', resetDrag);

    document.addEventListener('keydown', (ev) => {
        if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && (ev.key === 's' || ev.key === 'S') && state.file && !isModalOpen() && trusted(ev)) {
            ev.preventDefault();
            saveFile(false);
        }
    });

    window.addEventListener('beforeunload', (ev) => {
        if (state.dirty && editorContent() !== state.lastAutosaved) {
            ev.preventDefault();
            ev.returnValue = '';
        }
    });

    /* ------------------------------------------------------------------ */
    /* Boot                                                               */
    /* ------------------------------------------------------------------ */

    navigate('');
    // Deep links from the settings screen: #trash, #site-trash.
    if (TRASH_VIEW && (location.hash === '#trash' || location.hash === '#site-trash')) {
        openTrash(location.hash === '#site-trash' ? 'site' : 'mine');
    }
})();
