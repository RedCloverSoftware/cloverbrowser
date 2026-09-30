<?php
/**
 * Two-level trash.
 *
 *   Personal trash  Each user's own deletions. They can restore them, remove
 *                   them from their trash or empty it.
 *   Site trash      A safety net for administrators: every deletion (by any
 *                   user) is kept for the site retention period, even after
 *                   the user removed it from their own trash.
 *
 * There is ONE stored copy per deleted item. It lives as long as at least one
 * level still holds it, then the hourly cleanup deletes it for good.
 *
 * Storage hardening
 *   - A randomly named folder in the uploads directory with .htaccess /
 *     web.config denies, index files and 0700 permissions — or, recommended
 *     on nginx, any folder outside the web root set with CLOVERBROWSER_TRASH_DIR.
 *   - Stored items get random names with no extension, unrelated to the ids
 *     users see, so a trashed shell.php can neither be guessed nor executed.
 *   - Metadata files are PHP files that start with an exit() guard.
 *   - The store is invisible and unreachable through the file browser for
 *     everyone, administrators included (Cloverbrowser_Sandbox::is_reserved()).
 *   - Every endpoint re-checks ownership server-side; ids are 128-bit random.
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

// phpcs:disable WordPress.WP.AlternativeFunctions -- Justification:
// Cloverbrowser is a file manager. It must act on the server's files exactly as
// they are: preserve each file's permissions when saving (WP_Filesystem::put_contents()
// resets them), stream large files in chunks for header inspection and downloads,
// take file locks, and rename/delete symbolic links themselves rather than their
// targets. WP_Filesystem cannot do these things, and its FTP/SSH transports would
// act as a different system user. Every path reaching these calls has been
// confined to the sandbox root by Cloverbrowser_Sandbox, and access is gated by
// capability, nonce and the per-role access rules (see Cloverbrowser_Ajax).

final class Cloverbrowser_Trash {

    public const OPTION       = 'cloverbrowser_trash';
    public const STORE_OPTION = 'cloverbrowser_trash_store';
    public const CRON         = 'cloverbrowser_trash_cleanup';
    public const MARKER       = '.cloverbrowser-trash';
    public const MAX_DAYS     = 3650;

    private const ID_RE      = '/^[a-f0-9]{32}$/';
    private const GUARD      = "<?php exit; ?>\n";
    private const MEASURE_MAX = 20000;          // entries walked to size a trashed folder
    private const COPY_MAX    = 268435456;      // 256 MiB: cross-disk single-file fallback

    private static ?array $settings = null;
    /** @var string|false|null */
    private static $store = null;
    private static ?array $all = null;
    /** @var resource|null */
    private static $lock = null;

    public static function register(): void {
        add_action(self::CRON, [self::class, 'cleanup']);
        add_action('deleted_user', [self::class, 'on_deleted_user'], 10, 1);
        add_action('init', [self::class, 'schedule']);
    }

    public static function schedule(): void {
        if ((is_admin() || wp_doing_cron()) && !wp_next_scheduled(self::CRON)) {
            wp_schedule_event(time() + 300, 'hourly', self::CRON);
        }
    }

    public static function unschedule(): void {
        wp_clear_scheduled_hook(self::CRON);
    }

    /* ------------------------------------------------------------------ */
    /* Settings                                                            */
    /* ------------------------------------------------------------------ */

    public static function defaults(): array {
        return [
            'user_enabled'   => true,
            'user_days'      => 30,
            'global_enabled' => true,
            'global_days'    => 7,
            'user_purge'     => false,  // only administrators may permanently delete
        ];
    }

    public static function settings(): array {
        if (self::$settings === null) {
            $raw = get_option(self::OPTION, null);
            self::$settings = is_array($raw) ? self::sanitize($raw) : self::defaults();
        }
        return self::$settings;
    }

    /** Strict whitelist of untrusted input. */
    public static function sanitize(array $raw): array {
        $d = self::defaults();
        $bool = static fn ($v, bool $def): bool => is_bool($v) ? $v : (in_array($v, [1, '1', 'true'], true) ? true : (in_array($v, [0, '0', 'false', ''], true) ? false : $def));
        $days = static function ($v, int $def): int {
            if (!is_int($v) && !(is_string($v) && ctype_digit($v)) && !(is_float($v) && is_finite($v))) {
                return $def;
            }
            return max(1, min(self::MAX_DAYS, (int) $v));
        };
        return [
            'user_enabled'   => $bool($raw['user_enabled'] ?? null, $d['user_enabled']),
            'user_days'      => $days($raw['user_days'] ?? null, $d['user_days']),
            'global_enabled' => $bool($raw['global_enabled'] ?? null, $d['global_enabled']),
            'global_days'    => $days($raw['global_days'] ?? null, $d['global_days']),
            'user_purge'     => $bool($raw['user_purge'] ?? null, $d['user_purge']),
        ];
    }

    public static function save(array $raw): array {
        $clean = self::sanitize($raw);
        update_option(self::OPTION, $clean, true);
        self::$settings = $clean;
        self::$all = null;
        return $clean;
    }

    /** Do deletions go to a trash at all? */
    public static function active(): bool {
        $s = self::settings();
        return $s['user_enabled'] || $s['global_enabled'];
    }

    /** May this user permanently delete their own trashed items? */
    public static function user_can_purge(): bool {
        return Cloverbrowser_Policy::is_admin() || (self::settings()['user_purge'] && self::settings()['user_enabled']);
    }

    /* ------------------------------------------------------------------ */
    /* Storage                                                             */
    /* ------------------------------------------------------------------ */

    private static function norm(string $p): string {
        return rtrim(str_replace('\\', '/', $p), '/');
    }

    /** Already-existing store (never creates anything) — used by the sandbox to hide it. */
    public static function existing_store(): ?string {
        if (is_string(self::$store)) {
            return self::$store;
        }
        if (defined('CLOVERBROWSER_TRASH_DIR') && is_string(CLOVERBROWSER_TRASH_DIR) && CLOVERBROWSER_TRASH_DIR !== '') {
            $real = realpath(CLOVERBROWSER_TRASH_DIR);
            return $real !== false ? self::norm($real) : null;
        }
        $opt = get_option(self::STORE_OPTION);
        if (is_array($opt) && is_string($opt['dir'] ?? null) && $opt['dir'] !== '') {
            $real = realpath($opt['dir']);
            return $real !== false ? self::norm($real) : null;
        }
        return null;
    }

    /** The store folder, created and protected on first use. */
    public static function store(): string|WP_Error {
        if (is_string(self::$store)) {
            return self::$store;
        }
        $fail = new WP_Error('fbf_trash_store', __('The trash folder could not be created. Check that the uploads folder is writable by PHP.', 'cloverbrowser'));
        $opt = get_option(self::STORE_OPTION);
        $opt = is_array($opt) ? $opt : [];
        $token = (is_string($opt['token'] ?? null) && preg_match('/^[a-f0-9]{24}$/', $opt['token'])) ? $opt['token'] : '';
        if ($token === '') {
            $token = bin2hex(random_bytes(12));
            $opt['token'] = $token;
            unset($opt['dir']);
            update_option(self::STORE_OPTION, $opt, false);
        }

        if (defined('CLOVERBROWSER_TRASH_DIR') && is_string(CLOVERBROWSER_TRASH_DIR) && CLOVERBROWSER_TRASH_DIR !== '') {
            $dir = self::prepare(self::norm(CLOVERBROWSER_TRASH_DIR), $token);
            if ($dir === null) {
                return $fail;
            }
            return self::$store = $dir;
        }
        if (is_string($opt['dir'] ?? null) && $opt['dir'] !== '' && is_file($opt['dir'] . '/' . self::MARKER)) {
            $dir = self::prepare(self::norm($opt['dir']), $token); // re-assert protections
            if ($dir !== null) {
                return self::$store = $dir;
            }
        }
        foreach (self::candidates($token) as [$candidate, $outside]) {
            $dir = self::prepare($candidate, $token);
            if ($dir !== null) {
                update_option(self::STORE_OPTION, ['dir' => $dir, 'token' => $token, 'outside' => $outside], false);
                return self::$store = $dir;
            }
        }
        return $fail;
    }

    /** @return array<int, array{0: string, 1: bool}> */
    private static function candidates(string $token): array {
        $out = [];
        $filtered = apply_filters('cloverbrowser_trash_dir', '');
        if (is_string($filtered) && $filtered !== '') {
            $out[] = [self::norm($filtered), false];
        }
        // Default: the uploads folder (writable on every WordPress site), randomly
        // named and locked down. To keep deleted files outside the web root, define
        // CLOVERBROWSER_TRASH_DIR in wp-config.php (or use the filter above).
        $uploads = wp_upload_dir(null, false);
        if (empty($uploads['error']) && is_string($uploads['basedir']) && $uploads['basedir'] !== '') {
            $out[] = [self::norm($uploads['basedir']) . '/cloverbrowser-trash-' . $token, false];
        }
        return $out;
    }

    /** Create (if needed) and lock down a store folder. Returns its real path or null. */
    private static function prepare(string $dir, string $token): ?string {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            return null;
        }
        foreach (['items', 'meta'] as $sub) {
            if (!is_dir($dir . '/' . $sub) && !@mkdir($dir . '/' . $sub, 0700)) {
                return null;
            }
            @chmod($dir . '/' . $sub, 0700);
        }
        @chmod($dir, 0700);
        $files = [
            self::MARKER   => "Cloverbrowser trash store. Do not edit.\n" . $token . "\n",
            '.htaccess'    => "# Cloverbrowser trash: never served over the web.\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder deny,allow\n\tDeny from all\n</IfModule>\n",
            'web.config'   => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <security>\n      <authorization>\n        <remove users=\"*\" roles=\"\" verbs=\"\" />\n        <add accessType=\"Deny\" users=\"*\" />\n      </authorization>\n    </security>\n  </system.webServer>\n</configuration>\n",
            'index.php'    => "<?php\n// Silence is golden.\n",
            'index.html'   => '',
            'items/index.php' => "<?php\n// Silence is golden.\n",
            'meta/index.php'  => "<?php\n// Silence is golden.\n",
        ];
        foreach ($files as $name => $content) {
            $path = $dir . '/' . $name;
            if (!is_file($path) || ($name === self::MARKER && @file_get_contents($path) !== $content)) {
                if (@file_put_contents($path, $content, LOCK_EX) === false) {
                    return null;
                }
                @chmod($path, 0600);
            }
        }
        $real = realpath($dir);
        if ($real === false || !wp_is_writable($real . '/items') || !wp_is_writable($real . '/meta')) {
            return null;
        }
        return self::norm($real);
    }

    /** Is the store outside the public web root? */
    public static function store_outside_webroot(): bool {
        $dir = self::existing_store();
        if ($dir === null) {
            return false;
        }
        $raw = isset($_SERVER['DOCUMENT_ROOT']) && is_string($_SERVER['DOCUMENT_ROOT']) ? sanitize_text_field(wp_unslash($_SERVER['DOCUMENT_ROOT'])) : '';
        $docroot = $raw !== '' ? realpath($raw) : false;
        if ($docroot === false) {
            return false;
        }
        $docroot = self::norm($docroot);
        return !($dir === $docroot || str_starts_with($dir . '/', $docroot . '/')) && !Cloverbrowser_Sandbox::contains($dir);
    }

    /* ------------------------------------------------------------------ */
    /* Locking & metadata                                                  */
    /* ------------------------------------------------------------------ */

    private static function lock(string $store): void {
        if (self::$lock === null) {
            $fh = @fopen($store . '/.lock', 'c');
            @chmod($store . '/.lock', 0600);
            if ($fh !== false) {
                flock($fh, LOCK_EX);
                self::$lock = $fh;
            }
        }
    }

    private static function unlock(): void {
        if (self::$lock !== null) {
            flock(self::$lock, LOCK_UN);
            fclose(self::$lock);
            self::$lock = null;
        }
    }

    private static function meta_path(string $store, string $id): string {
        return $store . '/meta/' . $id . '.php';
    }

    /** Read and validate one metadata file. */
    private static function read_meta(string $store, string $id): ?array {
        if (!preg_match(self::ID_RE, $id)) {
            return null;
        }
        $raw = @file_get_contents(self::meta_path($store, $id), false, null, 0, 65536);
        if (!is_string($raw) || !str_starts_with($raw, self::GUARD)) {
            return null;
        }
        $m = json_decode(substr($raw, strlen(self::GUARD)), true, 4);
        if (!is_array($m) || ($m['id'] ?? null) !== $id || !is_string($m['sid'] ?? null) || !preg_match(self::ID_RE, $m['sid'])
            || !is_string($m['path'] ?? null) || !is_int($m['uid'] ?? null) || !is_int($m['deleted'] ?? null)) {
            return null;
        }
        return [
            'id'      => $id,
            'sid'     => $m['sid'],
            'uid'     => $m['uid'],
            'login'   => (string) ($m['login'] ?? ''),
            'path'    => $m['path'],
            'name'    => (string) ($m['name'] ?? basename($m['path'])),
            'dir'     => !empty($m['dir']),
            'link'    => !empty($m['link']),
            'size'    => (int) ($m['size'] ?? 0),
            'count'   => (int) ($m['count'] ?? 1),
            'approx'  => !empty($m['approx']),
            'deleted' => $m['deleted'],
            'in_user' => !empty($m['in_user']),
            'order'   => is_int($m['order'] ?? null) ? $m['order'] : $m['deleted'] * 1000000,
        ];
    }

    private static function write_meta(string $store, array $m): bool {
        $path = self::meta_path($store, $m['id']);
        $tmp  = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $json = wp_json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json) || @file_put_contents($tmp, self::GUARD . $json, LOCK_EX) === false) {
            return false;
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $path)) {
            Cloverbrowser_Sandbox::delete_file($tmp);
            return false;
        }
        self::$all = null;
        return true;
    }

    /** @return array<string, array> every stored item, keyed by id */
    private static function all(string $store): array {
        if (self::$all !== null) {
            return self::$all;
        }
        $out = [];
        foreach ((array) @scandir($store . '/meta') as $f) {
            if (is_string($f) && preg_match('/^([a-f0-9]{32})\.php$/', $f, $mm)) {
                $m = self::read_meta($store, $mm[1]);
                if ($m !== null) {
                    $out[$m['id']] = $m;
                }
            }
        }
        uasort($out, static fn (array $a, array $b): int => $b['order'] <=> $a['order']); // newest first
        return self::$all = $out;
    }

    /* ------------------------------------------------------------------ */
    /* Retention                                                           */
    /* ------------------------------------------------------------------ */

    /** Until when the owner's personal trash shows it (0 = not in it). */
    private static function user_until(array $m, ?array $s = null): int {
        $s = $s ?? self::settings();
        return ($s['user_enabled'] && $m['in_user']) ? $m['deleted'] + $s['user_days'] * DAY_IN_SECONDS : 0;
    }

    /** Until when the site trash holds it (0 = not held). */
    private static function site_until(array $m, ?array $s = null): int {
        $s = $s ?? self::settings();
        return $s['global_enabled'] ? $m['deleted'] + $s['global_days'] * DAY_IN_SECONDS : 0;
    }

    private static function expires(array $m, ?array $s = null): int {
        return max(self::user_until($m, $s), self::site_until($m, $s));
    }

    private static function in_user_view(array $m, int $uid): bool {
        return $m['uid'] === $uid && self::user_until($m) > time();
    }

    /* ------------------------------------------------------------------ */
    /* Put                                                                 */
    /* ------------------------------------------------------------------ */

    /** Size and entry count of a file, link or folder (lstat, capped). */
    private static function measure(string $abs): array {
        if (is_link($abs) || !is_dir($abs)) {
            $st = @lstat($abs);
            return [is_array($st) ? (int) $st['size'] : 0, 1, false];
        }
        $size = 0;
        $n = 1;
        try {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            foreach ($it as $path => $info) {
                if (++$n > self::MEASURE_MAX) {
                    return [$size, $n, true];
                }
                if (!$info->isDir() || $info->isLink()) {
                    $st = @lstat((string) $path);
                    $size += is_array($st) ? (int) $st['size'] : 0;
                }
            }
        } catch (UnexpectedValueException $e) {
            return [$size, $n, true];
        }
        return [$size, $n, false];
    }

    /**
     * Move a file, link or folder into the trash. The caller has already
     * applied every access check (same as for a permanent delete).
     */
    public static function put(string $abs): array|WP_Error {
        if (!self::active()) {
            return new WP_Error('fbf_trash_off', __('The trash is turned off.', 'cloverbrowser'));
        }
        $store = self::store();
        if (is_wp_error($store)) {
            return $store;
        }
        if (!file_exists($abs) && !is_link($abs)) {
            return new WP_Error('fbf_not_found', __('Path not found.', 'cloverbrowser'));
        }
        $rel     = Cloverbrowser_Sandbox::to_relative($abs);
        $is_link = is_link($abs);
        $is_dir  = !$is_link && is_dir($abs);
        [$size, $count, $approx] = self::measure($abs);

        self::lock($store);
        try {
            $id   = bin2hex(random_bytes(16));
            $sid  = bin2hex(random_bytes(16));
            $dest = $store . '/items/' . $sid;
            $moved = @rename($abs, $dest);
            if (!$moved && !$is_dir && !$is_link && is_file($abs) && $size <= self::COPY_MAX) {
                // Different disk: copy, then remove the original only once the copy is complete.
                if (@copy($abs, $dest) && (int) @filesize($dest) === $size) {
                    $moved = Cloverbrowser_Sandbox::delete_file($abs);
                    if (!$moved) {
                        Cloverbrowser_Sandbox::delete_file($dest);
                    }
                } else {
                    Cloverbrowser_Sandbox::delete_file($dest);
                }
            }
            if (!$moved) {
                return new WP_Error('fbf_trash_move', __('This item could not be moved to the trash (it may be on another disk, or permissions do not allow it). Nothing was deleted.', 'cloverbrowser'));
            }
            $user = wp_get_current_user();
            $m = [
                'v' => 1, 'id' => $id, 'sid' => $sid, 'uid' => (int) $user->ID, 'login' => (string) $user->user_login,
                'path' => $rel, 'name' => basename($rel), 'dir' => $is_dir, 'link' => $is_link,
                'size' => $size, 'count' => $count, 'approx' => $approx, 'deleted' => time(), 'order' => (int) floor(microtime(true) * 1000000),
                'in_user' => (bool) self::settings()['user_enabled'],
            ];
            if (!self::write_meta($store, $m)) {
                @rename($dest, $abs); // put it back rather than lose track of it
                return new WP_Error('fbf_trash_meta', __('The trash could not record this item, so it was left in place.', 'cloverbrowser'));
            }
        } finally {
            self::unlock();
        }
        Cloverbrowser_Drafts::forget($rel);
        return self::row(self::read_meta($store, $id) ?? $m, false);
    }

    /* ------------------------------------------------------------------ */
    /* Listing                                                             */
    /* ------------------------------------------------------------------ */

    private static function fmt(int $ts): string {
        return (string) wp_date(get_option('date_format') . ' ' . get_option('time_format'), $ts);
    }

    /** Client representation. $site adds who deleted it and the site retention. */
    private static function row(array $m, bool $site): array {
        $uu = self::user_until($m);
        $su = self::site_until($m);
        $r = [
            'id'       => $m['id'],
            'name'     => $m['name'],
            'path'     => $m['path'],
            'dir'      => $m['dir'],
            'link'     => $m['link'],
            'size'     => $m['size'],
            'count'    => $m['count'],
            'approx'   => $m['approx'],
            'deleted'  => $m['deleted'],
            'deletedText' => self::fmt($m['deleted']),
            'userUntil'   => $uu,
            'userUntilText' => $uu ? self::fmt($uu) : '',
            'mine'     => $m['uid'] === get_current_user_id(),
        ];
        if ($site) {
            $user = get_userdata($m['uid']);
            $exp  = self::expires($m);
            $r += [
                'by'         => $user ? $user->display_name : ($m['login'] !== '' ? $m['login'] : '#' . $m['uid']),
                'inUser'     => $uu > time(),
                'siteUntil'  => $su,
                'expires'    => $exp,
                'expiresText' => self::fmt($exp),
            ];
        }
        return $r;
    }

    private static function totals(array $rows): array {
        $size = 0;
        foreach ($rows as $r) {
            $size += (int) $r['size'];
        }
        return ['count' => count($rows), 'size' => $size];
    }

    public static function list_user(int $uid): array {
        $store = self::existing_store();
        $rows = [];
        if ($store !== null) {
            self::cleanup_throttled();
            foreach (self::all($store) as $m) {
                if (self::in_user_view($m, $uid)) {
                    $rows[] = self::row($m, false);
                }
            }
        }
        return ['items' => $rows] + self::totals($rows);
    }

    public static function list_site(): array {
        $store = self::existing_store();
        $rows = [];
        if ($store !== null) {
            self::cleanup_throttled();
            $now = time();
            foreach (self::all($store) as $m) {
                if (self::expires($m) > $now) {
                    $rows[] = self::row($m, true);
                }
            }
        }
        return ['items' => $rows] + self::totals($rows);
    }

    /** Count for the browser's Trash button. */
    public static function user_count(int $uid): int {
        $store = self::existing_store();
        if ($store === null || !self::settings()['user_enabled']) {
            return 0;
        }
        $n = 0;
        foreach (self::all($store) as $m) {
            $n += self::in_user_view($m, $uid) ? 1 : 0;
        }
        return $n;
    }

    /* ------------------------------------------------------------------ */
    /* Lookups with ownership                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Load an item for an action.
     * $owner = user id → it must be that user's, and still in their personal trash.
     * $owner = null    → site trash (administrators): any item still stored.
     */
    private static function find(string $store, string $id, ?int $owner): array|WP_Error {
        $missing = new WP_Error('fbf_not_found', __('This item is no longer in the trash.', 'cloverbrowser'));
        if (!preg_match(self::ID_RE, $id)) {
            return $missing;
        }
        $m = self::read_meta($store, $id);
        if ($m === null || self::expires($m) <= time()) {
            return $missing; // indistinguishable from "someone else's item"
        }
        if ($owner !== null && !self::in_user_view($m, $owner)) {
            return $missing;
        }
        return $m;
    }

    /* ------------------------------------------------------------------ */
    /* Restore                                                             */
    /* ------------------------------------------------------------------ */

    /** "report.txt" → "report (restored).txt", "report (restored 2).txt", … */
    private static function restored_name(string $name, int $n, bool $is_dir): string {
        // Plain ASCII on purpose: file names must not depend on the admin's language.
        $suffix = $n === 1 ? 'restored' : 'restored ' . $n;
        $dot = $is_dir ? false : strrpos($name, '.');
        if ($dot === false || $dot === 0) {
            return $name . ' (' . $suffix . ')';
        }
        return substr($name, 0, $dot) . ' (' . $suffix . ')' . substr($name, $dot);
    }

    /**
     * Put an item back where it was deleted from (under a new name when that
     * name is taken). $authorize(string $dest_abs, array $new_dirs_abs, string $stored_abs, array $meta)
     * must return true or a WP_Error; it runs inside the lock, right before the move.
     */
    public static function restore(string $id, ?int $owner, callable $authorize): array|WP_Error {
        $store = self::existing_store();
        if ($store === null) {
            return new WP_Error('fbf_not_found', __('This item is no longer in the trash.', 'cloverbrowser'));
        }
        self::lock($store);
        try {
            $m = self::find($store, $id, $owner);
            if (is_wp_error($m)) {
                return $m;
            }
            $stored = $store . '/items/' . $m['sid'];
            if (!file_exists($stored) && !is_link($stored)) {
                return new WP_Error('fbf_not_found', __('The stored copy of this item is missing.', 'cloverbrowser'));
            }
            $rel = Cloverbrowser_Sandbox::clean($m['path']);
            if (is_wp_error($rel) || $rel === '') {
                return new WP_Error('fbf_bad_path', __('Invalid path.', 'cloverbrowser'));
            }
            // Find the deepest existing ancestor; the rest must be recreated.
            $segs  = explode('/', $rel);
            $name  = array_pop($segs);
            $exist = $segs;
            $missing = [];
            $root  = Cloverbrowser_Sandbox::root();
            $base  = $root;
            while ($exist) {
                $raw = $root . '/' . implode('/', $exist);
                if (file_exists($raw) || is_link($raw)) {
                    // Something is there: it must be a real folder inside the sandbox
                    // (a symlink pointing elsewhere must never become a way out).
                    $base = Cloverbrowser_Sandbox::resolve(implode('/', $exist));
                    if (is_wp_error($base)) {
                        return $base;
                    }
                    if (!is_dir($base)) {
                        return new WP_Error('fbf_restore', sprintf(
                            /* translators: %s: path */
                            __('Cannot restore: %s is no longer a folder.', 'cloverbrowser'), implode('/', $exist)));
                    }
                    break;
                }
                array_unshift($missing, array_pop($exist));
            }
            $new_dirs = [];
            $cur = $base;
            foreach ($missing as $seg) {
                $cur .= '/' . $seg;
                $new_dirs[] = $cur;
            }
            $parent = $cur;
            $target = $parent . '/' . $name;
            $n = 0;
            while (file_exists($target) || is_link($target)) {
                if (++$n > 99) {
                    return new WP_Error('fbf_exists', __('Could not find a free name to restore this item under.', 'cloverbrowser'));
                }
                $target = $parent . '/' . self::restored_name($name, $n, $m['dir']);
            }
            if (Cloverbrowser_Sandbox::is_reserved($target) || !Cloverbrowser_Sandbox::contains($target)) {
                return new WP_Error('fbf_sandbox', __('Path resolves outside the sandbox.', 'cloverbrowser'));
            }
            $ok = $authorize($target, $new_dirs, $stored, $m);
            if ($ok !== true) {
                return $ok instanceof WP_Error ? $ok : new WP_Error('fbf_denied', __('Your role is not allowed to do that.', 'cloverbrowser'));
            }
            foreach ($new_dirs as $d) {
                if (file_exists($d) || is_link($d) || !@mkdir($d, 0755)) {
                    return new WP_Error('fbf_mkdir', sprintf(
                        /* translators: %s: folder path */
                        __('Could not recreate the folder %s.', 'cloverbrowser'), Cloverbrowser_Sandbox::to_relative($d)));
                }
            }
            $real_parent = realpath($parent);
            if ($real_parent === false || !Cloverbrowser_Sandbox::contains($real_parent) || Cloverbrowser_Sandbox::is_reserved($real_parent)) {
                return new WP_Error('fbf_sandbox', __('Path resolves outside the sandbox.', 'cloverbrowser'));
            }
            if (!@rename($stored, $target)) {
                return new WP_Error('fbf_restore', __('Restore failed (check permissions on the original folder).', 'cloverbrowser'));
            }
            Cloverbrowser_Sandbox::delete_file(self::meta_path($store, $m['id']));
            self::$all = null;
        } finally {
            self::unlock();
        }
        return ['rel' => Cloverbrowser_Sandbox::to_relative($target), 'renamed' => basename($target) !== $name, 'name' => basename($target)];
    }

    /* ------------------------------------------------------------------ */
    /* Remove / purge                                                      */
    /* ------------------------------------------------------------------ */

    /** Delete a stored copy for good (never follows symlinks). */
    private static function destroy(string $store, array $m): bool {
        $path = $store . '/items/' . $m['sid'];
        $ok = true;
        if (is_link($path) || is_file($path)) {
            $ok = Cloverbrowser_Sandbox::delete_file($path);
        } elseif (is_dir($path)) {
            try {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($it as $p => $info) {
                    if ($info->isDir() && !$info->isLink()) {
                        @chmod((string) $p, 0700); // a read-only subfolder must not block cleanup
                        $ok = @rmdir((string) $p) && $ok;
                    } else {
                        $ok = Cloverbrowser_Sandbox::delete_file((string) $p) && $ok;
                    }
                }
            } catch (UnexpectedValueException $e) {
                $ok = false;
            }
            $ok = @rmdir($path) && $ok;
        }
        if ($ok || (!file_exists($path) && !is_link($path))) {
            Cloverbrowser_Sandbox::delete_file(self::meta_path($store, $m['id']));
            self::$all = null;
            return true;
        }
        return false;
    }

    /**
     * Take an item out of its owner's personal trash. It stays in the site
     * trash while that still holds it; otherwise it is deleted for good.
     */
    public static function remove_from_user(string $id, int $uid): array|WP_Error {
        $store = self::existing_store();
        if ($store === null) {
            return new WP_Error('fbf_not_found', __('This item is no longer in the trash.', 'cloverbrowser'));
        }
        self::lock($store);
        try {
            $m = self::find($store, $id, $uid);
            if (is_wp_error($m)) {
                return $m;
            }
            return self::dismiss($store, $m);
        } finally {
            self::unlock();
        }
    }

    private static function dismiss(string $store, array $m): array {
        $m['in_user'] = false;
        $site = self::site_until($m);
        if ($site > time()) {
            self::write_meta($store, ['v' => 1] + $m);
            return ['removed' => true, 'keptUntil' => $site];
        }
        self::destroy($store, $m);
        return ['removed' => true, 'keptUntil' => 0];
    }

    public static function empty_user(int $uid): array {
        $store = self::existing_store();
        $n = 0;
        if ($store !== null) {
            self::lock($store);
            try {
                foreach (self::all($store) as $m) {
                    if (self::in_user_view($m, $uid)) {
                        self::dismiss($store, $m);
                        $n++;
                    }
                }
            } finally {
                self::unlock();
            }
        }
        return ['removed' => $n];
    }

    /** Permanently delete one item (owner from their trash when allowed, or an administrator). */
    public static function purge(string $id, ?int $owner): array|WP_Error {
        $store = self::existing_store();
        if ($store === null) {
            return new WP_Error('fbf_not_found', __('This item is no longer in the trash.', 'cloverbrowser'));
        }
        self::lock($store);
        try {
            $m = self::find($store, $id, $owner);
            if (is_wp_error($m)) {
                return $m;
            }
            if (!self::destroy($store, $m)) {
                return new WP_Error('fbf_delete', __('Some of this item could not be deleted (check permissions).', 'cloverbrowser'));
            }
        } finally {
            self::unlock();
        }
        return ['purged' => 1];
    }

    /** Empty the whole site trash (administrators). */
    public static function purge_all(): array {
        $store = self::existing_store();
        $n = 0;
        $failed = 0;
        if ($store !== null) {
            self::lock($store);
            try {
                foreach (self::all($store) as $m) {
                    self::destroy($store, $m) ? $n++ : $failed++;
                }
            } finally {
                self::unlock();
            }
        }
        return ['purged' => $n, 'failed' => $failed];
    }

    /* ------------------------------------------------------------------ */
    /* Housekeeping                                                        */
    /* ------------------------------------------------------------------ */

    /** Hourly: delete expired items and orphans. */
    public static function cleanup(): int {
        $store = self::existing_store();
        if ($store === null) {
            return 0;
        }
        $n = 0;
        self::lock($store);
        try {
            $now = time();
            $known = [];
            foreach (self::all($store) as $m) {
                if (self::expires($m) <= $now) {
                    $n += self::destroy($store, $m) ? 1 : 0;
                } else {
                    $known[$m['sid']] = true;
                }
            }
            // Items with no (valid) metadata — e.g. an interrupted delete — after a grace period.
            foreach ((array) @scandir($store . '/items') as $f) {
                if (is_string($f) && preg_match(self::ID_RE, $f) && !isset($known[$f])) {
                    $st = @lstat($store . '/items/' . $f);
                    if (is_array($st) && $st['ctime'] < $now - DAY_IN_SECONDS) {
                        $n += self::destroy($store, ['id' => str_repeat('0', 32), 'sid' => $f]) ? 1 : 0;
                    }
                }
            }
            foreach ((array) @scandir($store . '/meta') as $f) {
                if (is_string($f) && str_ends_with($f, '.tmp') && (int) @filemtime($store . '/meta/' . $f) < $now - HOUR_IN_SECONDS) {
                    Cloverbrowser_Sandbox::delete_file($store . '/meta/' . $f);
                }
            }
        } finally {
            self::unlock();
        }
        return $n;
    }

    /** Opportunistic cleanup when a trash is opened (in case WP-Cron is not running). */
    private static function cleanup_throttled(): void {
        if (get_transient('cloverbrowser_trash_gc') === false) {
            set_transient('cloverbrowser_trash_gc', 1, 10 * MINUTE_IN_SECONDS);
            self::cleanup();
        }
    }

    /** A deleted account's personal trash goes away; the site trash keeps its copies. */
    public static function on_deleted_user($uid): void {
        $uid = (int) $uid;
        $store = self::existing_store();
        if ($uid <= 0 || $store === null) {
            return;
        }
        self::lock($store);
        try {
            foreach (self::all($store) as $m) {
                if ($m['uid'] === $uid && $m['in_user']) {
                    self::dismiss($store, $m);
                }
            }
        } finally {
            self::unlock();
        }
    }

    /** Remove the whole store (uninstall). Only a folder carrying our marker is ever touched. */
    public static function destroy_store(string $dir, string $token): bool {
        $dir = self::norm($dir);
        $marker = @file_get_contents($dir . '/' . self::MARKER);
        if ($token === '' || !is_string($marker) || !str_contains($marker, $token)) {
            return false;
        }
        try {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $p => $info) {
                if ($info->isDir() && !$info->isLink()) {
                    @chmod((string) $p, 0700);
                    @rmdir((string) $p);
                } else {
                    Cloverbrowser_Sandbox::delete_file((string) $p);
                }
            }
        } catch (UnexpectedValueException $e) {
            return false;
        }
        return @rmdir($dir);
    }

    /* ------------------------------------------------------------------ */
    /* Client info & admin stats                                           */
    /* ------------------------------------------------------------------ */

    public static function client_info(): array {
        $s = self::settings();
        return [
            'trash' => [
                'user'       => $s['user_enabled'],
                'userDays'   => $s['user_days'],
                'site'       => $s['global_enabled'],
                'siteDays'   => $s['global_days'],
                'canPurge'   => self::user_can_purge(),
                'isAdmin'    => Cloverbrowser_Policy::is_admin(),
                'count'      => self::user_count(get_current_user_id()),
            ],
        ];
    }

    public static function admin_info(): array {
        $site = self::list_site();
        $dir = self::existing_store();
        return [
            'settings' => self::settings(),
            'count'    => $site['count'],
            'size'     => $site['size'],
            'sizeText' => size_format($site['size']),
            'location' => $dir ?? '',
            'outside'  => self::store_outside_webroot(),
            'custom'   => defined('CLOVERBROWSER_TRASH_DIR'),
        ];
    }
}
