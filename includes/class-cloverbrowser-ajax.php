<?php
/**
 * AJAX endpoints. No REST routes are registered anywhere in this plugin.
 *
 * Every request:  logged-in + `cloverbrowser_access` capability, POST only,
 *                 same-origin (Sec-Fetch-Site / Origin), valid nonce,
 *                 per-user rate limit, then the access policy for the
 *                 specific path and action (Cloverbrowser_Policy::check()).
 * Mutations:      additionally Cloverbrowser_Sandbox::can_write().
 * Access rules:   administrators only.
 * Trash:          a user only ever sees and acts on their OWN personal trash
 *                 (ownership re-checked server-side on every call); the site
 *                 trash and trash settings are administrators only.
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

final class Cloverbrowser_Ajax {

    private const ACTIONS = [
        'list', 'read', 'draft_read', 'draft_save', 'draft_discard', 'download', 'nonce',
        'save', 'convert_eol', 'chmod', 'mkdir', 'newfile', 'rename', 'delete', 'upload',
        'policy_get', 'policy_save', 'policy_test',
        'trash_list', 'trash_restore', 'trash_remove', 'trash_purge', 'trash_empty',
        'trash_settings_get', 'trash_settings_save',
    ];
    private const MAX_POLICY_JSON = 262144; // 256 KiB

    public static function register(): void {
        foreach (self::ACTIONS as $action) {
            add_action('wp_ajax_cloverbrowser_' . $action, [self::class, 'handle_' . $action]);
        }
    }

    /* ------------------------------- guards ------------------------------- */

    /** A request header / server value, unslashed and sanitized (null when absent). */
    private static function server(string $key): ?string {
        if (!isset($_SERVER[$key]) || !is_string($_SERVER[$key])) {
            return null;
        }
        return sanitize_text_field(wp_unslash($_SERVER[$key]));
    }

    private static function is_post(): bool {
        return self::server('REQUEST_METHOD') === 'POST';
    }

    /** Reject cross-site requests even before the nonce is looked at. */
    private static function same_origin(): bool {
        $site = self::server('HTTP_SEC_FETCH_SITE');
        if ($site !== null && !in_array($site, ['same-origin', 'none'], true)) {
            return false;
        }
        $origin = self::server('HTTP_ORIGIN');
        if ($origin !== null && $origin !== '') {
            $host = wp_parse_url($origin, PHP_URL_HOST);
            $port = wp_parse_url($origin, PHP_URL_PORT);
            $want = strtolower((string) self::server('HTTP_HOST'));
            $got  = strtolower((string) $host) . ($port ? ':' . $port : '');
            if ($origin === 'null' || $got !== $want) {
                return false;
            }
        }
        return true;
    }

    /**
     * Per-user request budget. Hampers scripted mass actions (e.g. an
     * injected script looping over delete/download) at negligible cost.
     */
    private static function rate_limit(string $bucket): void {
        $limits = (array) apply_filters('cloverbrowser_rate_limits', ['read' => 900, 'write' => 300]);
        $max = (int) ($limits[$bucket] ?? 300);
        if ($max <= 0) {
            return;
        }
        $key  = 'cloverbrowser_rl_' . $bucket . '_' . get_current_user_id();
        $now  = time();
        $data = get_transient($key);
        if (!is_array($data) || count($data) !== 2 || (int) $data[1] <= $now - 60) {
            $data = [0, $now];
        }
        $data[0] = (int) $data[0] + 1;
        set_transient($key, $data, 60);
        if ($data[0] > $max) {
            wp_send_json_error(['message' => __('Too many requests — wait a minute and try again.', 'cloverbrowser'), 'code' => 'fbf_rate'], 429);
        }
    }

    private static function guard(bool $write = false): void {
        if (!is_user_logged_in() || !current_user_can(Cloverbrowser_Policy::ACCESS_CAP)) {
            wp_send_json_error(['message' => __('You do not have permission to use the file browser.', 'cloverbrowser'), 'code' => 'fbf_forbidden'], 403);
        }
        if (!self::is_post()) {
            wp_send_json_error(['message' => __('Bad request method.', 'cloverbrowser'), 'code' => 'fbf_method'], 405);
        }
        if (!self::same_origin()) {
            wp_send_json_error(['message' => __('Cross-site request refused.', 'cloverbrowser'), 'code' => 'fbf_origin'], 403);
        }
        $nonce = self::str('nonce');
        if ($nonce === null || !wp_verify_nonce($nonce, 'cloverbrowser_ajax')) {
            wp_send_json_error(['message' => __('Security check failed — reload the page and try again.', 'cloverbrowser'), 'code' => 'fbf_nonce'], 403);
        }
        self::rate_limit($write ? 'write' : 'read');
        if ($write && !Cloverbrowser_Sandbox::can_write()) {
            wp_send_json_error([
                /* translators: %s: reason why the file browser is read-only */
                'message' => sprintf(__('The file browser is in read-only mode: %s', 'cloverbrowser'), Cloverbrowser_Sandbox::read_only_reason()),
                'code'    => 'fbf_read_only',
            ], 403);
        }
    }

    private static function admin_guard(): void {
        self::guard();
        if (!Cloverbrowser_Policy::is_admin()) {
            wp_send_json_error(['message' => __('Only administrators can manage access rules.', 'cloverbrowser'), 'code' => 'fbf_forbidden'], 403);
        }
    }

    private static function fail(string|WP_Error $err, int $code = 400): void {
        if (is_wp_error($err)) {
            $c = $err->get_error_code();
            if ($code === 400) {
                $code = match ($c) {
                    'fbf_scope', 'fbf_denied', 'fbf_protected', 'fbf_type', 'fbf_scope_root', 'fbf_forbidden', 'fbf_limit', 'fbf_reserved' => 403,
                    'fbf_not_found' => 404,
                    'fbf_conflict'  => 409,
                    default => 400,
                };
            }
            wp_send_json_error(['message' => $err->get_error_message(), 'code' => $c], $code);
        }
        wp_send_json_error(['message' => $err, 'code' => 'fbf_error'], $code);
    }

    /** Policy gate helper: fail the request unless $result === true. */
    private static function ok($result): void {
        if ($result !== true) {
            self::fail($result instanceof WP_Error ? $result : new WP_Error('fbf_denied', __('Your role is not allowed to do that.', 'cloverbrowser')));
        }
    }

    /**
     * A string POST field, with WordPress' magic-quote slashing removed.
     * (Without wp_unslash() every save would turn " into \" and \ into \\.)
     *
     * Nonces: every handler calls guard()/admin_guard() (or the download
     * checks) before reading any other field — the nonce itself is read here.
     *
     * Sanitization is deliberately field-specific, never sanitize_text_field():
     * file contents must be saved byte for byte, and file names/paths may
     * legally contain characters that function would strip or rewrite. Every
     * value is validated where it is used: paths by Cloverbrowser_Sandbox::clean()
     * and resolve() (NUL bytes, "..", length, sandbox confinement), names by
     * name_arg() / Cloverbrowser_Files::upload_name(), ids and modes by strict
     * regular expressions, JSON by depth/size-limited decoding plus whitelist
     * sanitizers. Nothing read here is ever output without escaping.
     */
    private static function str(string $key): ?string {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked in guard() before any other field is used.
        if (!isset($_POST[$key]) || !is_string($_POST[$key])) {
            return null;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- see above: validated per field where used.
        return wp_unslash($_POST[$key]);
    }

    /** @return string|WP_Error */
    private static function resolve_arg(string $key, bool $must_exist = true) {
        $raw = self::str($key);
        if ($raw === null) {
            return new WP_Error('fbf_bad_request', __('Bad request.', 'cloverbrowser'));
        }
        return Cloverbrowser_Sandbox::resolve($raw, $must_exist);
    }

    /** @return string|WP_Error Existing entry, final symlink NOT followed, never the root. */
    private static function resolve_entry_arg(string $key) {
        $raw = self::str($key);
        if ($raw === null) {
            return new WP_Error('fbf_bad_request', __('Bad request.', 'cloverbrowser'));
        }
        return Cloverbrowser_Sandbox::resolve_entry($raw);
    }

    /** @return string|WP_Error validated single path segment */
    private static function name_arg() {
        $name = self::str('name');
        if ($name === null || $name === '') {
            return new WP_Error('fbf_bad_request', __('A name is required.', 'cloverbrowser'));
        }
        if (strpbrk($name, "/\\\0") !== false || $name === '.' || $name === '..') {
            return new WP_Error('fbf_bad_name', __('Names cannot contain slashes or be “.” / “..”.', 'cloverbrowser'));
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $name) || strlen($name) > 255 || (function_exists('mb_check_encoding') && !mb_check_encoding($name, 'UTF-8'))) {
            return new WP_Error('fbf_bad_name', __('Names cannot contain control characters or exceed 255 bytes.', 'cloverbrowser'));
        }
        if (PHP_OS_FAMILY === 'Windows' && preg_match('/[:*?"<>|]/', $name)) {
            return new WP_Error('fbf_bad_name', __('That name contains characters that are not allowed on this server.', 'cloverbrowser'));
        }
        return $name;
    }

    private static function flag(string $key): bool {
        $v = self::str($key);
        return $v === '1' || $v === 'true';
    }

    /** Refuse to move, delete or recursively change a folder that holds the trash store. */
    private static function not_reserved_ancestor(string $abs): void {
        if (Cloverbrowser_Sandbox::contains_reserved($abs)) {
            self::fail(new WP_Error('fbf_reserved', __('This folder contains Cloverbrowser’s trash storage, so it cannot be moved, deleted or changed recursively.', 'cloverbrowser')));
        }
    }

    /** Type gate for a file that exists on disk. */
    private static function type_ok(string $abs, ?string $as_name = null): void {
        $eff = Cloverbrowser_Policy::effective();
        if ($eff !== null && is_file($abs)) {
            $err = Cloverbrowser_Policy::type_error($eff, Cloverbrowser_Filetype::classify_file($abs, $as_name));
            if ($err) {
                self::fail($err);
            }
        }
    }

    /* ------------------------------- handlers ------------------------------ */

    public static function handle_nonce(): void {
        self::guard();
        // Rotated through this authenticated endpoint rather than the heartbeat,
        // so the token is never broadcast to other scripts via jQuery events.
        wp_send_json_success(['nonce' => wp_create_nonce('cloverbrowser_ajax')]);
    }

    public static function handle_list(): void {
        self::guard();
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('list', $abs));
        $list = Cloverbrowser_Files::list_dir($abs);
        if (is_wp_error($list)) {
            self::fail($list);
        }
        $eff = Cloverbrowser_Policy::effective();
        $out = ['path' => Cloverbrowser_Sandbox::to_relative($abs), 'nav' => false, 'protected' => false] + $list;
        if ($eff !== null) {
            $out['entries'] = array_map(static function (array $e): array {
                unset($e['owner'], $e['group']); // don't disclose system account names
                return $e;
            }, Cloverbrowser_Policy::filter_listing($abs, $list['entries'], $eff));
            $out['total']     = count($out['entries']);
            $out['nav']       = !Cloverbrowser_Policy::in_scope($eff, $abs);
            $out['protected'] = Cloverbrowser_Policy::rule_effect($eff, $out['path']) === 'readonly';
        }
        wp_send_json_success($out);
    }

    public static function handle_read(): void {
        self::guard();
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('view', $abs));
        if (is_dir($abs)) {
            self::fail(__('That path is a folder.', 'cloverbrowser'));
        }
        self::type_ok($abs);
        $data = Cloverbrowser_Files::read($abs);
        if (is_wp_error($data)) {
            self::fail($data);
        }
        $eff = Cloverbrowser_Policy::effective();
        $data['protected'] = $eff !== null && Cloverbrowser_Policy::rule_effect($eff, Cloverbrowser_Sandbox::to_relative($abs)) === 'readonly';
        wp_send_json_success($data);
    }

    public static function handle_save(): void {
        self::guard(true);
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('edit', $abs));
        self::type_ok($abs);
        // Missing content usually means the POST body exceeded PHP limits —
        // never silently save an empty file in that case.
        $content = self::str('content');
        if ($content === null) {
            self::fail(__('Content missing from the request (it may exceed PHP post limits).', 'cloverbrowser'));
        }
        $content = Cloverbrowser_Files::normalize_eol($content);
        $eff = Cloverbrowser_Policy::effective();
        if ($eff !== null) {
            // The NEW content must not introduce a blocked type (e.g. PHP pasted into a .txt).
            $cats = Cloverbrowser_Filetype::classify(basename($abs), substr($content, 0, Cloverbrowser_Filetype::HEAD_BYTES));
            if (in_array('php', $eff['types'], true) && Cloverbrowser_Filetype::has_php_marker($content)) {
                $cats[] = 'php';
            }
            $err = Cloverbrowser_Policy::type_error($eff, $cats);
            if ($err) {
                self::fail($err);
            }
            $growth = strlen($content) - (int) @filesize($abs);
            if ($eff['max_growth'] > 0 && $growth > $eff['max_growth']) {
                self::fail(new WP_Error('fbf_limit', sprintf(
                    /* translators: 1: size increase, 2: allowed size increase */
                    __('This edit would make the file %1$s larger; your role may grow a file by at most %2$s per save.', 'cloverbrowser'),
                    size_format($growth), size_format($eff['max_growth'])
                )));
            }
        }
        $result = Cloverbrowser_Files::save($abs, $content, self::flag('allow_empty'), self::str('base_hash'), self::flag('force'));
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    public static function handle_convert_eol(): void {
        self::guard(true);
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('edit', $abs));
        self::type_ok($abs);
        $result = Cloverbrowser_Files::convert_eol($abs);
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    /* Drafts live in the database and never touch the filesystem. */

    public static function handle_draft_read(): void {
        self::guard();
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('view', $abs));
        $result = Cloverbrowser_Drafts::get(Cloverbrowser_Sandbox::to_relative($abs));
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    public static function handle_draft_save(): void {
        self::guard();
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('edit', $abs));
        if (!is_file($abs)) {
            self::fail(__('Original file is missing; draft not saved.', 'cloverbrowser'));
        }
        $content = self::str('content');
        if ($content === null) {
            self::fail(__('Content missing from the request.', 'cloverbrowser'));
        }
        $result = Cloverbrowser_Drafts::put(Cloverbrowser_Sandbox::to_relative($abs), Cloverbrowser_Files::normalize_eol($content), (string) self::str('base_hash'));
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    public static function handle_draft_discard(): void {
        self::guard();
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('view', $abs));
        wp_send_json_success(['discarded' => Cloverbrowser_Drafts::discard(Cloverbrowser_Sandbox::to_relative($abs))]);
    }

    public static function handle_chmod(): void {
        self::guard(true);
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('chmod', $abs));
        $mode = self::str('mode');
        if ($mode === null || !preg_match('/^0?[0-7]{3,4}$/', $mode)) {
            self::fail(__('Invalid permission mode (use octal, e.g. 0644).', 'cloverbrowser'));
        }
        $recursive = self::flag('recursive');
        if ($recursive) {
            self::not_reserved_ancestor($abs);
            self::ok(Cloverbrowser_Policy::check_tree($abs));
        }
        $result = Cloverbrowser_Files::chmod($abs, (int) octdec($mode), $recursive);
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    public static function handle_mkdir(): void {
        self::guard(true);
        $dir = self::resolve_arg('dir');
        if (is_wp_error($dir)) {
            self::fail($dir);
        }
        $name = self::name_arg();
        if (is_wp_error($name)) {
            self::fail($name);
        }
        self::ok(Cloverbrowser_Policy::check('create', $dir . '/' . $name));
        $result = Cloverbrowser_Files::mkdir($dir . '/' . $name);
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    public static function handle_newfile(): void {
        self::guard(true);
        $dir = self::resolve_arg('dir');
        if (is_wp_error($dir)) {
            self::fail($dir);
        }
        $name = self::name_arg();
        if (is_wp_error($name)) {
            self::fail($name);
        }
        self::ok(Cloverbrowser_Policy::check('create', $dir . '/' . $name));
        $eff = Cloverbrowser_Policy::effective();
        if ($eff !== null && ($err = Cloverbrowser_Policy::type_error($eff, Cloverbrowser_Filetype::by_name($name)))) {
            self::fail($err);
        }
        $result = Cloverbrowser_Files::create_file($dir . '/' . $name);
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    public static function handle_rename(): void {
        self::guard(true);
        $src = self::resolve_entry_arg('from');
        if (is_wp_error($src)) {
            self::fail($src);
        }
        $dst = self::resolve_arg('to', false);
        if (is_wp_error($dst)) {
            self::fail($dst);
        }
        self::ok(Cloverbrowser_Policy::check('rename', $src));
        self::ok(Cloverbrowser_Policy::check('rename_to', $dst));
        self::not_reserved_ancestor($src);
        if (is_dir($src) && !is_link($src)) {
            self::ok(Cloverbrowser_Policy::check_tree($src));
        } else {
            // Judge the file by its content under the NEW name (e.g. notes.txt → shell.php).
            self::type_ok($src, basename($dst));
        }
        $result = Cloverbrowser_Files::rename($src, $dst);
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    public static function handle_delete(): void {
        self::guard(true);
        $abs = self::resolve_entry_arg('path');
        if (is_wp_error($abs)) {
            self::fail($abs);
        }
        self::ok(Cloverbrowser_Policy::check('delete', $abs));
        self::not_reserved_ancestor($abs);
        $permanent = self::flag('permanent');
        if ($permanent && Cloverbrowser_Trash::active() && !Cloverbrowser_Policy::is_admin()) {
            // Everyone else's deletions always go through the trash.
            self::fail(new WP_Error('fbf_denied', __('Only administrators can delete items without using the trash.', 'cloverbrowser')));
        }
        $is_tree = is_dir($abs) && !is_link($abs);

        if (Cloverbrowser_Trash::active() && !$permanent) {
            // The whole folder moves, so everything inside must be deletable by this role.
            if ($is_tree) {
                self::ok(Cloverbrowser_Policy::check_tree($abs));
            }
            $item = Cloverbrowser_Trash::put($abs);
            if (is_wp_error($item)) {
                self::fail($item);
            }
            wp_send_json_success([
                'trashed'    => true,
                'item'       => $item,
                'deleted'    => (int) $item['count'],
                'trashCount' => Cloverbrowser_Trash::user_count(get_current_user_id()),
            ]);
        }

        $recursive = self::flag('recursive');
        if ($recursive) {
            self::ok(Cloverbrowser_Policy::check_tree($abs));
        }
        $result = Cloverbrowser_Files::delete($abs, $recursive);
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result + ['trashed' => false]);
    }

    public static function handle_upload(): void {
        self::guard(true);
        $dir = self::resolve_arg('dir');
        if (is_wp_error($dir)) {
            self::fail($dir);
        }
        if (!is_dir($dir)) {
            self::fail(__('Upload target is not a folder.', 'cloverbrowser'));
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- nonce checked in guard(); the name is validated by upload_name() and the temporary file by is_uploaded_file() and content inspection.
        $file = isset($_FILES['file']) && is_array($_FILES['file']) ? $_FILES['file'] : null;
        if (!is_array($file) || !is_string($file['tmp_name'] ?? null)) {
            self::fail(__('No file was uploaded.', 'cloverbrowser'));
        }
        $name = Cloverbrowser_Files::upload_name(is_string($file['name'] ?? null) ? $file['name'] : '');
        if (is_wp_error($name)) {
            self::fail($name);
        }
        $dst = $dir . '/' . $name;
        self::ok(Cloverbrowser_Policy::check('upload', $dst));
        $eff = Cloverbrowser_Policy::effective();
        if ($eff !== null) {
            if (file_exists($dst)) {
                self::ok(Cloverbrowser_Policy::check('edit', $dst)); // replacing = modifying
            }
            $tmp = $file['tmp_name'];
            if ($tmp !== '' && is_uploaded_file($tmp)) {
                $size = (int) @filesize($tmp);
                if ($eff['max_upload'] > 0 && $size > $eff['max_upload']) {
                    self::fail(new WP_Error('fbf_limit', sprintf(
                        /* translators: 1: file size, 2: maximum upload size */
                        __('This file is %1$s; your role may upload at most %2$s per file.', 'cloverbrowser'),
                        size_format($size), size_format($eff['max_upload'])
                    )));
                }
                // Header inspection of the real bytes, not the claimed name/MIME.
                $cats = Cloverbrowser_Filetype::classify_file($tmp, $name);
                if (in_array('php', $eff['types'], true)) {
                    $has = Cloverbrowser_Filetype::file_has_php($tmp); // full scan: catches image/PHP polyglots
                    if ($has === null) {
                        self::fail(new WP_Error('fbf_type', __('This file is too large to be checked for blocked content.', 'cloverbrowser')));
                    }
                    if ($has) {
                        $cats[] = 'php';
                    }
                }
                if ($err = Cloverbrowser_Policy::type_error($eff, $cats)) {
                    self::fail($err);
                }
            }
        }
        $result = Cloverbrowser_Files::upload($dir, $file, self::flag('overwrite'), self::flag('convert_eol'));
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result);
    }

    /** Form POST into a hidden iframe (attachment download). Errors are plain text. */
    public static function handle_download(): void {
        if (!is_user_logged_in() || !current_user_can(Cloverbrowser_Policy::ACCESS_CAP)) {
            Cloverbrowser_Files::plain_error(__('Forbidden.', 'cloverbrowser'), 403);
        }
        $nonce = self::str('nonce');
        if (!self::is_post() || !self::same_origin() || $nonce === null || !wp_verify_nonce($nonce, 'cloverbrowser_ajax')) {
            Cloverbrowser_Files::plain_error(__('Security check failed — reload the page and try again.', 'cloverbrowser'), 403);
        }
        $abs = self::resolve_arg('path');
        if (is_wp_error($abs)) {
            Cloverbrowser_Files::plain_error($abs->get_error_message(), 404);
        }
        $ok = Cloverbrowser_Policy::check('download', $abs);
        if ($ok === true && ($eff = Cloverbrowser_Policy::effective()) !== null) {
            $ok = Cloverbrowser_Policy::type_error($eff, Cloverbrowser_Filetype::classify_file($abs)) ?? true;
        }
        if ($ok !== true) {
            Cloverbrowser_Files::plain_error($ok->get_error_message(), 403);
        }
        Cloverbrowser_Files::download($abs);
    }

    /* --------------------------- access rules ---------------------------- */

    private static function policy_arg(): array {
        $json = self::str('policy');
        if ($json === null || strlen($json) > self::MAX_POLICY_JSON) {
            self::fail(__('Bad request.', 'cloverbrowser'));
        }
        $data = json_decode($json, true, 8);
        if (!is_array($data)) {
            self::fail(__('Bad request.', 'cloverbrowser'));
        }
        return $data;
    }

    public static function handle_policy_get(): void {
        self::admin_guard();
        $counts = count_users();
        $roles = [];
        foreach (Cloverbrowser_Policy::restrictable_roles() as $key => $label) {
            $roles[] = ['key' => $key, 'label' => $label, 'users' => (int) ($counts['avail_roles'][$key] ?? 0), 'lowTrust' => in_array($key, Cloverbrowser_Policy::LOW_TRUST_ROLES, true)];
        }
        $types = [];
        foreach (Cloverbrowser_Filetype::CATEGORIES as $cat) {
            $types[] = ['key' => $cat, 'label' => Cloverbrowser_Policy::type_label($cat)];
        }
        $builtin = array_map(static fn (array $r): array => ['m' => $r['m'], 'p' => $r['p'], 'e' => $r['e']], Cloverbrowser_Policy::builtin_rules());
        wp_send_json_success([
            'settings' => Cloverbrowser_Policy::get(),
            'roles'    => $roles,
            'types'    => $types,
            'builtin'  => $builtin,
            'writeLocked' => Cloverbrowser_Sandbox::site_write_locked(),
        ]);
    }

    public static function handle_policy_save(): void {
        self::admin_guard();
        self::rate_limit('write');
        wp_send_json_success(Cloverbrowser_Policy::save(self::policy_arg()));
    }

    public static function handle_policy_test(): void {
        self::admin_guard();
        $warnings = [];
        $settings = Cloverbrowser_Policy::sanitize(self::policy_arg(), $warnings);
        $role = (string) self::str('role');
        $path = (string) self::str('path');
        wp_send_json_success(Cloverbrowser_Policy::simulate($settings, $role, $path));
    }

    /* -------------------------------- trash -------------------------------- */

    /** 'mine' (the caller's personal trash) or 'site' (administrators only). */
    private static function trash_scope(): string {
        $scope = self::str('scope') === 'site' ? 'site' : 'mine';
        if ($scope === 'site' && !Cloverbrowser_Policy::is_admin()) {
            self::fail(new WP_Error('fbf_forbidden', __('Only administrators can open the site trash.', 'cloverbrowser')));
        }
        return $scope;
    }

    private static function trash_id(): string {
        $id = self::str('id');
        if ($id === null || !preg_match('/^[a-f0-9]{32}$/', $id)) {
            self::fail(new WP_Error('fbf_bad_request', __('Bad request.', 'cloverbrowser')));
        }
        return $id;
    }

    private static function trash_state(): array {
        return ['trashCount' => Cloverbrowser_Trash::user_count(get_current_user_id())];
    }

    public static function handle_trash_list(): void {
        self::guard();
        $scope = self::trash_scope();
        $data = $scope === 'site' ? Cloverbrowser_Trash::list_site() : Cloverbrowser_Trash::list_user(get_current_user_id());
        wp_send_json_success($data + ['scope' => $scope] + self::trash_state());
    }

    public static function handle_trash_restore(): void {
        self::guard(true);
        $scope = self::trash_scope();
        $id = self::trash_id();
        $eff = Cloverbrowser_Policy::effective();
        // Runs inside the trash lock, right before the item is moved back.
        $authorize = static function (string $dest, array $new_dirs, string $stored, array $meta) use ($eff) {
            if ($eff === null) {
                return true; // administrator
            }
            foreach ($new_dirs as $d) {
                $r = Cloverbrowser_Policy::check('create', $d, $eff);
                if ($r !== true) {
                    return $r;
                }
            }
            $r = Cloverbrowser_Policy::check('restore', $dest, $eff);
            if ($r !== true) {
                return $r;
            }
            if (is_file($stored) && !is_link($stored)) {
                // Same header inspection as an upload: the content is judged, under its restore name.
                $cats = Cloverbrowser_Filetype::classify_file($stored, basename($dest));
                if (in_array('php', $eff['types'], true)) {
                    $has = Cloverbrowser_Filetype::file_has_php($stored);
                    if ($has === null || $has) {
                        $cats[] = 'php';
                    }
                }
                if ($err = Cloverbrowser_Policy::type_error($eff, $cats)) {
                    return $err;
                }
            } elseif (is_dir($stored) && !is_link($stored)) {
                $dest_rel = Cloverbrowser_Sandbox::to_relative($dest);
                $n = 0;
                try {
                    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($stored, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                    foreach ($it as $path => $info) {
                        if (++$n > 10000) {
                            break;
                        }
                        $rel = $dest_rel . substr(str_replace('\\', '/', (string) $path), strlen($stored));
                        if (Cloverbrowser_Policy::rule_effect($eff, $rel) !== null) {
                            return new WP_Error('fbf_protected', __('This folder contains protected items, so your role cannot do that to it.', 'cloverbrowser'));
                        }
                    }
                } catch (UnexpectedValueException $e) {
                    return new WP_Error('fbf_perm', __('Could not read the folder.', 'cloverbrowser'));
                }
            }
            return true;
        };
        $result = Cloverbrowser_Trash::restore($id, $scope === 'site' ? null : get_current_user_id(), $authorize);
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result + self::trash_state());
    }

    /** Take an item out of the caller's personal trash (the site trash may keep it). */
    public static function handle_trash_remove(): void {
        self::guard(true);
        $result = Cloverbrowser_Trash::remove_from_user(self::trash_id(), get_current_user_id());
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result + self::trash_state());
    }

    /**
     * Delete one item for good. From "mine" only when an administrator allows
     * users to do so; from "site" administrators only.
     */
    public static function handle_trash_purge(): void {
        self::guard(true);
        $scope = self::trash_scope();
        $id = self::trash_id();
        if ($scope === 'mine' && !Cloverbrowser_Trash::user_can_purge()) {
            self::fail(new WP_Error('fbf_denied', __('Only administrators can permanently delete items from the trash.', 'cloverbrowser')));
        }
        $result = Cloverbrowser_Trash::purge($id, $scope === 'site' ? null : get_current_user_id());
        if (is_wp_error($result)) {
            self::fail($result);
        }
        wp_send_json_success($result + self::trash_state());
    }

    /** "mine": clear the personal trash (the site trash keeps its copies). "site": administrators empty everything. */
    public static function handle_trash_empty(): void {
        self::guard(true);
        $scope = self::trash_scope();
        $result = $scope === 'site' ? Cloverbrowser_Trash::purge_all() : Cloverbrowser_Trash::empty_user(get_current_user_id());
        wp_send_json_success($result + self::trash_state());
    }

    public static function handle_trash_settings_get(): void {
        self::admin_guard();
        wp_send_json_success(Cloverbrowser_Trash::admin_info());
    }

    public static function handle_trash_settings_save(): void {
        self::admin_guard();
        self::rate_limit('write');
        $json = self::str('settings');
        $data = ($json !== null && strlen($json) <= 4096) ? json_decode($json, true, 3) : null;
        if (!is_array($data)) {
            self::fail(__('Bad request.', 'cloverbrowser'));
        }
        Cloverbrowser_Trash::save($data);
        wp_send_json_success(Cloverbrowser_Trash::admin_info());
    }
}
