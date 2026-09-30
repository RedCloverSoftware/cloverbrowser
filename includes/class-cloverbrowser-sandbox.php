<?php
/**
 * Path sandbox: the client only ever sees root-relative paths.
 * The server resolves them to absolute real paths and refuses anything
 * that escapes the sandbox root (including via symlinks / "..").
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

final class Cloverbrowser_Sandbox {

    /**
     * Capability required to open the browser at all (filterable).
     * On multisite, subsite admins must NOT get access to files shared by
     * the whole network (wp-config.php etc.), so default to super admins.
     */
    public static function cap(): string {
        $default = is_multisite() ? 'manage_network_options' : 'manage_options';
        return (string) apply_filters('cloverbrowser_capability', $default);
    }

    /**
     * May the current user modify files? Honours WordPress' own file-edit
     * lockdown (DISALLOW_FILE_EDIT / DISALLOW_FILE_MODS map `edit_files` to
     * do_not_allow). CLOVERBROWSER_READ_ONLY overrides explicitly in either direction.
     */
    public static function can_write(): bool {
        if (!current_user_can(Cloverbrowser_Policy::ACCESS_CAP)) {
            return false;
        }
        if (current_user_can(self::cap())) {
            $allowed = defined('CLOVERBROWSER_READ_ONLY') ? !CLOVERBROWSER_READ_ONLY : current_user_can('edit_files');
        } else {
            // Restricted roles: the site-wide file-edit lock applies to them too,
            // then the access policy must grant at least one write permission.
            $allowed = !self::site_write_locked();
            $eff = Cloverbrowser_Policy::effective();
            $any = false;
            foreach (Cloverbrowser_Policy::WRITE_PERMS as $p) {
                $any = $any || !empty($eff['perms'][$p]);
            }
            $allowed = $allowed && $any;
        }
        return (bool) apply_filters('cloverbrowser_can_write', $allowed);
    }

    /** CLOVERBROWSER_READ_ONLY, or WordPress' own DISALLOW_FILE_EDIT / DISALLOW_FILE_MODS. */
    public static function site_write_locked(): bool {
        if (defined('CLOVERBROWSER_READ_ONLY')) {
            return (bool) CLOVERBROWSER_READ_ONLY;
        }
        return (defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS) || (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT);
    }

    /** Human-readable reason shown in the UI when writes are disabled. */
    public static function read_only_reason(): string {
        if (defined('CLOVERBROWSER_READ_ONLY') && CLOVERBROWSER_READ_ONLY) {
            return __('CLOVERBROWSER_READ_ONLY is set in wp-config.php.', 'cloverbrowser');
        }
        if ((defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS) || (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT)) {
            return __('DISALLOW_FILE_EDIT / DISALLOW_FILE_MODS is set in wp-config.php. Define CLOVERBROWSER_READ_ONLY as false to override.', 'cloverbrowser');
        }
        if (!current_user_can(self::cap())) {
            return __('Your role has read-only access.', 'cloverbrowser');
        }
        return __('Your account does not have the edit_files capability.', 'cloverbrowser');
    }

    /**
     * Delete one file or symbolic link (never follows the link) through
     * WordPress' wp_delete_file(). Returns whether it is gone.
     */
    public static function delete_file(string $path): bool {
        wp_delete_file($path);
        clearstatcache(true, $path);
        return !file_exists($path) && !is_link($path);
    }

    /** Canonical sandbox root for THIS site (defaults to this vhost's ABSPATH). */
    public static function root(): string {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }
        $raw  = defined('CLOVERBROWSER_ROOT') ? (string) CLOVERBROWSER_ROOT : (string) apply_filters('cloverbrowser_root_path', ABSPATH);
        $real = realpath($raw);
        $cached = ($real !== false)
            ? rtrim(str_replace('\\', '/', $real), '/')
            : rtrim(str_replace('\\', '/', $raw), '/');
        return $cached;
    }

    /** Is the absolute path inside (or equal to) the sandbox root? */
    public static function contains(string $abs): bool {
        $root = rtrim(str_replace('\\', '/', self::root()), '/');
        $path = rtrim(str_replace('\\', '/', $abs), '/');
        if (DIRECTORY_SEPARATOR === '\\') {
            $path = strtolower($path);
            $root = strtolower($root);
        }
        if ($path === $root) {
            return true;
        }
        return str_starts_with($path, $root . '/');
    }

    /**
     * Folders the file browser must never reach, for anyone (administrators
     * included): currently the trash store, when it lives inside the sandbox.
     *
     * @return string[] absolute real paths
     */
    public static function reserved(): array {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }
        $store = class_exists('Cloverbrowser_Trash') ? Cloverbrowser_Trash::existing_store() : null;
        if ($store === null) {
            return []; // not created yet — look again next time
        }
        return $cached = [$store];
    }

    private static function cmp_path(string $p): string {
        $p = rtrim(str_replace('\\', '/', $p), '/');
        return DIRECTORY_SEPARATOR === '\\' ? strtolower($p) : $p;
    }

    /** Is $abs a reserved folder or inside one? */
    public static function is_reserved(string $abs): bool {
        $path = self::cmp_path($abs);
        foreach (self::reserved() as $r) {
            $r = self::cmp_path($r);
            if ($path === $r || str_starts_with($path . '/', $r . '/')) {
                return true;
            }
        }
        return false;
    }

    /** Does the folder $abs contain a reserved folder (so moving/deleting it would take that along)? */
    public static function contains_reserved(string $abs): bool {
        $path = self::cmp_path($abs);
        foreach (self::reserved() as $r) {
            if (str_starts_with(self::cmp_path($r) . '/', $path . '/')) {
                return true;
            }
        }
        return false;
    }

    private static function reserved_error(string $rel): WP_Error {
        // Looks exactly like a missing path: the store's name is never disclosed.
        return new WP_Error('fbf_not_found', sprintf(
            /* translators: %s: path */
            __('Path not found or not accessible: %s', 'cloverbrowser'),
            $rel
        ));
    }

    /**
     * Normalize a root-relative path: forward slashes only, '.' segments
     * dropped, '..' segments unwound, NUL bytes rejected.
     * (No trimming: names with leading/trailing spaces are legal.)
     *
     * @return string|WP_Error
     */
    public static function clean(string $relative) {
        if ($relative === '') {
            return '';
        }
        // Bounded input: no filesystem path is longer than this.
        if (strlen($relative) > 4096) {
            return new WP_Error('fbf_bad_path', __('Invalid path.', 'cloverbrowser'));
        }
        if (str_contains($relative, "\0")) {
            return new WP_Error('fbf_bad_path', __('Invalid path.', 'cloverbrowser'));
        }
        $relative = ltrim(str_replace('\\', '/', $relative), '/');
        $out = [];
        foreach (explode('/', $relative) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($out);
                continue;
            }
            // On Windows, drive letters / alternate data streams are meaningless here.
            if (PHP_OS_FAMILY === 'Windows' && str_contains($seg, ':')) {
                return new WP_Error('fbf_bad_path', __('Invalid path segment.', 'cloverbrowser'));
            }
            $out[] = $seg;
        }
        return implode('/', $out);
    }

    /**
     * Resolve a root-relative path to an absolute real path.
     * With $must_exist = false the FINAL segment may not exist yet
     * (mkdir / new file / rename target); every parent must.
     *
     * @return string|WP_Error
     */
    public static function resolve(string $relative, bool $must_exist = true) {
        $rel = self::clean($relative);
        if (is_wp_error($rel)) {
            return $rel;
        }
        $root = self::root();

        if ($must_exist) {
            $abs  = $rel === '' ? $root : $root . '/' . $rel;
            $real = realpath($abs);
            if ($real === false) {
                // Missing, unreadable, or blocked by open_basedir.
                return new WP_Error('fbf_not_found', sprintf(
                    /* translators: %s: path */
                    __('Path not found or not accessible: %s', 'cloverbrowser'),
                    $rel
                ));
            }
            if (!self::contains($real)) {
                return new WP_Error('fbf_sandbox', __('Path resolves outside the sandbox.', 'cloverbrowser'));
            }
            if (self::is_reserved($real)) {
                return self::reserved_error($rel);
            }
            return str_replace('\\', '/', $real);
        }

        $parts = $rel === '' ? [] : explode('/', $rel);
        $name  = array_pop($parts);
        if ($name === null || $name === '') {
            return new WP_Error('fbf_bad_path', __('A name is required.', 'cloverbrowser'));
        }
        if ($name === '.' || $name === '..' || strpbrk($name, "/\\\0") !== false) {
            return new WP_Error('fbf_bad_path', __('Invalid name.', 'cloverbrowser'));
        }
        $parentRel = implode('/', $parts);
        $parent    = $parentRel === '' ? $root : realpath($root . '/' . $parentRel);
        if ($parent === false) {
            return new WP_Error('fbf_not_found', sprintf(
                /* translators: %s: path */
                __('Parent folder not found: %s', 'cloverbrowser'),
                $parentRel
            ));
        }
        if (!self::contains($parent)) {
            return new WP_Error('fbf_sandbox', __('Parent folder resolves outside the sandbox.', 'cloverbrowser'));
        }
        $abs = rtrim(str_replace('\\', '/', $parent), '/') . '/' . $name;
        if (self::is_reserved($abs)) {
            return self::reserved_error($rel);
        }
        return $abs;
    }

    /**
     * Resolve an EXISTING directory entry WITHOUT following a symlink in the
     * final segment. Used for delete / rename, which must act on a link
     * itself rather than on whatever it points to. The sandbox root itself
     * is never a valid target.
     *
     * @return string|WP_Error
     */
    public static function resolve_entry(string $relative) {
        $rel = self::clean($relative);
        if (is_wp_error($rel)) {
            return $rel;
        }
        if ($rel === '') {
            return new WP_Error('fbf_root', __('This operation is not allowed on the sandbox root.', 'cloverbrowser'));
        }
        $abs = self::resolve($rel, false);
        if (is_wp_error($abs)) {
            return $abs;
        }
        if (!file_exists($abs) && !is_link($abs)) {
            return new WP_Error('fbf_not_found', sprintf(
                /* translators: %s: path */
                __('Path not found: %s', 'cloverbrowser'),
                $rel
            ));
        }
        return $abs;
    }

    /** Convert a validated absolute path back to a root-relative client path. */
    public static function to_relative(string $abs): string {
        $root = rtrim(str_replace('\\', '/', self::root()), '/');
        $path = str_replace('\\', '/', $abs);
        $cmp  = static fn (string $s): string => DIRECTORY_SEPARATOR === '\\' ? strtolower($s) : $s;
        if ($cmp($path) === $cmp($root)) {
            return '';
        }
        if (str_starts_with($cmp($path), $cmp($root) . '/')) {
            return substr($path, strlen($root) + 1);
        }
        return ltrim($path, '/');
    }
}
