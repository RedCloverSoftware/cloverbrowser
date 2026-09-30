<?php
/**
 * Role-based access policy.
 *
 * Administrators (holders of Cloverbrowser_Sandbox::cap()) are unrestricted and manage
 * the policy. Every other role has no access until an administrator enables
 * it. For enabled roles the "All roles" (global) rules ALWAYS apply and a
 * role's own rules can only restrict further:
 *
 *   permissions      allowed by global AND by the role
 *   allowed folders  inside a global folder AND inside a role folder
 *   blocked types    global ∪ role
 *   protected items  built-in ∪ global ∪ role
 *   size limits      the smaller non-zero value
 *
 * A user holding several enabled roles gets the most permissive combination
 * of those roles, still capped by the global rules.
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

final class Cloverbrowser_Policy {

    public const OPTION     = 'cloverbrowser_policy';
    public const ACCESS_CAP = 'cloverbrowser_access';
    public const PERMS      = ['view', 'download', 'edit', 'create', 'upload', 'rename', 'delete', 'chmod'];
    public const WRITE_PERMS = ['edit', 'create', 'upload', 'rename', 'delete', 'chmod'];
    public const MATCH      = ['contains', 'name', 'path', 'tree'];
    public const EFFECTS    = ['hide', 'readonly'];
    public const LOW_TRUST_ROLES = ['subscriber', 'contributor', 'customer'];

    private const MAX_RULES   = 200;
    private const MAX_PATHS   = 50;
    private const MAX_PATTERN = 255;
    private const MAX_BYTES   = 1099511627776; // 1 TiB — caps limits to sane integers

    /** Action → permission it requires. */
    private const ACTION_PERM = [
        'view' => 'view', 'download' => 'download', 'edit' => 'edit', 'create' => 'create',
        'upload' => 'upload', 'rename' => 'rename', 'rename_to' => 'rename', 'delete' => 'delete', 'chmod' => 'chmod',
        'restore' => 'delete', // undoing a deletion needs the permission that made it
    ];
    private const WRITE_ACTIONS = ['edit', 'create', 'upload', 'rename', 'rename_to', 'delete', 'chmod', 'restore'];

    private static ?array $settings = null;
    private static array $eff_cache = [];

    public static function register(): void {
        add_filter('user_has_cap', [self::class, 'grant_access_cap'], 10, 4);
    }

    /* ------------------------------------------------------------------ */
    /* Settings                                                            */
    /* ------------------------------------------------------------------ */

    public static function default_set(bool $global): array {
        return [
            'enabled'    => false,
            'perms'      => $global
                ? ['view' => true, 'download' => true, 'edit' => true, 'create' => true, 'upload' => true, 'rename' => true, 'delete' => true, 'chmod' => false]
                : ['view' => true, 'download' => true, 'edit' => false, 'create' => false, 'upload' => false, 'rename' => false, 'delete' => false, 'chmod' => false],
            'paths'      => [],
            'types'      => $global ? ['php', 'server_config', 'executable'] : [],
            'rules'      => [],
            'max_upload' => 0,
            'max_growth' => 0,
        ];
    }

    public static function defaults(): array {
        return ['version' => 1, 'global' => self::default_set(true), 'roles' => []];
    }

    public static function get(): array {
        if (self::$settings === null) {
            $raw = get_option(self::OPTION, null);
            $warnings = [];
            self::$settings = is_array($raw) ? self::sanitize($raw, $warnings) : self::defaults();
        }
        return self::$settings;
    }

    /** @return array{settings: array, warnings: string[]} */
    public static function save(array $raw): array {
        $warnings = [];
        $clean = self::sanitize($raw, $warnings);
        update_option(self::OPTION, $clean, true);
        self::$settings  = $clean;
        self::$eff_cache = [];
        return ['settings' => $clean, 'warnings' => $warnings];
    }

    /** Roles that can be restricted (roles that already hold the admin capability are always unrestricted). */
    public static function restrictable_roles(): array {
        $out = [];
        $admin_cap = Cloverbrowser_Sandbox::cap();
        foreach (wp_roles()->roles as $key => $role) {
            if (!empty($role['capabilities'][$admin_cap])) {
                continue;
            }
            $out[(string) $key] = translate_user_role((string) $role['name']);
        }
        return $out;
    }

    /** Strict whitelist sanitation of untrusted settings input. */
    public static function sanitize(array $raw, array &$warnings): array {
        $out = self::defaults();
        $out['global'] = self::sanitize_set(is_array($raw['global'] ?? null) ? $raw['global'] : [], true, $warnings, __('All roles', 'cloverbrowser'));
        $roles = self::restrictable_roles();
        $in_roles = is_array($raw['roles'] ?? null) ? $raw['roles'] : [];
        foreach ($roles as $key => $label) {
            if (isset($in_roles[$key]) && is_array($in_roles[$key])) {
                $out['roles'][$key] = self::sanitize_set($in_roles[$key], false, $warnings, $label);
            }
        }
        // Cross-checks that only make sense with the whole picture.
        foreach ($out['roles'] as $key => $set) {
            if (!$set['enabled']) {
                continue;
            }
            $label = $roles[$key] ?? $key;
            if (in_array($key, self::LOW_TRUST_ROLES, true)) {
                /* translators: %s: role name */
                $warnings[] = sprintf(__('%s is normally given to untrusted accounts. Make sure you really want it to reach server files.', 'cloverbrowser'), $label);
            }
            $writes_code = !in_array('php', $out['global']['types'], true) && !in_array('php', $set['types'], true)
                && ($set['perms']['edit'] || $set['perms']['upload'] || $set['perms']['create'] || $set['perms']['rename'])
                && ($out['global']['perms']['edit'] || $out['global']['perms']['upload'] || $out['global']['perms']['create'] || $out['global']['perms']['rename']);
            if ($writes_code) {
                /* translators: %s: role name */
                $warnings[] = sprintf(__('%s can create or modify PHP code. Anyone who can write PHP can take over the whole site — block the “PHP code” type unless that is intended.', 'cloverbrowser'), $label);
            }
        }
        return $out;
    }

    private static function sanitize_set(array $in, bool $global, array &$warnings, string $label): array {
        $set = self::default_set($global);
        $set['enabled'] = !$global && !empty($in['enabled']) && $in['enabled'] !== 'false';
        if (is_array($in['perms'] ?? null)) {
            foreach (self::PERMS as $p) {
                $set['perms'][$p] = !empty($in['perms'][$p]) && $in['perms'][$p] !== 'false';
            }
        }
        $set['paths'] = [];
        foreach (array_slice(is_array($in['paths'] ?? null) ? $in['paths'] : [], 0, self::MAX_PATHS) as $p) {
            if (!is_string($p) || strlen($p) > 1024) {
                continue;
            }
            $rel = Cloverbrowser_Sandbox::clean($p);
            if (is_wp_error($rel) || $rel === '' || in_array($rel, $set['paths'], true)) {
                continue;
            }
            $abs = Cloverbrowser_Sandbox::resolve($rel);
            if (is_wp_error($abs) || !is_dir($abs)) {
                /* translators: 1: folder path, 2: role name */
                $warnings[] = sprintf(__('The folder “%1$s” (%2$s) does not exist; it grants no access until it is created.', 'cloverbrowser'), $rel, $label);
            }
            $set['paths'][] = $rel;
        }
        $set['types'] = array_values(array_intersect(Cloverbrowser_Filetype::CATEGORIES, is_array($in['types'] ?? null) ? array_filter($in['types'], 'is_string') : []));
        $set['rules'] = [];
        $seen = [];
        foreach (array_slice(is_array($in['rules'] ?? null) ? $in['rules'] : [], 0, self::MAX_RULES) as $r) {
            if (!is_array($r)) {
                continue;
            }
            $m = is_string($r['m'] ?? null) ? $r['m'] : '';
            $e = is_string($r['e'] ?? null) ? $r['e'] : '';
            $p = is_string($r['p'] ?? null) ? trim($r['p']) : '';
            if (!in_array($m, self::MATCH, true) || !in_array($e, self::EFFECTS, true) || $p === '' || strlen($p) > self::MAX_PATTERN || preg_match('/[\x00-\x1F\x7F]/', $p)) {
                continue;
            }
            if ($m === 'path' || $m === 'tree') {
                $c = Cloverbrowser_Sandbox::clean($p);
                if (is_wp_error($c) || $c === '') {
                    continue;
                }
                $p = $c;
            } elseif (str_contains($p, '/')) {
                continue; // name rules match a single path segment
            }
            $key = $m . "\0" . self::lower($p) . "\0" . $e;
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $set['rules'][] = ['m' => $m, 'p' => $p, 'e' => $e];
        }
        foreach (['max_upload', 'max_growth'] as $k) {
            $v = $in[$k] ?? 0;
            $v = is_numeric($v) ? (float) $v : 0;
            $set[$k] = (int) max(0, min(self::MAX_BYTES, floor($v)));
        }
        return $set;
    }

    /* ------------------------------------------------------------------ */
    /* Who is restricted                                                   */
    /* ------------------------------------------------------------------ */

    public static function is_admin(?WP_User $user = null): bool {
        $user = $user ?? wp_get_current_user();
        return $user instanceof WP_User && $user->exists() && user_can($user, Cloverbrowser_Sandbox::cap());
    }

    public static function unrestricted(): bool {
        return self::is_admin();
    }

    /** user_has_cap filter: grants the virtual `cloverbrowser_access` capability. */
    public static function grant_access_cap(array $allcaps, array $caps, array $args, $user): array {
        if (!in_array(self::ACCESS_CAP, $caps, true) || !$user instanceof WP_User) {
            return $allcaps;
        }
        $admin_cap = Cloverbrowser_Sandbox::cap();
        if (!empty($allcaps[$admin_cap])) {
            $allcaps[self::ACCESS_CAP] = true;
            return $allcaps;
        }
        $allcaps[self::ACCESS_CAP] = self::enabled_roles_of($user) !== [];
        return $allcaps;
    }

    private static function enabled_roles_of(WP_User $user, ?array $settings = null): array {
        $settings = $settings ?? self::get();
        $out = [];
        foreach ((array) $user->roles as $role) {
            if (!empty($settings['roles'][$role]['enabled'])) {
                $out[] = (string) $role;
            }
        }
        return $out;
    }

    /* ------------------------------------------------------------------ */
    /* Effective policy                                                    */
    /* ------------------------------------------------------------------ */

    /** Effective policy for the current user; null = unrestricted (administrator). */
    public static function effective(): ?array {
        if (self::unrestricted()) {
            return null;
        }
        $uid = get_current_user_id();
        if (!isset(self::$eff_cache[$uid])) {
            self::$eff_cache[$uid] = self::compute(self::get(), self::enabled_roles_of(wp_get_current_user()));
        }
        return self::$eff_cache[$uid];
    }

    /** Build the effective policy of a set of (enabled) roles. */
    public static function compute(array $settings, array $roles): array {
        $g = $settings['global'];
        $sets = [];
        foreach ($roles as $r) {
            if (isset($settings['roles'][$r])) {
                $sets[] = $settings['roles'][$r];
            }
        }
        $eff = [
            'access' => $sets !== [],
            'perms'  => array_fill_keys(self::PERMS, false),
            'global_roots' => self::resolve_roots($g['paths']),
            'role_roots'   => null,
            'types'  => $g['types'],
            'rules'  => array_merge(self::builtin_rules(), $g['rules']),
            'max_upload' => $g['max_upload'],
            'max_growth' => $g['max_growth'],
        ];
        if (!$sets) {
            $eff['roots'] = [];
            return $eff;
        }
        // Merge roles permissively …
        $role_perms = array_fill_keys(self::PERMS, false);
        $role_paths = [];
        $unlimited_paths = false;
        $types = null;
        $rules = null;
        $max_upload = null;
        $max_growth = null;
        foreach ($sets as $s) {
            foreach (self::PERMS as $p) {
                $role_perms[$p] = $role_perms[$p] || $s['perms'][$p];
            }
            if ($s['paths'] === []) {
                $unlimited_paths = true;
            }
            $role_paths = array_merge($role_paths, $s['paths']);
            $types = $types === null ? $s['types'] : array_values(array_intersect($types, $s['types']));
            $keyed = [];
            foreach ($s['rules'] as $rule) {
                $keyed[$rule['m'] . "\0" . self::lower($rule['p']) . "\0" . $rule['e']] = $rule;
            }
            $rules = $rules === null ? $keyed : array_intersect_key($rules, $keyed);
            $max_upload = $max_upload === null ? $s['max_upload'] : (($max_upload === 0 || $s['max_upload'] === 0) ? 0 : max($max_upload, $s['max_upload']));
            $max_growth = $max_growth === null ? $s['max_growth'] : (($max_growth === 0 || $s['max_growth'] === 0) ? 0 : max($max_growth, $s['max_growth']));
        }
        // … then cap by the global rules.
        foreach (self::PERMS as $p) {
            $eff['perms'][$p] = $role_perms[$p] && $g['perms'][$p];
        }
        $eff['role_roots'] = $unlimited_paths ? null : self::resolve_roots(array_values(array_unique($role_paths)));
        $eff['types'] = array_values(array_unique(array_merge($g['types'], $types ?? [])));
        $eff['rules'] = array_merge($eff['rules'], array_values($rules ?? []));
        $eff['max_upload'] = self::min_limit($g['max_upload'], (int) $max_upload);
        $eff['max_growth'] = self::min_limit($g['max_growth'], (int) $max_growth);
        $eff['roots'] = self::combine_roots($eff['global_roots'], $eff['role_roots']);
        return $eff;
    }

    private static function min_limit(int $a, int $b): int {
        if ($a === 0) {
            return $b;
        }
        return $b === 0 ? $a : min($a, $b);
    }

    /** Relative folder list → canonical absolute paths. null = no folder limit. */
    private static function resolve_roots(array $paths): ?array {
        if ($paths === []) {
            return null;
        }
        $out = [];
        foreach ($paths as $rel) {
            $abs = Cloverbrowser_Sandbox::resolve((string) $rel);
            if (!is_wp_error($abs) && is_dir($abs)) {
                $out[] = rtrim($abs, '/');
            }
        }
        return array_values(array_unique($out)); // [] = limit configured but nothing exists → no access
    }

    private static function within(string $abs, string $root): bool {
        return $abs === $root || str_starts_with($abs, $root . '/') || $root === '';
    }

    /** Intersection of two folder lists (null = unlimited). */
    private static function combine_roots(?array $a, ?array $b): ?array {
        if ($a === null) {
            return $b;
        }
        if ($b === null) {
            return $a;
        }
        $out = [];
        foreach ($a as $x) {
            foreach ($b as $y) {
                if (self::within($y, $x)) {
                    $out[] = $y;
                } elseif (self::within($x, $y)) {
                    $out[] = $x;
                }
            }
        }
        return array_values(array_unique($out));
    }

    /** Protected for every non-administrator, whatever the settings say. */
    public static function builtin_rules(): array {
        $rules = [];
        $root = Cloverbrowser_Sandbox::root();
        foreach ([ABSPATH . 'wp-config.php', dirname(ABSPATH) . '/wp-config.php'] as $cfg) {
            $real = realpath($cfg);
            if ($real !== false && Cloverbrowser_Sandbox::contains($real)) {
                $rules[] = ['m' => 'path', 'p' => Cloverbrowser_Sandbox::to_relative($real), 'e' => 'hide', 'builtin' => true];
            }
        }
        $plugin = realpath(CLOVERBROWSER_PLUGIN_DIR);
        if ($plugin !== false && Cloverbrowser_Sandbox::contains($plugin) && $plugin !== $root) {
            $rules[] = ['m' => 'tree', 'p' => Cloverbrowser_Sandbox::to_relative($plugin), 'e' => 'hide', 'builtin' => true];
        }
        return $rules;
    }

    /* ------------------------------------------------------------------ */
    /* Matching                                                            */
    /* ------------------------------------------------------------------ */

    public static function lower(string $s): string {
        return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
    }

    /**
     * Wildcard match (* and ?), case-insensitive, linear-time two-pointer
     * algorithm — no regular expressions, so no ReDoS from admin patterns
     * or attacker-chosen file names.
     */
    public static function glob_match(string $pattern, string $text): bool {
        $split = static fn (string $s): array => function_exists('mb_str_split') ? mb_str_split(self::lower($s), 1, 'UTF-8') : str_split(self::lower($s));
        $p = $split($pattern);
        $t = $split($text);
        $pn = count($p);
        $tn = count($t);
        $pi = $ti = 0;
        $star = -1;
        $mark = 0;
        while ($ti < $tn) {
            if ($pi < $pn && ($p[$pi] === '?' || $p[$pi] === $t[$ti])) {
                $pi++;
                $ti++;
            } elseif ($pi < $pn && $p[$pi] === '*') {
                $star = $pi++;
                $mark = $ti;
            } elseif ($star !== -1) {
                $pi = $star + 1;
                $ti = ++$mark;
            } else {
                return false;
            }
        }
        while ($pi < $pn && $p[$pi] === '*') {
            $pi++;
        }
        return $pi === $pn;
    }

    /** Does a rule match this sandbox-relative path (or one of its parent folders)? */
    public static function rule_matches(array $rule, string $rel): bool {
        $lrel = self::lower($rel);
        $lp   = self::lower($rule['p']);
        switch ($rule['m']) {
            case 'path':
                return $lrel === $lp;
            case 'tree':
                return $lrel === $lp || str_starts_with($lrel, $lp . '/');
            case 'name':
            case 'contains':
                foreach ($rel === '' ? [] : explode('/', $rel) as $seg) {
                    if ($rule['m'] === 'name' ? self::glob_match($rule['p'], $seg) : str_contains(self::lower($seg), $lp)) {
                        return true;
                    }
                }
                return false;
        }
        return false;
    }

    /** 'hide' | 'readonly' | null */
    public static function rule_effect(array $eff, string $rel): ?string {
        $effect = null;
        foreach ($eff['rules'] as $rule) {
            if (self::rule_matches($rule, $rel)) {
                if ($rule['e'] === 'hide') {
                    return 'hide';
                }
                $effect = 'readonly';
            }
        }
        return $effect;
    }

    public static function in_scope(array $eff, string $abs): bool {
        if ($eff['roots'] === null) {
            return true;
        }
        foreach ($eff['roots'] as $root) {
            if (self::within($abs, $root)) {
                return true;
            }
        }
        return false;
    }

    /** Strict ancestor of an allowed folder (navigable, but nothing else). */
    public static function is_nav_ancestor(array $eff, string $abs): bool {
        if ($eff['roots'] === null) {
            return false;
        }
        $abs = rtrim($abs, '/');
        foreach ($eff['roots'] as $root) {
            if ($root !== $abs && (str_starts_with($root, $abs . '/') || $abs === Cloverbrowser_Sandbox::root() && $root !== $abs)) {
                return true;
            }
        }
        return false;
    }

    public static function is_root(array $eff, string $abs): bool {
        return $eff['roots'] !== null && in_array(rtrim($abs, '/'), $eff['roots'], true);
    }

    /** Blocked categories among $cats, or []. */
    public static function blocked_types(array $eff, array $cats): array {
        return array_values(array_intersect($eff['types'], $cats));
    }

    public static function type_label(string $cat): string {
        $labels = [
            'php'           => __('PHP code', 'cloverbrowser'),
            'server_config' => __('Server configuration', 'cloverbrowser'),
            'executable'    => __('Programs & scripts', 'cloverbrowser'),
            'web_active'    => __('Web pages, SVG & JavaScript', 'cloverbrowser'),
            'archive'       => __('Archives', 'cloverbrowser'),
            'image'         => __('Images', 'cloverbrowser'),
            'media'         => __('Audio & video', 'cloverbrowser'),
            'document'      => __('Documents & PDFs', 'cloverbrowser'),
            'database'      => __('Databases & dumps', 'cloverbrowser'),
            'binary'        => __('Any other binary file', 'cloverbrowser'),
        ];
        return $labels[$cat] ?? $cat;
    }

    public static function type_error(array $eff, array $cats): ?WP_Error {
        $blocked = self::blocked_types($eff, $cats);
        if (!$blocked) {
            return null;
        }
        return new WP_Error('fbf_type', sprintf(
            /* translators: %s: file type name(s), e.g. "PHP code" */
            __('This file type (%s) is blocked for your role.', 'cloverbrowser'),
            implode(', ', array_map([self::class, 'type_label'], $blocked))
        ));
    }

    /* ------------------------------------------------------------------ */
    /* Gate                                                                */
    /* ------------------------------------------------------------------ */

    /**
     * Central permission gate for a restricted user.
     * $abs must come from Cloverbrowser_Sandbox::resolve() or resolve_entry().
     * Returns true, or a WP_Error explaining the refusal.
     *
     * @return true|WP_Error
     */
    public static function check(string $action, string $abs, ?array $eff = null) {
        if ($eff === null) {
            $eff = self::effective();
            if ($eff === null) {
                return true; // administrator
            }
        }
        if (!$eff['access']) {
            return new WP_Error('fbf_forbidden', __('You do not have permission to use the file browser.', 'cloverbrowser'));
        }
        $rel = Cloverbrowser_Sandbox::to_relative($abs);
        if (!self::in_scope($eff, $abs) && !($action === 'list' && self::is_nav_ancestor($eff, $abs))) {
            return new WP_Error('fbf_scope', __('This location is outside the folders your role can access.', 'cloverbrowser'));
        }
        $effect = self::rule_effect($eff, $rel);
        if ($effect === 'hide') {
            // Indistinguishable from a missing path: protected names are not disclosed.
            return new WP_Error('fbf_not_found', sprintf(
                /* translators: %s: path */
                __('Path not found or not accessible: %s', 'cloverbrowser'),
                $rel
            ));
        }
        $need = self::ACTION_PERM[$action] ?? null;
        if ($need !== null && empty($eff['perms'][$need])) {
            return new WP_Error('fbf_denied', self::denied_message($need));
        }
        if (in_array($action, self::WRITE_ACTIONS, true) && $effect === 'readonly') {
            return new WP_Error('fbf_protected', __('This item is protected: your role can only read it.', 'cloverbrowser'));
        }
        if (in_array($action, ['rename', 'delete', 'chmod'], true) && (self::is_root($eff, $abs) || self::is_nav_ancestor($eff, $abs))) {
            return new WP_Error('fbf_scope_root', __('The top-level folders your role can access cannot be renamed, deleted or have their permissions changed.', 'cloverbrowser'));
        }
        return true;
    }

    public static function denied_message(string $perm): string {
        $m = [
            'view'     => __('Your role is not allowed to open files.', 'cloverbrowser'),
            'download' => __('Your role is not allowed to download files.', 'cloverbrowser'),
            'edit'     => __('Your role is not allowed to edit files.', 'cloverbrowser'),
            'create'   => __('Your role is not allowed to create files or folders.', 'cloverbrowser'),
            'upload'   => __('Your role is not allowed to upload files.', 'cloverbrowser'),
            'rename'   => __('Your role is not allowed to rename or move items.', 'cloverbrowser'),
            'delete'   => __('Your role is not allowed to delete items.', 'cloverbrowser'),
            'chmod'    => __('Your role is not allowed to change permissions.', 'cloverbrowser'),
        ];
        return $m[$perm] ?? __('Your role is not allowed to do that.', 'cloverbrowser');
    }

    /**
     * Recursive operations by a restricted user must not touch anything that
     * is protected (hidden/read-only) for them — including items they cannot
     * even see. Walks the tree (bounded) without following symlinked folders.
     *
     * @return true|WP_Error
     */
    public static function check_tree(string $abs, ?array $eff = null) {
        $eff = $eff ?? self::effective();
        if ($eff === null || !is_dir($abs) || is_link($abs)) {
            return true;
        }
        $n = 0;
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($it as $path => $info) {
                if (++$n > 10000) {
                    break; // Cloverbrowser_Files enforces the hard cap with a proper message
                }
                if (self::rule_effect($eff, Cloverbrowser_Sandbox::to_relative((string) $path)) !== null) {
                    return new WP_Error('fbf_protected', __('This folder contains protected items, so your role cannot do that to it.', 'cloverbrowser'));
                }
            }
        } catch (UnexpectedValueException $e) {
            return new WP_Error('fbf_perm', sprintf(
                /* translators: %s: system error message */
                __('A subfolder could not be read: %s', 'cloverbrowser'),
                $e->getMessage()
            ));
        }
        return true;
    }

    /** Filter + annotate a directory listing for a restricted user. */
    public static function filter_listing(string $dir_abs, array $entries, ?array $eff = null): array {
        $eff = $eff ?? self::effective();
        if ($eff === null) {
            return $entries;
        }
        $nav = !self::in_scope($eff, $dir_abs);
        $out = [];
        foreach ($entries as $e) {
            $abs  = Cloverbrowser_Sandbox::root() . ($e['rel'] === '' ? '' : '/' . $e['rel']);
            $real = realpath($abs);
            if ($real === false) {
                continue; // broken links are useless to restricted users
            }
            $real = str_replace('\\', '/', $real);
            if ($nav) {
                // Navigation-only folder: show only the way towards allowed folders.
                if (!$e['is_dir'] || !(self::in_scope($eff, $real) || self::is_nav_ancestor($eff, $real))) {
                    continue;
                }
            } elseif (!self::in_scope($eff, $real)) {
                continue; // e.g. a symlink pointing out of the allowed folders
            }
            $effect = self::rule_effect($eff, $e['rel']);
            if ($effect === 'hide' || ($real !== $abs && self::rule_effect($eff, Cloverbrowser_Sandbox::to_relative($real)) === 'hide')) {
                continue;
            }
            $e['nav']       = !self::in_scope($eff, $real);
            $e['protected'] = $effect === 'readonly';
            $e['root']      = self::is_root($eff, $real);
            $blocked = $e['is_dir'] ? [] : self::blocked_types($eff, Cloverbrowser_Filetype::by_name($e['name']));
            $e['locked'] = $blocked !== [];
            if ($blocked) {
                $e['locked_reason'] = implode(', ', array_map([self::class, 'type_label'], $blocked));
            }
            $out[] = $e;
        }
        return $out;
    }

    /** What the browser UI needs to know about the current user. */
    public static function client_info(): array {
        $eff = self::effective();
        if ($eff === null) {
            return ['restricted' => false, 'perms' => array_fill_keys(self::PERMS, true), 'maxUpload' => 0, 'maxGrowth' => 0];
        }
        return [
            'restricted' => true,
            'perms'      => $eff['perms'],
            'maxUpload'  => $eff['max_upload'],
            'maxGrowth'  => $eff['max_growth'],
            'roots'      => $eff['roots'] === null ? null : array_map([Cloverbrowser_Sandbox::class, 'to_relative'], $eff['roots']),
        ];
    }

    /** Settings-page "test access" tool: evaluate every action for a role on a path. */
    public static function simulate(array $settings, string $role, string $rel_path): array {
        $eff = self::compute($settings, !empty($settings['roles'][$role]['enabled']) ? [$role] : []);
        $abs = Cloverbrowser_Sandbox::resolve($rel_path);
        if (is_wp_error($abs)) {
            return ['error' => $abs->get_error_message()];
        }
        $is_file = is_file($abs);
        $cats = $is_file ? Cloverbrowser_Filetype::classify_file($abs) : [];
        $results = [];
        foreach (['list', 'view', 'download', 'edit', 'create', 'upload', 'rename', 'delete', 'chmod'] as $action) {
            if ($is_file && in_array($action, ['list', 'create', 'upload'], true)) {
                continue;
            }
            if (!$is_file && in_array($action, ['view', 'download', 'edit'], true)) {
                continue;
            }
            $r = self::check($action, $abs, $eff);
            if ($r === true && $is_file && in_array($action, ['view', 'download', 'edit', 'rename'], true)) {
                $t = self::type_error($eff, $cats);
                if ($t) {
                    $r = $t;
                }
            }
            $results[] = ['action' => $action, 'allowed' => $r === true, 'reason' => $r === true ? '' : $r->get_error_message()];
        }
        return [
            'path'    => Cloverbrowser_Sandbox::to_relative($abs),
            'is_file' => $is_file,
            'types'   => array_map([self::class, 'type_label'], $cats),
            'access'  => $eff['access'],
            'results' => $results,
        ];
    }
}
