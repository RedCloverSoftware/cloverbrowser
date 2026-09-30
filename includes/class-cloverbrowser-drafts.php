<?php
/**
 * Autosave drafts, stored in the database (non-autoloaded options) — never
 * on disk next to the original. A draft of wp-config.php written as a
 * dotfile inside the web root could be served verbatim by the web server
 * (e.g. with directory listing on, or nginx not denying dotfiles), which
 * would break the plugin's "no public exposure" guarantee.
 *
 * Drafts are keyed by the file's sandbox-relative real path and shared
 * between administrators (like the file itself). A small index option lets
 * rename/delete of a folder carry along or clean up the drafts inside it.
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

final class Cloverbrowser_Drafts {

    public const PREFIX = 'cloverbrowser_draft_';
    public const INDEX  = 'cloverbrowser_draft_index';

    private static function key(string $rel): string {
        return self::PREFIX . md5($rel);
    }

    /** @return array<string,string> option key => rel */
    private static function index(): array {
        $i = get_option(self::INDEX, []);
        return is_array($i) ? $i : [];
    }

    private static function write_index(array $index): void {
        if ($index) {
            update_option(self::INDEX, $index, false);
        } else {
            delete_option(self::INDEX);
        }
    }

    private static function load(string $rel): ?array {
        $d = get_option(self::key($rel), false);
        if (!is_array($d) || !isset($d['content'], $d['rel']) || $d['rel'] !== $rel || !is_string($d['content'])) {
            return null;
        }
        return $d;
    }

    private static function store(string $rel, array $data): bool {
        $key = self::key($rel);
        $ok  = get_option($key, false) === false
            ? add_option($key, $data, '', false)
            : update_option($key, $data, false);
        if ($ok || self::load($rel) !== null) {
            $index       = self::index();
            $index[$key] = $rel;
            self::write_index($index);
            return true;
        }
        return false;
    }

    /** Public metadata (no content). $current_hash flags drafts made against an older version. */
    public static function meta(string $rel, ?string $current_hash = null): ?array {
        $d = self::load($rel);
        if ($d === null) {
            return null;
        }
        $user  = !empty($d['user']) ? get_userdata((int) $d['user']) : false;
        $saved = (int) ($d['saved'] ?? 0);
        return [
            'saved'    => $saved,
            'modified' => (string) wp_date('Y-m-d H:i', $saved),
            'size'     => strlen($d['content']),
            'author'   => $user ? $user->display_name : '',
            'stale'    => $current_hash !== null && !empty($d['base_hash']) && !hash_equals((string) $d['base_hash'], $current_hash),
        ];
    }

    public static function get(string $rel): array|WP_Error {
        $d = self::load($rel);
        if ($d === null) {
            return new WP_Error('fbf_no_draft', __('No draft exists for this file.', 'cloverbrowser'));
        }
        return ['content' => $d['content']] + (self::meta($rel) ?? []);
    }

    public static function put(string $rel, string $content, string $base_hash): array|WP_Error {
        if (strlen($content) > Cloverbrowser_Files::max_edit_bytes()) {
            return new WP_Error('fbf_too_big', __('Draft is larger than the editor limit; not saved.', 'cloverbrowser'));
        }
        $data = [
            'rel'       => $rel,
            'content'   => $content,
            'saved'     => time(),
            'base_hash' => $base_hash,
            'user'      => get_current_user_id(),
        ];
        if (!self::store($rel, $data)) {
            return new WP_Error('fbf_draft', __('Could not store the draft in the database.', 'cloverbrowser'));
        }
        return self::meta($rel) ?? [];
    }

    public static function discard(string $rel): bool {
        $key = self::key($rel);
        delete_option($key);
        $index = self::index();
        if (isset($index[$key])) {
            unset($index[$key]);
            self::write_index($index);
        }
        return true;
    }

    /** Is $rel equal to $base or inside the folder $base? */
    private static function under(string $rel, string $base): bool {
        return $rel === $base || str_starts_with($rel, $base . '/');
    }

    /** Carry drafts along when a file or folder is renamed/moved. */
    public static function move(string $from, string $to): void {
        foreach (self::index() as $rel) {
            if (!self::under($rel, $from)) {
                continue;
            }
            $d = self::load($rel);
            self::discard($rel);
            if ($d !== null) {
                $new      = $to . substr($rel, strlen($from));
                $d['rel'] = $new;
                self::store($new, $d);
            }
        }
    }

    /** Drop drafts of a deleted file, or of everything inside a deleted folder. */
    public static function forget(string $rel_or_dir): void {
        foreach (self::index() as $rel) {
            if (self::under($rel, $rel_or_dir)) {
                self::discard($rel);
            }
        }
    }

    /** Remove every draft (uninstall). */
    public static function purge_all(): void {
        foreach (array_keys(self::index()) as $key) {
            delete_option($key);
        }
        delete_option(self::INDEX);
    }
}
