<?php
/**
 * Remove everything Cloverbrowser stored: autosave drafts, access rules,
 * trash settings and the trash itself (items still in any trash are deleted).
 * The site's own files are never touched.
 *
 * @package Cloverbrowser
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/** Wrapped in a function so no variables leak into the global scope. */
function cloverbrowser_uninstall(): void {
    global $wpdb;

    $index = get_option('cloverbrowser_draft_index', []);
    if (is_array($index)) {
        foreach (array_keys($index) as $key) {
            delete_option((string) $key);
        }
    }
    delete_option('cloverbrowser_draft_index');
    delete_option('cloverbrowser_policy');

    // Trash store: only a folder carrying our marker file with the recorded token is removed.
    $store = get_option('cloverbrowser_trash_store');
    if (is_array($store) && is_string($store['dir'] ?? null) && is_string($store['token'] ?? null)) {
        require_once __DIR__ . '/includes/class-cloverbrowser-sandbox.php';
        require_once __DIR__ . '/includes/class-cloverbrowser-trash.php';
        Cloverbrowser_Trash::destroy_store($store['dir'], $store['token']);
    }
    delete_option('cloverbrowser_trash_store');
    delete_option('cloverbrowser_trash');
    delete_transient('cloverbrowser_trash_gc');
    wp_clear_scheduled_hook('cloverbrowser_trash_cleanup');

    // Drafts are stored one option per file; remove any the index missed.
    // A LIKE match on our own prefix has no WordPress API equivalent, and this
    // runs once, on uninstall, so caching does not apply.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
            $wpdb->esc_like('cloverbrowser_draft_') . '%'
        )
    );
    wp_cache_flush();
}

cloverbrowser_uninstall();
