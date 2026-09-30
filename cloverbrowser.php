<?php
/**
 * Plugin Name:       Cloverbrowser
 * Description:       Server file browser & editor for WordPress admins, sandboxed to this site's vhost root, with per-role access rules and a two-level trash. No public exposure.
 * Version:           1.5.0
 * Requires at least: 6.2
 * Requires PHP:      8.0
 * Author:            Red Clover Software Services Inc
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       cloverbrowser
 * Domain Path:       /languages
 *
 * Optional wp-config.php overrides:
 *   define('CLOVERBROWSER_ROOT', '/srv/www/this-vhost');       // hard sandbox root
 *   define('CLOVERBROWSER_MAX_EDIT_BYTES', 4 * 1024 * 1024);   // editor size cap
 *   define('CLOVERBROWSER_READ_ONLY', true);                   // browse/download only, for everyone
 *   define('CLOVERBROWSER_READ_ONLY', false);                  // allow writes even when DISALLOW_FILE_EDIT is set
 *   define('CLOVERBROWSER_DISABLE', true);                     // kill switch
 *   define('CLOVERBROWSER_TRASH_DIR', '/srv/private/trash'); // where deleted items are kept
 *
 * Access: administrators are unrestricted and manage "Cloverbrowser → Settings"
 * (access rules and trash). Other roles have no access until an administrator
 * enables them.
 *
 * Trash: deletions go to the user's personal trash and to the site trash
 * (administrators' safety net, 7 days by default) — see Cloverbrowser_Trash.
 *
 * Interface language: the user's own profile language, or — when the user
 * has not chosen one — the site language (Settings → General).
 */

defined('ABSPATH') || exit;

// Checked before any PHP 8-only syntax is loaded (includes are required below).
if (version_compare(PHP_VERSION, '8.0.0', '<')) {
    add_action('admin_notices', static function () {
        echo '<div class="notice notice-error"><p>' . esc_html__('Cloverbrowser requires PHP 8.0 or newer.', 'cloverbrowser') . '</p></div>';
    });
    return;
}

define('CLOVERBROWSER_VERSION', '1.5.0');
define('CLOVERBROWSER_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CLOVERBROWSER_PLUGIN_URL', plugin_dir_url(__FILE__));

require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-i18n.php';
require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-sandbox.php';
require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-filetype.php';
require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-policy.php';
require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-drafts.php';
require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-trash.php';
require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-files.php';
require_once CLOVERBROWSER_PLUGIN_DIR . 'includes/class-cloverbrowser-ajax.php';

final class Cloverbrowser_Plugin {

    public const BRAND = 'Cloverbrowser'; // product name — never translated
    private const PAGE_SLUG   = 'cloverbrowser';
    private const ACCESS_SLUG = 'cloverbrowser-settings';
    
    private static string $hook = '';
    private static string $access_hook = '';

    public static function boot(): void {
        if (defined('CLOVERBROWSER_DISABLE') && CLOVERBROWSER_DISABLE) {
            return;
        }
        // Needed on every request: the access capability, trash housekeeping (WP-Cron)
        // and user-deletion cleanup (which can also happen through the REST API).
        Cloverbrowser_Policy::register();
        Cloverbrowser_Trash::register();
        if (!is_admin()) {
            return; // no front-end functionality at all
        }
        // Admin screens and admin-ajax only.
        Cloverbrowser_I18n::register();
        Cloverbrowser_Ajax::register();
        add_action('admin_menu', [self::class, 'menu']);
        add_action('admin_enqueue_scripts', [self::class, 'assets']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [self::class, 'action_links']);
    }

    public static function menu(): void {
        self::$hook = (string) add_menu_page(
            self::BRAND,
            self::BRAND,
            Cloverbrowser_Policy::ACCESS_CAP,
            self::PAGE_SLUG,
            [self::class, 'render'],
            self::menu_icon(),
            81
        );
        add_submenu_page(self::PAGE_SLUG, self::BRAND, __('Browse files', 'cloverbrowser'), Cloverbrowser_Policy::ACCESS_CAP, self::PAGE_SLUG, [self::class, 'render']);
        self::$access_hook = (string) add_submenu_page(
            self::PAGE_SLUG,
            __('Settings', 'cloverbrowser') . ' ‹ ' . self::BRAND,
            __('Settings', 'cloverbrowser'),
            Cloverbrowser_Sandbox::cap(),
            self::ACCESS_SLUG,
            [self::class, 'render_access']
        );
        foreach ([self::$hook, self::$access_hook] as $h) {
            if ($h !== '') {
                add_action('load-' . $h, [self::class, 'security_headers']);
            }
        }
    }

    public static function action_links(array $links): array {
        if (current_user_can(Cloverbrowser_Sandbox::cap())) {
            array_unshift($links, '<a href="' . esc_url(admin_url('admin.php?page=' . self::ACCESS_SLUG)) . '">' . esc_html__('Settings', 'cloverbrowser') . '</a>');
        }
        return $links;
    }

    /**
     * Extra response headers for our own admin screens. WordPress core relies
     * on inline scripts, so script-src cannot be locked down here, but these
     * directives are free: no plugins/embeds, no <base> hijacking, forms may
     * only post to this site, and the page cannot be framed elsewhere.
     */
    public static function security_headers(): void {
        if (headers_sent()) {
            return;
        }
        header("Content-Security-Policy: object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'");
        header('Referrer-Policy: same-origin');
        header('X-Content-Type-Options: nosniff');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    }

    /** Admin menu icon: our own readable SVG file, as the base64 data URI WordPress expects for recolouring. */
    private static function menu_icon(): string {
        $svg = (string) file_get_contents(CLOVERBROWSER_PLUGIN_DIR . 'assets/img/menu-icon.svg'); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local plugin asset
        return $svg === '' ? 'dashicons-portfolio' : 'data:image/svg+xml;base64,' . base64_encode($svg);
    }

    /** JSON safe to embed inside a <script> element (no </script>, quotes or & can break out). */
    public static function script_json(array $data): string {
        return (string) wp_json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE);
    }

    /** The wordmark SVG from our own asset, sized by CSS and hidden from assistive tech (its wrapper is labelled). */
    private static function logo_markup(): string {
        $svg = (string) file_get_contents(CLOVERBROWSER_PLUGIN_DIR . 'assets/img/cloverbrowser-logo.svg'); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local plugin asset
        if (!preg_match('/viewBox="([0-9. ]+)"/', $svg, $vb) || !preg_match('#<svg[^>]*>(.*)</svg>#s', $svg, $inner)) {
            return '';
        }
        return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="' . esc_attr($vb[1]) . '" aria-hidden="true" focusable="false">' . $inner[1] . '</svg>';
    }

    private static function base_cfg(): array {
        return [
            'ajaxUrl'   => admin_url('admin-ajax.php'),
            'nonce'     => wp_create_nonce('cloverbrowser_ajax'),
            'rootLabel' => basename(Cloverbrowser_Sandbox::root()) ?: '/',
        ];
    }

    public static function assets(string $hook): void {
        if ($hook !== '' && $hook === self::$access_hook) {
            wp_enqueue_style('cloverbrowser-app', CLOVERBROWSER_PLUGIN_URL . 'assets/css/file-browser.css', [], CLOVERBROWSER_VERSION);
            wp_enqueue_style('cloverbrowser-settings', CLOVERBROWSER_PLUGIN_URL . 'assets/css/access-rules.css', ['cloverbrowser-app'], CLOVERBROWSER_VERSION);
            wp_enqueue_script('cloverbrowser-settings', CLOVERBROWSER_PLUGIN_URL . 'assets/js/access-rules.js', ['wp-i18n'], CLOVERBROWSER_VERSION, true);
            wp_add_inline_script('cloverbrowser-settings', 'window.CloverbrowserConfig = ' . self::script_json(self::base_cfg() + [
                'browserUrl' => admin_url('admin.php?page=' . self::PAGE_SLUG),
                'logo'       => self::logo_markup(),
            ]) . ';', 'before');
            wp_set_script_translations('cloverbrowser-settings', Cloverbrowser_I18n::DOMAIN, CLOVERBROWSER_PLUGIN_DIR . 'languages');
            return;
        }
        if (self::$hook === '' || $hook !== self::$hook) {
            return;
        }

        // WordPress core's bundled CodeMirror. Returns false when the user has
        // turned syntax highlighting off in their profile — respected below.
        $editor_settings = wp_enqueue_code_editor(['type' => 'text/plain']);
        if ($editor_settings !== false) {
            foreach (['application/x-httpd-php', 'text/css', 'text/html', 'application/json', 'text/javascript', 'application/xml'] as $type) {
                wp_enqueue_code_editor(['type' => $type]);
            }
        }

        wp_enqueue_style('cloverbrowser-app', CLOVERBROWSER_PLUGIN_URL . 'assets/css/file-browser.css', $editor_settings !== false ? ['code-editor'] : [], CLOVERBROWSER_VERSION);
        wp_enqueue_script(
            'cloverbrowser-app',
            CLOVERBROWSER_PLUGIN_URL . 'assets/js/file-browser.js',
            $editor_settings !== false ? ['code-editor', 'wp-i18n'] : ['wp-i18n'],
            CLOVERBROWSER_VERSION,
            true
        );

        $can_write = Cloverbrowser_Sandbox::can_write();
        $cfg = self::base_cfg() + [
            'maxEdit'        => Cloverbrowser_Files::max_edit_bytes(),
            'eolMax'         => Cloverbrowser_Files::EOL_MAX_BYTES,
            'serverEol'      => Cloverbrowser_Files::eol_name(Cloverbrowser_Files::server_eol()),
            'canWrite'       => $can_write,
            'readOnlyReason' => $can_write ? '' : Cloverbrowser_Sandbox::read_only_reason(),
            'codeEditor'     => is_array($editor_settings) ? $editor_settings : null,
            'isAdmin'        => Cloverbrowser_Policy::is_admin(),
            'accessUrl'      => Cloverbrowser_Policy::is_admin() ? admin_url('admin.php?page=' . self::ACCESS_SLUG) : '',
            'logo'           => self::logo_markup(),
        ] + Cloverbrowser_Policy::client_info() + Cloverbrowser_Trash::client_info();
        wp_add_inline_script('cloverbrowser-app', 'window.CloverbrowserConfig = ' . self::script_json($cfg) . ';', 'before');
        // JS strings: languages/cloverbrowser-{locale}-{md5}.json (see Cloverbrowser_I18n::script_file()).
        wp_set_script_translations('cloverbrowser-app', Cloverbrowser_I18n::DOMAIN, CLOVERBROWSER_PLUGIN_DIR . 'languages');
    }

    public static function render(): void {
        if (!current_user_can(Cloverbrowser_Policy::ACCESS_CAP)) {
            wp_die(esc_html__('You do not have permission to access the file browser.', 'cloverbrowser'), esc_html(self::BRAND), ['response' => 403]);
        }
        $root = Cloverbrowser_Sandbox::root();
        $admin = Cloverbrowser_Policy::is_admin();
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(self::BRAND); ?></h1>
            <p class="description">
                <?php
                if ($admin) {
                    echo wp_kses(
                        sprintf(
                            /* translators: %s: absolute server path of the sandbox root */
                            esc_html__('Full file access for this server, sandboxed to %s.', 'cloverbrowser'),
                            '<code>' . esc_html($root) . '</code>'
                        ),
                        ['code' => []]
                    );
                    echo ' ';
                    esc_html_e('Admin-only; every request is capability- and nonce-checked.', 'cloverbrowser');
                } else {
                    esc_html_e('Your access is limited by rules set by an administrator.', 'cloverbrowser');
                }
                ?>
            </p>
            <?php if (!Cloverbrowser_Sandbox::can_write()) : ?>
                <div class="notice notice-info inline"><p><strong><?php esc_html_e('Read-only mode.', 'cloverbrowser'); ?></strong> <?php echo esc_html(Cloverbrowser_Sandbox::read_only_reason()); ?></p></div>
            <?php endif; ?>
            <div id="cloverbrowser-root" class="cloverbrowser-root">
                <div class="fbx-boot"><span class="fbx-spinner" aria-hidden="true"></span> <?php esc_html_e('Loading file browser…', 'cloverbrowser'); ?></div>
                <noscript><p><?php esc_html_e('The file browser requires JavaScript.', 'cloverbrowser'); ?></p></noscript>
            </div>
        </div>
        <?php
    }

    public static function render_access(): void {
        if (!Cloverbrowser_Policy::is_admin()) {
            wp_die(esc_html__('Only administrators can manage access rules.', 'cloverbrowser'), esc_html(self::BRAND), ['response' => 403]);
        }
        ?>
        <div class="wrap">
            <h1 class="screen-reader-text"><?php echo esc_html(self::BRAND . ' — ' . __('Settings', 'cloverbrowser')); ?></h1>
            <div id="cloverbrowser-settings-root" class="cloverbrowser-root">
                <div class="fbx-boot"><span class="fbx-spinner" aria-hidden="true"></span> <?php esc_html_e('Loading settings…', 'cloverbrowser'); ?></div>
                <noscript><p><?php esc_html_e('The file browser requires JavaScript.', 'cloverbrowser'); ?></p></noscript>
            </div>
        </div>
        <?php
    }
}

register_activation_hook(__FILE__, static function (): void {
    if (class_exists('Cloverbrowser_Trash')) {
        Cloverbrowser_Trash::schedule();
    }
});
register_deactivation_hook(__FILE__, static function (): void {
    if (class_exists('Cloverbrowser_Trash')) {
        Cloverbrowser_Trash::unschedule();
    }
});

Cloverbrowser_Plugin::boot();
