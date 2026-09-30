<?php
/**
 * Translations.
 *
 * Language selection follows WordPress itself: determine_locale() returns the
 * user's own "Language" profile setting when one is chosen, and otherwise the
 * site-wide language from Settings → General. Nothing needs configuring.
 *
 * Bundled catalogues (languages/) cover the ten most widely spoken languages
 * (English is the source language). Regional variants fall back to the
 * bundled catalogue of the same language, e.g. es_MX → es_ES, fr_CA → fr_FR,
 * pt_PT → pt_BR. Translations placed in wp-content/languages/plugins/ take
 * precedence over the bundled ones, as usual for WordPress plugins.
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

final class Cloverbrowser_I18n {

    public const DOMAIN = 'cloverbrowser';

    /** Bundled locales, in order of speaker count (Ethnologue). en_US is the source language. */
    public const LOCALES = ['zh_CN', 'hi_IN', 'es_ES', 'ar', 'fr_FR', 'bn_BD', 'pt_BR', 'ru_RU', 'ur'];

    public static function register(): void {
        add_action('init', [self::class, 'load']);
        add_filter('load_script_translation_file', [self::class, 'script_file'], 10, 3);
    }

    /** The bundled locale that should serve $locale, or null if none fits. */
    public static function resolve(string $locale): ?string {
        if (in_array($locale, self::LOCALES, true)) {
            return $locale;
        }
        $lang = strtolower(explode('_', $locale)[0]);
        if ($lang === 'zh') {
            // Traditional-script locales (zh_TW, zh_HK) must not fall back to Simplified Chinese.
            return $locale === 'zh_SG' ? 'zh_CN' : null;
        }
        if ($lang === 'ary') {
            $lang = 'ar'; // Moroccan Arabic → Modern Standard Arabic
        }
        foreach (self::LOCALES as $bundled) {
            if (strtolower(explode('_', $bundled)[0]) === $lang) {
                return $bundled;
            }
        }
        return null;
    }

    public static function load(): void {
        $locale = determine_locale(); // user language, else site language
        if ($locale === '' || str_starts_with($locale, 'en_')) {
            return;
        }
        // Site-installed translations first: the first catalogue loaded wins on conflicts.
        load_textdomain(self::DOMAIN, WP_LANG_DIR . '/plugins/' . self::DOMAIN . '-' . $locale . '.mo', $locale);

        $bundled = self::resolve($locale);
        if ($bundled !== null) {
            load_textdomain(self::DOMAIN, CLOVERBROWSER_PLUGIN_DIR . 'languages/' . self::DOMAIN . '-' . $bundled . '.mo', $locale);
        }
    }

    /**
     * JS translations: WordPress looks for
     * languages/cloverbrowser-{locale}-{md5 of script path}.json.
     * Apply the same regional fallback as for PHP.
     *
     * @param string|false $file
     * @return string|false
     */
    public static function script_file($file, string $handle, string $domain) {
        if ($domain !== self::DOMAIN || !is_string($file) || is_readable($file)) {
            return $file;
        }
        $locale  = determine_locale();
        $bundled = self::resolve($locale);
        if ($bundled === null || $bundled === $locale) {
            return $file;
        }
        $alt = str_replace('/' . self::DOMAIN . '-' . $locale . '-', '/' . self::DOMAIN . '-' . $bundled . '-', $file);
        return is_readable($alt) ? $alt : $file;
    }
}
