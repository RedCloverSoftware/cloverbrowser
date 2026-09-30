<?php
/**
 * File-type classification by content (magic bytes / markers) AND name.
 *
 * Hardening notes — this code inspects attacker-supplied bytes and names:
 *  - Only bounded reads (HEAD_BYTES, SCAN_CHUNK) — never whole-file loads.
 *  - Only byte comparisons (substr / strncmp / stripos) on the data: no
 *    regular expressions over content, no eval/include/unserialize, no
 *    getimagesize()/exif (historically fragile parsers), no archive
 *    extraction (no zip bombs), no stream wrappers (paths are absolute
 *    sandbox paths resolved by Cloverbrowser_Sandbox).
 *  - Names are only lower-cased and split on "."; never used in a pattern.
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

final class Cloverbrowser_Filetype {

    public const HEAD_BYTES = 4096;
    private const SCAN_CHUNK = 1048576;      // 1 MiB streaming window for deep scans
    private const SCAN_OVERLAP = 16;         // so markers spanning two chunks are found
    public const DEEP_SCAN_MAX = 67108864;   // 64 MiB: larger files count as "unverifiable"

    /** Category keys, in display order. */
    public const CATEGORIES = ['php', 'server_config', 'executable', 'web_active', 'archive', 'image', 'media', 'document', 'database', 'binary'];

    private const EXT = [
        'php'           => ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar', 'inc', 'module'],
        'executable'    => ['exe', 'dll', 'so', 'dylib', 'bin', 'com', 'msi', 'sh', 'bash', 'zsh', 'ksh', 'csh', 'bat', 'cmd', 'ps1', 'vbs', 'py', 'pyc', 'pl', 'cgi', 'rb', 'jar', 'class', 'wasm', 'elf', 'run', 'appimage'],
        'web_active'    => ['html', 'htm', 'xhtml', 'shtml', 'svg', 'svgz', 'js', 'mjs', 'cjs', 'xml', 'xsl', 'xslt', 'swf'],
        'archive'       => ['zip', 'gz', 'tgz', 'bz2', 'xz', 'zst', '7z', 'rar', 'tar', 'lz', 'lzma', 'cab', 'iso', 'dmg'],
        'image'         => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'avif', 'heic', 'heif', 'tif', 'tiff', 'psd'],
        'media'         => ['mp3', 'mp4', 'm4a', 'm4v', 'mov', 'avi', 'mkv', 'webm', 'ogg', 'oga', 'ogv', 'wav', 'flac', 'aac', 'wmv', 'flv'],
        'document'      => ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf', 'epub'],
        'database'      => ['sql', 'sqlite', 'sqlite3', 'db', 'db3', 'mdb', 'accdb', 'dump', 'bak'],
    ];

    /** Server configuration files, matched on the whole (lower-cased) name. */
    private const CONFIG_NAMES = ['.htaccess', '.htpasswd', '.user.ini', 'php.ini', 'web.config', 'nginx.conf', '.env'];

    /** [category, offset, magic bytes] */
    private const MAGIC = [
        ['executable', 0, "\x7FELF"],
        ['executable', 0, "MZ"],
        ['executable', 0, "\xFE\xED\xFA\xCE"], ['executable', 0, "\xFE\xED\xFA\xCF"],
        ['executable', 0, "\xCE\xFA\xED\xFE"], ['executable', 0, "\xCF\xFA\xED\xFE"],
        ['executable', 0, "\xCA\xFE\xBA\xBE"],
        ['executable', 0, "\x00asm"],
        ['executable', 0, "#!"],
        ['archive', 0, "PK\x03\x04"], ['archive', 0, "PK\x05\x06"], ['archive', 0, "PK\x07\x08"],
        ['archive', 0, "\x1F\x8B"], ['archive', 0, "BZh"], ['archive', 0, "\xFD7zXZ\x00"],
        ['archive', 0, "7z\xBC\xAF\x27\x1C"], ['archive', 0, "Rar!\x1A\x07"], ['archive', 0, "\x28\xB5\x2F\xFD"],
        ['archive', 257, "ustar"], ['archive', 0, "MSCF"],
        ['image', 0, "\xFF\xD8\xFF"], ['image', 0, "\x89PNG\r\n\x1A\n"], ['image', 0, "GIF87a"], ['image', 0, "GIF89a"],
        ['image', 0, "BM"], ['image', 0, "\x00\x00\x01\x00"], ['image', 0, "II*\x00"], ['image', 0, "MM\x00*"], ['image', 0, "8BPS"],
        ['media', 0, "ID3"], ['media', 0, "OggS"], ['media', 0, "fLaC"], ['media', 0, "\x1A\x45\xDF\xA3"], ['media', 0, "FLV"],
        ['document', 0, "%PDF-"], ['document', 0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"], ['document', 0, "{\\rtf"],
        ['database', 0, "SQLite format 3\x00"],
        ['web_active', 0, "FWS"], ['web_active', 0, "CWS"], ['web_active', 0, "ZWS"],
    ];

    private const WEAK_MAGIC = ['MZ', 'BM', 'BZh', 'ID3', 'FLV', 'FWS', 'CWS', 'ZWS'];

    /** Lower-cased extension of a base name ("" when none; ".htaccess" has none). */
    public static function ext(string $name): string {
        $dot = strrpos($name, '.');
        return ($dot === false || $dot === 0) ? '' : strtolower(substr($name, $dot + 1));
    }

    /** Categories implied by the NAME alone (cheap; used for listings). */
    public static function by_name(string $name): array {
        $cats  = [];
        $lower = strtolower($name);
        $ext   = self::ext($name);
        if (in_array($lower, self::CONFIG_NAMES, true) || str_starts_with($lower, '.env.')) {
            $cats[] = 'server_config';
        }
        foreach (self::EXT as $cat => $list) {
            if ($ext !== '' && in_array($ext, $list, true)) {
                $cats[] = $cat;
            }
        }
        // Double extensions such as "shell.php.jpg" are executed as PHP by some
        // Apache setups (AddHandler) — treat any php-ish inner extension as PHP.
        $parts = explode('.', $lower);
        array_shift($parts);
        array_pop($parts);
        foreach ($parts as $inner) {
            if (in_array($inner, self::EXT['php'], true)) {
                $cats[] = 'php';
                break;
            }
        }
        return array_values(array_unique($cats));
    }

    /** Categories implied by the first bytes of the content. */
    public static function by_head(string $head): array {
        $head = substr($head, 0, self::HEAD_BYTES);
        $cats = [];
        $binary = self::looks_binary($head);
        foreach (self::MAGIC as [$cat, $off, $magic]) {
            if (strlen($head) >= $off + strlen($magic) && substr($head, $off, strlen($magic)) === $magic) {
                // Short printable signatures ("MZ", "BM", "ID3"…) also start ordinary
                // text; only trust them when the rest of the head is binary.
                if (in_array($magic, self::WEAK_MAGIC, true) && !$binary) {
                    continue;
                }
                $cats[] = $cat;
            }
        }
        // RIFF containers: WEBP image vs WAVE/AVI media.
        if (strncmp($head, 'RIFF', 4) === 0 && strlen($head) >= 12) {
            $kind = substr($head, 8, 4);
            $cats[] = $kind === 'WEBP' ? 'image' : 'media';
        }
        // ISO-BMFF: "ftyp" at offset 4 — HEIC/AVIF images vs MP4/MOV media.
        if (strlen($head) >= 12 && substr($head, 4, 4) === 'ftyp') {
            $brand = substr($head, 8, 4);
            $cats[] = in_array($brand, ['avif', 'avis', 'heic', 'heix', 'mif1', 'msf1'], true) ? 'image' : 'media';
        }
        if (self::has_php_marker($head)) {
            $cats[] = 'php';
        }
        // Script-capable markup near the start (BOM / whitespace tolerated).
        $lead = strtolower(ltrim(substr($head, 0, 1024), "\xEF\xBB\xBF \t\r\n"));
        if (str_starts_with($lead, '<!doctype html') || str_starts_with($lead, '<html') || str_starts_with($lead, '<svg')
            || (str_starts_with($lead, '<?xml') && str_contains($lead, '<svg'))
            || stripos($head, '<script') !== false) {
            $cats[] = 'web_active';
        }
        if ($binary) {
            $cats[] = 'binary';
        }
        return array_values(array_unique($cats));
    }

    /** Union of name- and content-based categories. */
    public static function classify(string $name, string $head): array {
        return array_values(array_unique(array_merge(self::by_name($name), self::by_head($head))));
    }

    /** Read the head of a regular file (bounded). */
    public static function head(string $abs): string {
        if (!is_file($abs) || !is_readable($abs)) {
            return '';
        }
        $fh = @fopen($abs, 'rb');
        if (!$fh) {
            return '';
        }
        $data = (string) fread($fh, self::HEAD_BYTES);
        fclose($fh);
        return $data;
    }

    public static function classify_file(string $abs, ?string $name = null): array {
        return self::classify($name ?? basename($abs), self::head($abs));
    }

    public static function has_php_marker(string $data): bool {
        if (stripos($data, '<?php') !== false || str_contains($data, '<?=')) {
            return true;
        }
        if (ini_get('short_open_tag')) {
            foreach (["<? ", "<?\n", "<?\r", "<?\t"] as $m) {
                if (str_contains($data, $m)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Stream the whole file looking for PHP opening tags (catches polyglots
     * such as a GIF/JPEG with embedded PHP). Returns null if the file is too
     * large to verify.
     */
    public static function file_has_php(string $abs): ?bool {
        $size = @filesize($abs);
        if ($size === false) {
            return null;
        }
        if ($size > self::DEEP_SCAN_MAX) {
            return null;
        }
        $fh = @fopen($abs, 'rb');
        if (!$fh) {
            return null;
        }
        $carry = '';
        while (!feof($fh)) {
            $chunk = (string) fread($fh, self::SCAN_CHUNK);
            if (self::has_php_marker($carry . $chunk)) {
                fclose($fh);
                return true;
            }
            $carry = substr($chunk, -self::SCAN_OVERLAP);
        }
        fclose($fh);
        return false;
    }

    public static function looks_binary(string $head): bool {
        if ($head === '') {
            return false;
        }
        if (str_contains($head, "\0")) {
            return true;
        }
        $len  = strlen($head);
        $ctrl = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($head[$i]);
            if ($o < 9 || ($o > 13 && $o < 32)) {
                $ctrl++;
            }
        }
        return ($ctrl / $len) >= 0.05;
    }
}
