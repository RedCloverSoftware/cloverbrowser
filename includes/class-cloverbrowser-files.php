<?php
/**
 * Filesystem operations. All methods receive absolute paths that have
 * already been resolved + sandbox-validated by Cloverbrowser_Sandbox.
 * Every potentially-heavy operation is hard-capped so it cannot stall
 * the server for other vhosts/users.
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

final class Cloverbrowser_Files {

    /** Legacy (≤1.0) on-disk draft suffix — no longer written; listed so leftovers can be removed. */
    public const LEGACY_DRAFT_SUFFIX = '.fbfdraft';

    private const MAX_LIST    = 10000; // entries returned per folder listing
    private const MAX_RECURSE = 10000; // cap for recursive chmod/delete

    private const BINARY_EXT = [
        'zip','rar','7z','gz','bz2','xz','tar','tgz','zst','jpg','jpeg','png','gif',
        'webp','bmp','ico','svgz','pdf','exe','dll','so','dylib','bin','iso','dmg',
        'mp3','mp4','avi','mov','mkv','flv','wmv','wasm','eot','ttf','otf','woff',
        'woff2','class','jar','pyc','o','a','mo','db','sqlite','sqlite3','psd','ai',
        'swf','doc','docx','xls','xlsx','ppt','pptx','odt','ods','odp','ds_store',
    ];

    public static function max_edit_bytes(): int {
        return (int) (defined('CLOVERBROWSER_MAX_EDIT_BYTES') ? CLOVERBROWSER_MAX_EDIT_BYTES : 2 * 1024 * 1024);
    }

    private static function fmt_time(int $ts): string {
        return $ts > 0 ? (string) wp_date('Y-m-d H:i', $ts) : '';
    }

    /* ------------------------------ Listing ------------------------------ */

    /** @return array{entries: array<int,array>, total: int, truncated: bool}|WP_Error */
    public static function list_dir(string $abs): array|WP_Error {
        if (!is_dir($abs)) {
            return new WP_Error('fbf_not_dir', __('Not a folder.', 'cloverbrowser'));
        }
        if (!is_readable($abs)) {
            return new WP_Error('fbf_perm', __('This folder is not readable by the PHP process.', 'cloverbrowser'));
        }
        $names = @scandir($abs);
        if ($names === false) {
            return new WP_Error('fbf_read', __('Could not read the folder.', 'cloverbrowser'));
        }
        $names = array_values(array_filter($names, static fn ($n) => $n !== '.' && $n !== '..'));
        // Never list the trash store (it may sit in wp-content).
        $base = rtrim(str_replace('\\', '/', $abs), '/');
        $names = array_values(array_filter($names, static fn ($n) => !Cloverbrowser_Sandbox::is_reserved($base . '/' . $n)));
        $total = count($names);

        // Huge folders (e.g. uploads caches): return a capped page instead of failing outright.
        $entries = [];
        foreach (array_slice($names, 0, self::MAX_LIST) as $name) {
            $entries[] = self::entry($abs . '/' . $name, (string) $name);
        }
        return ['entries' => $entries, 'total' => $total, 'truncated' => $total > self::MAX_LIST];
    }

    private static function entry(string $abs, string $name): array {
        $e = [
            'name'     => $name,
            'rel'      => Cloverbrowser_Sandbox::to_relative($abs),
            'is_dir'   => false,
            'is_link'  => false,
            'broken'   => false,
            'size'     => 0,
            'perms'    => '000',
            'mtime'    => 0,
            'modified' => '',
            'owner'    => '',
            'group'    => '',
            'writable' => false,
        ];
        $stat = @lstat($abs);
        if ($stat === false) {
            return $e;
        }
        $e['is_link'] = (($stat['mode'] & 0xF000) === 0xA000);
        $e['is_dir']  = (($stat['mode'] & 0xF000) === 0x4000);
        if ($e['is_link']) {
            $e['link_target'] = (string) @readlink($abs);
            $target = @stat($abs);
            if ($target === false) {
                $e['broken'] = true;
            } else {
                $e['is_dir'] = is_dir($abs); // symlinks to folders behave as folders
                $stat['size'] = $target['size'];
            }
        }
        $e['size']     = (int) $stat['size'];
        $e['mtime']    = (int) $stat['mtime'];
        $e['modified'] = self::fmt_time($e['mtime']);
        $e['perms']    = sprintf('%o', $stat['mode'] & 07777); // includes setuid/sticky when set
        $e['owner']    = self::uid_name((int) $stat['uid']);
        $e['group']    = self::gid_name((int) $stat['gid']);
        $e['writable'] = (bool) wp_is_writable($abs);
        return $e;
    }

    private static function uid_name(int $id): string {
        static $cache = [];
        if (!isset($cache[$id])) {
            $u = function_exists('posix_getpwuid') ? @posix_getpwuid($id) : false;
            $cache[$id] = (is_array($u) && isset($u['name'])) ? (string) $u['name'] : (string) $id;
        }
        return $cache[$id];
    }

    private static function gid_name(int $id): string {
        static $cache = [];
        if (!isset($cache[$id])) {
            $g = function_exists('posix_getgrgid') ? @posix_getgrgid($id) : false;
            $cache[$id] = (is_array($g) && isset($g['name'])) ? (string) $g['name'] : (string) $id;
        }
        return $cache[$id];
    }

    /* --------------------------- Text detection --------------------------- */

    public static function is_text(string $abs): bool {
        if (!is_file($abs) || !is_readable($abs)) {
            return false;
        }
        $ext = strtolower((string) pathinfo($abs, PATHINFO_EXTENSION));
        if (in_array($ext, self::BINARY_EXT, true)) {
            return false;
        }
        $fh = @fopen($abs, 'rb');
        if (!$fh) {
            return false;
        }
        $chunk = (string) fread($fh, 8192);
        fclose($fh);
        if (str_contains($chunk, "\0")) {
            return false;
        }
        $len  = strlen($chunk);
        $ctrl = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($chunk[$i]);
            if ($o < 9 || ($o > 13 && $o < 32)) {
                $ctrl++;
            }
        }
        return $len === 0 || ($ctrl / $len) < 0.05;
    }

    private static function is_utf8(string $s): bool {
        return function_exists('mb_check_encoding')
            ? mb_check_encoding($s, 'UTF-8')
            : (@preg_match('//u', $s) === 1);
    }

    /* ---------------------------- Line endings ---------------------------- */

    /** Largest text file whose line endings are inspected / converted. */
    public const EOL_MAX_BYTES = 33554432; // 32 MiB

    /** The server's native line ending ("\n" on Linux/macOS, "\r\n" on Windows). */
    public static function server_eol(): string {
        $eol = (string) apply_filters('cloverbrowser_server_eol', PHP_EOL);
        return in_array($eol, ["\n", "\r\n", "\r"], true) ? $eol : "\n";
    }

    public static function eol_name(string $eol): string {
        return $eol === "\r\n" ? 'crlf' : ($eol === "\r" ? 'cr' : 'lf');
    }

    /** 'none' | 'lf' | 'crlf' | 'cr' | 'mixed' */
    public static function eol_kind(string $s): string {
        $crlf = substr_count($s, "\r\n");
        $lf   = substr_count($s, "\n") - $crlf;
        $cr   = substr_count($s, "\r") - $crlf;
        $kinds = array_filter(['crlf' => $crlf, 'lf' => $lf, 'cr' => $cr]);
        if (!$kinds) {
            return 'none';
        }
        return count($kinds) > 1 ? 'mixed' : (string) array_key_first($kinds);
    }

    /** Convert every CRLF / CR / LF to $eol (default: the server's). */
    public static function normalize_eol(string $s, ?string $eol = null): string {
        $eol = $eol ?? self::server_eol();
        $s = str_replace("\r\n", "\n", $s);
        $s = str_replace("\r", "\n", $s);
        return $eol === "\n" ? $s : str_replace("\n", $eol, $s);
    }

    /** Line-ending kind of a (small enough) text file, or null for binary / oversized files. */
    public static function file_eol_kind(string $abs): ?string {
        $size = @filesize($abs);
        if ($size === false || $size > self::EOL_MAX_BYTES || Cloverbrowser_Filetype::looks_binary(Cloverbrowser_Filetype::head($abs))) {
            return null;
        }
        $data = @file_get_contents($abs);
        return $data === false ? null : self::eol_kind($data);
    }

    /* ------------------------------ Read/Save ----------------------------- */

    public static function read(string $abs): array|WP_Error {
        if (!is_file($abs)) {
            return new WP_Error('fbf_not_file', __('Not a file.', 'cloverbrowser'));
        }
        if (!is_readable($abs)) {
            return new WP_Error('fbf_perm', __('This file is not readable by the PHP process.', 'cloverbrowser'));
        }
        $size = (int) filesize($abs);
        if ($size > self::max_edit_bytes()) {
            return new WP_Error(
                'fbf_too_big',
                sprintf(
                    /* translators: 1: file size, 2: editor size limit */
                    __('File is %1$s — above the %2$s editor limit. Use Download instead.', 'cloverbrowser'),
                    size_format($size),
                    size_format(self::max_edit_bytes())
                )
            );
        }
        if (!self::is_text($abs)) {
            return new WP_Error('fbf_binary', __('This looks like a binary or non-text file. Editing is disabled — use Download instead.', 'cloverbrowser'));
        }
        $content = file_get_contents($abs);
        if ($content === false) {
            return new WP_Error('fbf_read', __('Could not read the file.', 'cloverbrowser'));
        }
        if (!self::is_utf8($content)) {
            return new WP_Error('fbf_encoding', __('File contains non-UTF-8 bytes; the editor only handles UTF-8 text. Use Download instead.', 'cloverbrowser'));
        }
        $stat = @stat($abs) ?: [];
        $hash = sha1($content);
        return [
            'content'  => $content,
            'size'     => strlen($content),
            'hash'     => $hash,
            'eol'      => self::eol_kind($content),
            'mtime'    => (int) ($stat['mtime'] ?? 0),
            'modified' => self::fmt_time((int) ($stat['mtime'] ?? 0)),
            'perms'    => sprintf('%o', ((int) ($stat['mode'] ?? 0100644)) & 07777),
            'writable' => wp_is_writable($abs),
            'draft'    => Cloverbrowser_Drafts::meta(Cloverbrowser_Sandbox::to_relative($abs), $hash),
        ];
    }

    /**
     * Overwrite a file in place (preserves owner, group, mode and inode).
     * $base_hash is the sha1 the editor loaded; if the file changed on disk
     * since then the save is refused unless $force is set.
     */
    public static function save(string $abs, string $content, bool $allow_empty, ?string $base_hash, bool $force): array|WP_Error {
        if (!is_file($abs)) {
            return new WP_Error('fbf_not_file', __('Target is not a file.', 'cloverbrowser'));
        }
        if (!wp_is_writable($abs)) {
            return new WP_Error('fbf_perm', __('This file is not writable by the PHP process (check its permissions).', 'cloverbrowser'));
        }
        if (strlen($content) > self::max_edit_bytes()) {
            return new WP_Error('fbf_too_big', __('Content exceeds the editor size limit.', 'cloverbrowser'));
        }
        if ($content === '' && ((int) filesize($abs)) > 0 && !$allow_empty) {
            return new WP_Error('fbf_empty', __('Refusing to overwrite a non-empty file with empty content. Confirm if this is intentional.', 'cloverbrowser'));
        }
        if ($base_hash !== null && $base_hash !== '' && !$force) {
            $current = @sha1_file($abs);
            if ($current !== false && !hash_equals($current, $base_hash)) {
                return new WP_Error('fbf_conflict', __('This file was changed on disk after you opened it.', 'cloverbrowser'));
            }
        }
        // Editor saves always use the server's native line endings.
        $content = self::normalize_eol($content);
        $w = self::write_in_place($abs, $content);
        if (is_wp_error($w)) {
            return $w;
        }
        Cloverbrowser_Drafts::discard(Cloverbrowser_Sandbox::to_relative($abs)); // the original is now current
        return self::saved_info($abs, $content);
    }

    private static function saved_info(string $abs, string $content): array {
        $stat = @stat($abs) ?: [];
        return [
            'size'     => strlen($content),
            'hash'     => sha1($content),
            'eol'      => self::eol_kind($content),
            'mtime'    => (int) ($stat['mtime'] ?? time()),
            'modified' => self::fmt_time((int) ($stat['mtime'] ?? time())),
        ];
    }

    /** Overwrite in place (keeps owner, group, mode, inode); verifies every byte was written. */
    private static function write_in_place(string $abs, string $content): true|WP_Error {
        $fh = @fopen($abs, 'r+b');
        if (!$fh) {
            return new WP_Error('fbf_write', __('Could not open the file for writing.', 'cloverbrowser'));
        }
        @flock($fh, LOCK_EX); // best effort; not all filesystems support it
        $len   = strlen($content);
        $bytes = 0;
        while ($bytes < $len) {
            $w = @fwrite($fh, substr($content, $bytes));
            if ($w === false || $w === 0) {
                break;
            }
            $bytes += $w;
        }
        $ok = ($bytes === $len) && @ftruncate($fh, $len);
        @fflush($fh);
        @flock($fh, LOCK_UN);
        @fclose($fh);
        clearstatcache(true, $abs);
        if (!$ok) {
            return new WP_Error('fbf_write', __('Write failed or was incomplete (disk full?). The file may be damaged — your content is still in the editor.', 'cloverbrowser'));
        }
        return true;
    }

    /** Convert a text file's line endings to the server's in place. */
    public static function convert_eol(string $abs): array|WP_Error {
        if (!is_file($abs)) {
            return new WP_Error('fbf_not_file', __('Not a file.', 'cloverbrowser'));
        }
        if (!wp_is_writable($abs)) {
            return new WP_Error('fbf_perm', __('This file is not writable by the PHP process (check its permissions).', 'cloverbrowser'));
        }
        if ((int) filesize($abs) > self::EOL_MAX_BYTES || Cloverbrowser_Filetype::looks_binary(Cloverbrowser_Filetype::head($abs))) {
            return new WP_Error('fbf_binary', __('Line endings can only be converted in text files up to 32 MB.', 'cloverbrowser'));
        }
        $data = file_get_contents($abs);
        if ($data === false) {
            return new WP_Error('fbf_read', __('Could not read the file.', 'cloverbrowser'));
        }
        $converted = self::normalize_eol($data);
        if ($converted !== $data) {
            $w = self::write_in_place($abs, $converted);
            if (is_wp_error($w)) {
                return $w;
            }
        }
        return self::saved_info($abs, $converted) + ['changed' => $converted !== $data];
    }

    /* ------------------------------ Mutations ----------------------------- */

    public static function mkdir(string $abs): array|WP_Error {
        if (file_exists($abs) || is_link($abs)) {
            return new WP_Error('fbf_exists', __('Something with that name already exists here.', 'cloverbrowser'));
        }
        if (!@mkdir($abs, 0755)) {
            return new WP_Error('fbf_mkdir', __('Could not create the folder (is the parent writable?).', 'cloverbrowser'));
        }
        return ['rel' => Cloverbrowser_Sandbox::to_relative($abs)];
    }

    public static function create_file(string $abs): array|WP_Error {
        if (file_exists($abs) || is_link($abs)) {
            return new WP_Error('fbf_exists', __('Something with that name already exists here.', 'cloverbrowser'));
        }
        // 'x' = O_CREAT|O_EXCL: never follows a (dangling) symlink planted at this name.
        $fh = @fopen($abs, 'xb');
        if (!$fh) {
            return new WP_Error('fbf_create', __('Could not create the file (is the folder writable?).', 'cloverbrowser'));
        }
        fclose($fh);
        return ['rel' => Cloverbrowser_Sandbox::to_relative($abs)];
    }

    /** $src is resolved without following a final symlink, so links are renamed, not their targets. */
    public static function rename(string $src, string $dst): array|WP_Error {
        if (!file_exists($src) && !is_link($src)) {
            return new WP_Error('fbf_not_found', __('Source not found.', 'cloverbrowser'));
        }
        if (file_exists($dst) || is_link($dst)) {
            return new WP_Error('fbf_exists', __('Destination already exists.', 'cloverbrowser'));
        }
        if (is_dir($src) && !is_link($src) && str_starts_with($dst . '/', rtrim($src, '/') . '/')) {
            return new WP_Error('fbf_rename', __('A folder cannot be moved inside itself.', 'cloverbrowser'));
        }
        $from = Cloverbrowser_Sandbox::to_relative($src);
        if (!@rename($src, $dst)) {
            return new WP_Error('fbf_rename', __('Rename failed (check permissions, or cross-device move).', 'cloverbrowser'));
        }
        $to = Cloverbrowser_Sandbox::to_relative($dst);
        Cloverbrowser_Drafts::move($from, $to); // keep autosave drafts attached
        return ['rel' => $to];
    }

    /**
     * Count everything below $abs (not following symlinked folders) BEFORE a
     * recursive operation, so an over-cap tree is refused without touching
     * anything instead of being half-processed.
     */
    private static function count_tree(string $abs): int|WP_Error {
        $n = 0;
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($it as $_) {
                if (++$n > self::MAX_RECURSE) {
                    return new WP_Error(
                        'fbf_too_many',
                        sprintf(
                            /* translators: %s: maximum number of items */
                            __('This folder contains more than %s items; recursive operations are refused for performance reasons. Nothing was changed.', 'cloverbrowser'),
                            number_format_i18n(self::MAX_RECURSE)
                        )
                    );
                }
            }
        } catch (UnexpectedValueException $e) {
            return new WP_Error('fbf_perm', sprintf(
                /* translators: %s: system error message */
                __('A subfolder could not be read: %s Nothing was changed.', 'cloverbrowser'),
                $e->getMessage()
            ));
        }
        return $n;
    }

    public static function chmod(string $abs, int $mode, bool $recursive): array|WP_Error {
        $recursive = $recursive && is_dir($abs) && !is_link($abs);
        if ($recursive) {
            $count = self::count_tree($abs);
            if (is_wp_error($count)) {
                return $count;
            }
        }
        $changed = 0;
        $failed  = 0;
        $skipped = 0;
        if (@chmod($abs, $mode)) {
            $changed++;
        } else {
            $failed++;
        }
        if ($recursive) {
            try {
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($it as $path => $info) {
                    // chmod() follows symlinks — a link inside the tree could
                    // point outside the sandbox, so links are never touched.
                    if ($info->isLink()) {
                        $skipped++;
                        continue;
                    }
                    if (@chmod((string) $path, $mode)) {
                        $changed++;
                    } else {
                        $failed++;
                    }
                }
            } catch (UnexpectedValueException $e) {
                return new WP_Error('fbf_perm', sprintf(
                    /* translators: %s: system error message */
                    __('A subfolder could not be read: %s', 'cloverbrowser'),
                    $e->getMessage()
                ));
            }
        }
        clearstatcache();
        return [
            'changed'  => $changed,
            'failed'   => $failed,
            'skipped'  => $skipped,
            'perms'    => sprintf('%o', ((int) @fileperms($abs)) & 07777),
            'writable' => (bool) wp_is_writable($abs),
        ];
    }

    /** $abs is resolved without following a final symlink: deleting a link removes only the link. */
    public static function delete(string $abs, bool $recursive): array|WP_Error {
        if (!file_exists($abs) && !is_link($abs)) {
            return new WP_Error('fbf_not_found', __('Path not found.', 'cloverbrowser'));
        }
        $rel = Cloverbrowser_Sandbox::to_relative($abs);
        if (is_link($abs) || is_file($abs)) {
            if (!Cloverbrowser_Sandbox::delete_file($abs)) {
                return new WP_Error('fbf_delete', __('Delete failed (check permissions).', 'cloverbrowser'));
            }
            Cloverbrowser_Drafts::forget($rel);
            return ['deleted' => 1, 'failed' => 0];
        }
        if (!is_dir($abs)) {
            return new WP_Error('fbf_not_dir', __('Not a folder.', 'cloverbrowser'));
        }
        if (!$recursive) {
            $items = array_diff(@scandir($abs) ?: [], ['.', '..']);
            if ($items) {
                return new WP_Error('fbf_not_empty', __('Folder is not empty. Tick “Also delete everything inside it” to delete its contents.', 'cloverbrowser'));
            }
            if (!@rmdir($abs)) {
                return new WP_Error('fbf_delete', __('Delete failed (check permissions).', 'cloverbrowser'));
            }
            Cloverbrowser_Drafts::forget($rel);
            return ['deleted' => 1, 'failed' => 0];
        }

        $count = self::count_tree($abs);
        if (is_wp_error($count)) {
            return $count;
        }
        $deleted = 0;
        $failed  = 0;
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($it as $path => $info) {
                $ok = ($info->isDir() && !$info->isLink()) ? @rmdir((string) $path) : Cloverbrowser_Sandbox::delete_file((string) $path);
                $ok ? $deleted++ : $failed++;
            }
        } catch (UnexpectedValueException $e) {
            return new WP_Error('fbf_perm', sprintf(
                /* translators: %s: system error message */
                __('A subfolder could not be read: %s', 'cloverbrowser'),
                $e->getMessage()
            ));
        }
        Cloverbrowser_Drafts::forget($rel);
        if (!@rmdir($abs)) {
            return new WP_Error(
                'fbf_delete',
                sprintf(
                    /* translators: 1: number of items removed, 2: number of items that could not be deleted */
                    _n(
                        'Removed %1$s item but %2$s could not be deleted, so the folder itself remains (check permissions).',
                        'Removed %1$s items but %2$s could not be deleted, so the folder itself remains (check permissions).',
                        $deleted,
                        'cloverbrowser'
                    ),
                    number_format_i18n($deleted),
                    number_format_i18n($failed)
                )
            );
        }
        return ['deleted' => $deleted + 1, 'failed' => $failed];
    }

    /* ------------------------------ Upload -------------------------------- */

    /** Validate an uploaded file's client-supplied name. Keeps it as-is (dotfiles included) when safe. */
    public static function upload_name(string $raw): string|WP_Error {
        $name = str_replace('\\', '/', $raw);
        $name = substr($name, (int) strrpos('/' . $name, '/'));   // basename, locale-independent
        $name = (string) preg_replace('/[\x00-\x1F\x7F]/', '', $name);
        if ($name === '' || $name === '.' || $name === '..' || strlen($name) > 255) {
            return new WP_Error('fbf_upload', __('Invalid file name.', 'cloverbrowser'));
        }
        if (PHP_OS_FAMILY === 'Windows' && preg_match('/[:*?"<>|]/', $name)) {
            return new WP_Error('fbf_upload', __('File name contains characters that are not allowed on this server.', 'cloverbrowser'));
        }
        return $name;
    }

    public static function upload(string $dest_dir, array $file, bool $overwrite, bool $convert_eol = false): array|WP_Error {
        $err = $file['error'] ?? UPLOAD_ERR_NO_FILE;
        if (!is_int($err) || $err !== UPLOAD_ERR_OK) {
            return new WP_Error('fbf_upload', self::upload_err(is_int($err) ? $err : -1));
        }
        $tmp = $file['tmp_name'] ?? '';
        if (!is_string($tmp) || $tmp === '' || !is_uploaded_file($tmp)) {
            return new WP_Error('fbf_upload', __('Invalid upload.', 'cloverbrowser'));
        }
        $name = self::upload_name(is_string($file['name'] ?? null) ? $file['name'] : '');
        if (is_wp_error($name)) {
            return $name;
        }
        $dst = $dest_dir . '/' . $name;
        if (is_link($dst)) {
            // move_uploaded_file() may copy through a symlink (cross-device tmp dir),
            // which could write outside the sandbox.
            return new WP_Error('fbf_upload', sprintf(
                /* translators: %s: file name */
                __('“%s” is a symbolic link here; delete it first if you want to replace it.', 'cloverbrowser'),
                $name
            ));
        }
        if (is_dir($dst)) {
            return new WP_Error('fbf_upload', sprintf(
                /* translators: %s: folder name */
                __('A folder named “%s” already exists here.', 'cloverbrowser'),
                $name
            ));
        }
        if (file_exists($dst) && !$overwrite) {
            return new WP_Error('fbf_exists', sprintf(
                /* translators: %s: file name */
                __('A file named “%s” already exists in this folder.', 'cloverbrowser'),
                $name
            ));
        }
        // Optional: convert a text upload's line endings to the server's before it lands.
        if ($convert_eol && (int) @filesize($tmp) <= self::EOL_MAX_BYTES && !Cloverbrowser_Filetype::looks_binary(Cloverbrowser_Filetype::head($tmp))) {
            $data = @file_get_contents($tmp);
            if (is_string($data)) {
                $converted = self::normalize_eol($data);
                if ($converted !== $data) {
                    @file_put_contents($tmp, $converted);
                    clearstatcache(true, $tmp);
                }
            }
        }
        $moved = self::place_upload($file, $dest_dir, $name);
        if (is_wp_error($moved)) {
            return $moved;
        }
        clearstatcache(true, $dst);
        Cloverbrowser_Drafts::forget(Cloverbrowser_Sandbox::to_relative($dst)); // replaced content: old drafts are meaningless
        return [
            'name' => $name,
            'rel'  => Cloverbrowser_Sandbox::to_relative($dst),
            'size' => (int) @filesize($dst),
            'eol'  => self::file_eol_kind($dst),
        ];
    }

    /**
     * Move the validated upload into $dest_dir under exactly $name, through
     * WordPress' own wp_handle_upload(): its target folder and file name are
     * pointed at the (already sandbox-checked) destination for this one call.
     * Type checks are Cloverbrowser's own (content inspection per role), so
     * WordPress' extension/MIME whitelist is not applied on top.
     */
    private static function place_upload(array $file, string $dest_dir, string $name): true|WP_Error {
        if (!function_exists('wp_handle_upload')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $file['name'] = $name;
        $target = static function (array $dirs) use ($dest_dir): array {
            $dirs['path']   = $dest_dir;
            $dirs['url']    = '';
            $dirs['subdir'] = '';
            $dirs['error']  = false;
            return $dirs;
        };
        add_filter('upload_dir', $target, PHP_INT_MAX);
        $result = wp_handle_upload($file, [
            'test_form' => false,          // our own nonce + capability checks already ran
            'test_size' => false,          // empty files are valid uploads here
            'test_type' => false,          // replaced by per-role content inspection
            'unique_filename_callback' => static fn (): string => $name, // keep the exact name (replacing is confirmed by the user)
        ]);
        remove_filter('upload_dir', $target, PHP_INT_MAX);
        if (!is_array($result) || !empty($result['error'])) {
            return new WP_Error('fbf_upload', is_array($result) && is_string($result['error'] ?? null)
                ? $result['error']
                : __('Could not move the upload into place (folder writable? name too long?).', 'cloverbrowser'));
        }
        if (!isset($result['file']) || wp_normalize_path((string) $result['file']) !== wp_normalize_path($dest_dir . '/' . $name)) {
            return new WP_Error('fbf_upload', __('Could not move the upload into place (folder writable? name too long?).', 'cloverbrowser'));
        }
        return true;
    }

    private static function upload_err(int $code): string {
        return match ($code) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => __('The upload exceeds the server’s size limit (upload_max_filesize / post_max_size).', 'cloverbrowser'),
            UPLOAD_ERR_PARTIAL  => __('The upload was only partially received — retry.', 'cloverbrowser'),
            UPLOAD_ERR_NO_FILE  => __('No file was received.', 'cloverbrowser'),
            UPLOAD_ERR_NO_TMP_DIR, UPLOAD_ERR_CANT_WRITE => __('The server’s temporary upload storage is misconfigured.', 'cloverbrowser'),
            UPLOAD_ERR_EXTENSION => __('A PHP extension blocked the upload.', 'cloverbrowser'),
            /* translators: %d: PHP upload error code */
            default => sprintf(__('Upload error (code %d).', 'cloverbrowser'), $code),
        };
    }

    /* ------------------------------ Download ------------------------------ */

    /**
     * Error page for the download iframe: a minimal HTML document with the
     * escaped message (the browser UI reads its text), sandboxed by CSP.
     */
    public static function plain_error(string $message, int $status): void {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        status_header($status);
        nocache_headers();
        header('Content-Type: text/html; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: sandbox allow-same-origin; default-src 'none'");
        echo '<!DOCTYPE html><meta charset="utf-8"><title>' . esc_html__('Download failed.', 'cloverbrowser') . '</title><body>' . esc_html($message) . '</body>';
        exit;
    }

    /** Stream a file to the admin as an attachment. POST-only: admin-ajax + capability + nonce. */
    public static function download(string $abs): void {
        if (!is_file($abs) || !is_readable($abs)) {
            self::plain_error(__('File not found or not readable by the PHP process.', 'cloverbrowser'), 404);
        }
        $fh = @fopen($abs, 'rb');
        if (!$fh) {
            self::plain_error(__('Could not open the file.', 'cloverbrowser'), 500);
        }
        $name = basename($abs);
        $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $name) ?: 'file';

        // Drop any output buffers (ours or other plugins') so large files are
        // streamed instead of being accumulated in memory.
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        if (function_exists('set_time_limit')) {
            // Large downloads must not be cut off by max_execution_time.
            @set_time_limit(0); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
        }
        nocache_headers();
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $safe . '"; filename*=UTF-8\'\'' . rawurlencode($name));
        header('Content-Length: ' . (string) filesize($abs));
        header('X-Content-Type-Options: nosniff');
        // Even if a browser were tricked into rendering it, the payload gets no script, no origin.
        header("Content-Security-Policy: sandbox; default-src 'none'");
        header('Cross-Origin-Resource-Policy: same-origin');

        // 256 KB chunks; stop as soon as the client disconnects so we never
        // burn server time streaming to nobody.
        while (!feof($fh)) {
            echo fread($fh, 256 * 1024); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw file bytes of an attachment download (Content-Type: application/octet-stream, nosniff, CSP sandbox), not HTML.
            flush();
            if (connection_aborted()) {
                break;
            }
        }
        fclose($fh);
        exit;
    }
}
