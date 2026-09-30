# Cloverbrowser

Browse, edit, upload and restore your site's files from the WordPress admin, with per-role access rules and a two-level trash.

<img width="1718" height="861" alt="cloverbrowser2" src="https://github.com/user-attachments/assets/f84af5b8-24d7-428e-8598-4649086147db" />
<img width="1703" height="1777" alt="cloverbrowser_settings3" src="https://github.com/user-attachments/assets/7495eed0-2205-4c37-adda-1e768c7f170a" />

---

## Description

Cloverbrowser is a file browser and code editor for the WordPress admin. It works only inside wp-admin: it adds nothing to your public site and makes no requests to outside services.

### Browse and edit

- Browse the folders of your WordPress installation, sort by name, size, permissions or date.
- Open text files in the WordPress code editor (syntax highlighting for PHP, CSS, JavaScript, HTML, JSON, XML, Markdown, SQL and more), with autosaved drafts and conflict detection when a file changed on disk.
- Upload by button or drag and drop, create files and folders, rename and move, change permissions (chmod) and download.
- Line endings: files with Windows (CRLF), old Mac (CR) or mixed line endings are detected, and you can convert them to the server's format. Uploads offer the same conversion, and the editor always saves in the server's format.

### Access rules for other roles

Administrators always have full access and manage the rules. Every other role has no access until an administrator enables it. For each role (and for "All roles" at once) you can set:

- what they can do: open, download, edit, create, upload, rename and move, delete, change permissions;
- which folders they can reach (a list of folders and everything inside them);
- blocked file types, recognised by their content and headers, not only by the name (PHP code, server configuration files, programs and scripts, web pages and JavaScript, archives, images, audio and video, documents, databases, any other binary file);
- protected files and folders, hidden or read-only, by name, name pattern, exact path or folder;
- the largest upload and the largest growth of a file per save.

A "Test access" tool shows what a role could do with any path before you save the rules. `wp-config.php` and the plugin's own folder are always protected from non-administrators.

### Two-level trash

- **Personal trash:** each user's deletions go to their own trash, where they can restore them, remove them or empty it. Users only ever see their own items.
- **Site trash:** a safety net only administrators can see. Every deletion is kept for the retention period (7 days by default), even after a user empties their own trash.

Retention periods and who may permanently delete items are set on the Settings screen.

### Security

- Every request is checked for the logged-in user's capability, a WordPress nonce, the same origin, a per-user rate limit and then the access rules for the exact path and action.
- All paths are confined to the site's root folder (symbolic links cannot be used to escape it).
- File content is never interpreted as HTML in the interface, downloads are sent so the browser cannot run them, and the plugin's screens send restrictive security headers.
- The interface ignores clicks and uploads triggered by scripts rather than by the person using the page, which makes it much harder for a malicious browser extension to act on your behalf.

### Languages

Included translations: Arabic, Bengali, Chinese (Simplified), French, Hindi, Portuguese (Brazil), Russian, Spanish and Urdu. The interface follows the user's profile language, or the site language when the user has not chosen one.

---

## Installation

1. Upload the `cloverbrowser` folder to `/wp-content/plugins/`, or install the plugin from the Plugins screen.
2. Activate it.
3. Open **Cloverbrowser → Browse files**. To give other roles access, or to change the trash settings, open **Cloverbrowser → Settings**.

---

## Configuration

Optional settings in `wp-config.php`:

| Constant | Purpose |
|---|---|
| `CLOVERBROWSER_ROOT` | Limits the browser to another folder (default: the WordPress root folder). |
| `CLOVERBROWSER_READ_ONLY` | Allows browsing and downloading only, for everyone. With `false`, files can be changed even when `DISALLOW_FILE_EDIT` is set. |
| `CLOVERBROWSER_TRASH_DIR` | Stores deleted items in a folder of your choice. |
| `CLOVERBROWSER_MAX_EDIT_BYTES` | Changes the largest file the editor opens. |
| `CLOVERBROWSER_DISABLE` | Switches the plugin off without deactivating it. |

```php
define( 'CLOVERBROWSER_ROOT', '/path/to/folder' );
define( 'CLOVERBROWSER_READ_ONLY', true );
define( 'CLOVERBROWSER_TRASH_DIR', '/path/outside/the/web/root' );
define( 'CLOVERBROWSER_MAX_EDIT_BYTES', 4 * 1024 * 1024 );
define( 'CLOVERBROWSER_DISABLE', true );
```

---

## Frequently Asked Questions

**Who can use Cloverbrowser?**

Administrators (on multisite: super admins). Other roles only after an administrator enables them under Settings → Access rules, and only within the rules set there.

**Does it respect `DISALLOW_FILE_EDIT`?**

Yes. When `DISALLOW_FILE_EDIT` or `DISALLOW_FILE_MODS` is set, Cloverbrowser is read-only for everyone unless you define `CLOVERBROWSER_READ_ONLY` as `false`.

**Where are deleted files kept?**

In a randomly named folder inside the uploads folder, protected by `.htaccess` and `web.config` rules, random file names and private file permissions. On nginx, which ignores those rule files, add a rule denying access to that folder, or define `CLOVERBROWSER_TRASH_DIR` as a folder outside the web root. The Settings screen shows the current location.

**What happens when I delete the plugin?**

Uninstalling removes the plugin's settings, autosaved drafts and the trash, including anything still in it. Your site's files are not touched.

**Does the plugin send any data anywhere?**

No. It makes no external requests, loads nothing from other sites and collects no usage data.

---

## License & Credits

- **License:** [GPLv2 or later](https://www.gnu.org/licenses/gpl-2.0.html)
- **Contributors:** [Liam Sherman Parris](https://github.com/LiamJSP)
- **Requires:** WordPress 6.2+ · PHP 8.0+ · Tested up to WordPress 7.1
- **Tags:** file manager, file editor, files, trash, admin

---

## Disclaimer

Cloverbrowser is a free, open-source utility intended for experienced
site administrators. It is provided **as-is**, without warranty of any
kind. The author and Red Clover Software make no representations about
suitability, security, or fitness for any purpose, and assume no
liability for data loss, site damage, unauthorised access, or any other
direct or indirect consequence of using or being unable to use this
plugin. No support, maintenance, or security-patch commitment is made.
By installing or using Cloverbrowser you accept these terms.
See `DISCLAIMER.md` for the full text.

