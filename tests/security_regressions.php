<?php

declare(strict_types=1);

namespace KaraDAV;

use KD2\WebDAV\Exception as WebDAV_Exception;

$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . '/karadav-tests-' . bin2hex(random_bytes(6));
mkdir($tmp, 0700, true);

define(__NAMESPACE__ . '\\ROOT', $root);
define(__NAMESPACE__ . '\\DB_FILE', $tmp . '/db.sqlite');
define(__NAMESPACE__ . '\\DB_JOURNAL_MODE', 'TRUNCATE');
define(__NAMESPACE__ . '\\DATA_ROOT', $tmp);
define(__NAMESPACE__ . '\\STORAGE_PATH', $tmp . '/%s');
define(__NAMESPACE__ . '\\CACHE_PATH', $tmp . '/.cache');
define(__NAMESPACE__ . '\\WWW_URL', 'https://karadav.test/');
define(__NAMESPACE__ . '\\DEFAULT_QUOTA', 200);
define(__NAMESPACE__ . '\\LOG_FILE', null);
define(__NAMESPACE__ . '\\AUTH_CALLBACK', null);
define(__NAMESPACE__ . '\\LDAP_HOST', null);
define(__NAMESPACE__ . '\\LDAP_PORT', null);
define(__NAMESPACE__ . '\\LDAP_SECURE', null);
define(__NAMESPACE__ . '\\LDAP_LOGIN', null);
define(__NAMESPACE__ . '\\LDAP_BASE', null);
define(__NAMESPACE__ . '\\LDAP_DISPLAY_NAME', null);
define(__NAMESPACE__ . '\\LDAP_FIND_USER', null);
define(__NAMESPACE__ . '\\LDAP_FIND_IS_ADMIN', null);
define(__NAMESPACE__ . '\\ENABLE_XSENDFILE', false);
define(__NAMESPACE__ . '\\DEFAULT_TRASHBIN_DELAY', 0);
define(__NAMESPACE__ . '\\BLOCK_IOS_APPS', false);

spl_autoload_register(function (string $class) use ($root): void {
	$file = $root . '/lib/' . str_replace('\\', '/', $class) . '.php';

	if (is_file($file)) {
		require_once $file;
	}
});

function assert_true(bool $condition, string $message): void
{
	if (!$condition) {
		throw new \RuntimeException($message);
	}
}

function remove_tree(string $path): void
{
	if (!is_dir($path)) {
		return;
	}

	foreach (new \FilesystemIterator($path) as $item) {
		if ($item->isDir() && !$item->isLink()) {
			remove_tree($item->getPathname());
		}
		else {
			unlink($item->getPathname());
		}
	}

	rmdir($path);
}

try {
	// Simulate a version-4 database containing an orphan created while foreign
	// key enforcement was disabled.
	$seed = new \SQLite3(DB_FILE);
	$seed->exec(file_get_contents(ROOT . '/sql/schema.sql'));
	$seed->exec('DROP TABLE share_password_attempts;');
	$seed->exec("INSERT INTO users (id, login, password, quota, is_admin) VALUES (1, 'old', 'hash', 1000, 0);");
	$seed->exec("INSERT INTO shares (user, path, token, share_type, permissions, created) VALUES (1, 'private.jpg', '0123456789abcdef0123456789abcdef', 3, 1, 1);");
	$seed->exec('DELETE FROM users WHERE id = 1;');
	$seed->exec('PRAGMA user_version = 4;');
	$seed->close();

	$db = DB::getInstance();
	$db->upgradeVersion();
	assert_true((int) $db->querySingle('PRAGMA foreign_keys;') === 1, 'Foreign keys must be enabled');
	assert_true((int) $db->querySingle('PRAGMA user_version;') === DB::VERSION, 'Database must migrate to the current version');
	assert_true((int) $db->querySingle('SELECT COUNT(*) FROM shares;') === 0, 'Migration must remove orphaned shares');
	assert_true((int) $db->querySingle("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'share_password_attempts';") === 1, 'Migration must create the password-attempt table');

	$db->exec('PRAGMA user_version = 99;');

	try {
		$db->upgradeVersion();
		assert_true(false, 'A newer database version must be rejected');
	}
	catch (\RuntimeException $e) {
		assert_true(str_contains($e->getMessage(), 'newer than supported'), 'Newer database rejection should be explicit');
	}

	$db->exec('PRAGMA user_version = ' . DB::VERSION . ';');
	$db->exec("INSERT INTO users (id, login, password, quota, is_admin) VALUES (2, 'owner', 'hash', 1000, 0);");
	$db->exec("INSERT INTO shares (user, path, token, share_type, permissions, created) VALUES (2, 'file.jpg', 'abcdef0123456789abcdef0123456789', 3, 1, 1);");
	$db->exec('DELETE FROM users WHERE id = 2;');
	assert_true((int) $db->querySingle('SELECT COUNT(*) FROM shares;') === 0, 'Deleting a user must cascade to shares');

	$db->exec("INSERT INTO users (id, login, password, quota, is_admin) VALUES (3, 'alice', 'user-hash', 1000, 0);");
	$db->exec("INSERT INTO app_sessions (user, password, expiry, token) VALUES (3, 'app-hash', datetime('now', '-1 minute'), 'expired-token');");
	$users = new Users();
	assert_true($users->appSessionValidateToken('expired-token') === null, 'Expired login-flow tokens must not be exchangeable');

	$app_secret = 'app-secret';
	$app_hash = password_hash($app_secret . 'user-hash', PASSWORD_DEFAULT);
	$statement = $db->prepare("INSERT INTO app_sessions (user, password, expiry, token) VALUES (3, ?, datetime('now', '+1 hour'), 'active-token');");
	$statement->bindValue(1, $app_hash);
	$statement->execute();
	assert_true($users->appSessionLogin('mallory', 'active-token:' . $app_secret) === null, 'App passwords must be bound to their login');
	assert_true($users->appSessionLogin('alice', 'active-token:' . $app_secret)?->login === 'alice', 'Valid app passwords should still authenticate');
	$users->appSessionDelete('active-token:' . $app_secret);
	assert_true((int) $db->querySingle("SELECT COUNT(*) FROM app_sessions WHERE token = 'active-token';") === 0, 'Account removal must revoke its app password');

	class URIValidationServer extends \KD2\WebDAV\Server
	{
		public function __construct() {}
	}

	$server = new URIValidationServer();
	$blocked = false;

	try {
		$server->validateURI('photos/../../other-user');
	}
	catch (WebDAV_Exception $e) {
		$blocked = $e->getCode() === 403;
	}

	assert_true($blocked, 'DAV path validation must reject traversal');

	class PermissionTestNextCloud extends NextCloud
	{
		public function publicSharePermissions($value): int
		{
			return $this->normalizePublicSharePermissions($value);
		}

		public function setStorageForTest(Storage $storage): void
		{
			$this->storage = $storage;
		}
	}

	$nextcloud = new PermissionTestNextCloud($users);
	assert_true(
		$nextcloud->publicSharePermissions(Shares::PERMISSION_READ | Shares::PERMISSION_DELETE) === Shares::PERMISSION_READ,
		'Unsupported public-share write permissions must be removed'
	);

	$blocked = false;

	try {
		$nextcloud->publicSharePermissions(Shares::PERMISSION_CREATE);
	}
	catch (WebDAV_Exception $e) {
		$blocked = $e->getCode() === 400;
	}

	assert_true($blocked, 'Upload-only public shares must be rejected');

	$shares = new Shares();
	$alice = $users->get('alice');

	try {
		$shares->create($alice, 'file.txt', Shares::TYPE_PUBLIC_LINK, Shares::PERMISSION_READ, ['expire_date' => 'not-a-date']);
		assert_true(false, 'Invalid share expiration dates must be rejected');
	}
	catch (WebDAV_Exception $e) {
		assert_true($e->getCode() === 400, 'Invalid expiration should be a client error');
	}

	$protected_share = $shares->create($alice, 'file.txt', Shares::TYPE_PUBLIC_LINK, Shares::PERMISSION_READ, [
		'password' => 'secret',
		'expire_date' => date('Y-m-d', strtotime('+1 day')),
	]);
	$first_attempt = $shares->reservePasswordAttempt($protected_share, '127.0.0.1');
	assert_true($first_attempt === ['allowed' => true, 'retry_after' => 1], 'First password attempt should reserve a backoff window');
	$blocked_attempt = $shares->reservePasswordAttempt($protected_share, '127.0.0.1');
	assert_true(!$blocked_attempt['allowed'] && $blocked_attempt['retry_after'] > 0, 'Password retries must be throttled');
	$shares->clearPasswordFailures($protected_share, '127.0.0.1');
	assert_true($shares->reservePasswordAttempt($protected_share, '127.0.0.1')['allowed'], 'Successful authentication should clear backoff');
	$shares->clearPasswordFailures($protected_share, '127.0.0.1');

	$db->run('UPDATE shares SET expire_date = ? WHERE id = ?;', '2099-02-31 00:00:00', $protected_share->id);
	assert_true($shares->isExpired($shares->get($protected_share->id)), 'Normalized invalid persisted expirations must fail closed');
	$db->run('UPDATE shares SET expire_date = ? WHERE id = ?;', 'malformed', $protected_share->id);
	assert_true($shares->isExpired($shares->get($protected_share->id)), 'Malformed stored expirations must fail closed');

	$shares->create($alice, 'folder_a/child.txt', Shares::TYPE_PUBLIC_LINK);
	$unrelated = $shares->create($alice, 'folderXa/child.txt', Shares::TYPE_PUBLIC_LINK);
	$shares->deleteForPath($alice->id, 'folder_a', true);
	assert_true($shares->list($alice, 'folder_a/child.txt') === [], 'Deleting a path must revoke descendant shares');
	assert_true($shares->get($unrelated->id, $alice->id) !== null, 'LIKE escaping must not revoke similarly named paths');

	$storage = new Storage($users, $nextcloud);
	$nextcloud->setStorageForTest($storage);
	$user_path = $users->current()->path;
	file_put_contents($user_path . 'assembled.txt', 'original');

	try {
		$nextcloud->assembleChunks('alice', 'missing-upload', 'assembled.txt', null);
		assert_true(false, 'Missing chunks must fail');
	}
	catch (WebDAV_Exception $e) {
		assert_true($e->getCode() === 400, 'Missing chunks should be a client error');
	}

	assert_true(file_get_contents($user_path . 'assembled.txt') === 'original', 'A failed assembly must not truncate an existing file');
	$chunk_path = sprintf(STORAGE_PATH, '_chunks') . '/alice/ordered-upload';
	mkdir($chunk_path, 0770, true);
	file_put_contents($chunk_path . '/1', 'one-');
	file_put_contents($chunk_path . '/10', 'ten');
	file_put_contents($chunk_path . '/2', 'two-');
	$nextcloud->assembleChunks('alice', 'ordered-upload', 'assembled.txt', null);
	assert_true(file_get_contents($user_path . 'assembled.txt') === 'one-two-ten', 'Chunks must be assembled in natural order');

	$replacement_share = $shares->create($alice, 'assembled.txt', Shares::TYPE_PUBLIC_LINK);
	$replacement = fopen('php://temp', 'w+b');
	fwrite($replacement, 'replacement');
	rewind($replacement);
	$storage->put('assembled.txt', $replacement);
	assert_true($shares->get($replacement_share->id, $alice->id) === null, 'Overwriting a path must revoke its public shares');

	mkdir($user_path . 'source_a');
	file_put_contents($user_path . 'source_a/file.txt', 'copy');
	Storage::indexFiles($alice, 'source_a');
	$source_id = $storage->getFileId('source_a/file.txt');
	$storage->copy('source_a', 'copy_b');
	assert_true($storage->getFileId('source_a/file.txt') === $source_id, 'COPY must preserve source cache rows');
	assert_true($storage->getFileId('copy_b/file.txt') !== null, 'COPY must index destination cache rows');

	$pending_path = sprintf(STORAGE_PATH, '_chunks') . '/alice/other-upload';
	mkdir($pending_path, 0770, true);
	file_put_contents($pending_path . '/1', str_repeat('x', 2000));
	$pointer = fopen('php://temp', 'w+b');
	fwrite($pointer, 'new');
	rewind($pointer);

	try {
		$nextcloud->storeChunk('alice', 'new-upload', '1', $pointer);
		assert_true(false, 'All pending uploads must count toward quota');
	}
	catch (WebDAV_Exception $e) {
		assert_true($e->getCode() === 403, 'Aggregate pending chunk quota should reject the upload');
	}

	assert_true(is_file($pending_path . '/1'), 'Rejecting one upload must not delete other pending uploads');

	$delete_root = $tmp . '/delete-root';
	$outside = $tmp . '/outside';
	mkdir($delete_root);
	mkdir($outside);
	file_put_contents($outside . '/keep.txt', 'keep');
	symlink($outside, $delete_root . '/link');
	Storage::deleteDirectory($delete_root);
	assert_true(is_file($outside . '/keep.txt'), 'Recursive deletion must not follow directory symlinks');
	assert_true(!file_exists($delete_root), 'Requested directory should still be removed');

	$root_link = $tmp . '/root-link';
	symlink($outside, $root_link);
	Storage::deleteDirectory($root_link);
	assert_true(!is_link($root_link), 'A top-level directory symlink should be unlinked');
	assert_true(is_file($outside . '/keep.txt'), 'Deleting a top-level symlink must not delete its target');

	echo "security regressions: ok\n";
}
finally {
	remove_tree($tmp);
}
