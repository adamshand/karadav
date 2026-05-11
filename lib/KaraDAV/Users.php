<?php

namespace KaraDAV;

use KD2\Graphics\Image;
use stdClass;

const AVATAR_MAX_SIZE = 2 * 1024 * 1024;
const AVATAR_SIZE = 256;
const AVATAR_MIME_TYPES = [
	'image/jpeg' => 'jpg',
	'image/png'  => 'png',
	'image/gif'  => 'gif',
	'image/webp' => 'webp',
];

class Users
{
	protected ?stdClass $current = null;

	public function __construct()
	{
		if (!session_id()) {
			// Protect the cookie : CSRF/JS stealing the cookie
			session_set_cookie_params([
				'samesite' => 'Strict',
				'httponly' => true,
				'secure'   => parse_url(WWW_URL, PHP_URL_SCHEME) === 'https',
			]);
		}
	}

	static public function generatePassword(): string
	{
		$password = base64_encode(random_bytes(16));
		$password = substr(str_replace(['/', '+', '='], '', $password), 0, 16);
		return $password;
	}

	public function list(): array
	{
		return array_map([$this, 'makeUserObjectGreatAgain'], iterator_to_array(DB::getInstance()->iterate('SELECT * FROM users ORDER BY login;')));
	}

	public function fetch(string $login): ?stdClass
	{
		return DB::getInstance()->first('SELECT * FROM users WHERE login = ?;', $login);
	}

	public function get(string $login): ?stdClass
	{
		$user = $this->fetch($login);

		if (!$user && LDAP::enabled() && LDAP::checkUser($login)) {
			$this->create($login, self::generatePassword(), DEFAULT_QUOTA);
			$user = $this->fetch($login);

			if (!$user) {
				throw new \LogicException('User does not exist after getting created?');
			}

			$user->is_admin = LDAP::checkIsAdmin($login);
		}
		elseif (!$user) {
			return null;
		}

		return $this->makeUserObjectGreatAgain($user);
	}

	public function getById(int $id): ?stdClass
	{
		$user = DB::getInstance()->first('SELECT * FROM users WHERE id = ?;', $id);
		return $this->makeUserObjectGreatAgain($user);
	}

	protected function makeUserObjectGreatAgain(?stdClass $user): ?stdClass
	{
		if ($user) {
			$user->path = sprintf(STORAGE_PATH, $user->login);
			$user->path = rtrim($user->path, '/') . '/';

			if (!file_exists($user->path)) {
				$parent = dirname($user->path);

				// Create parent directory with default permissions, if required
				if (!file_exists($parent)) {
					mkdir($parent, 0770, true);
				}

				mkdir($user->path, fileperms($parent), true);
			}

			$user->path = rtrim(realpath($user->path), '/') . '/';

			$user->dav_url = WWW_URL . 'files/' . $user->login . '/';
			$user->avatar_url = WWW_URL . 'avatars/' . $this->avatarToken($user);

			if ($avatar = $this->avatarPath($user)) {
				$user->avatar_url .= '?v=' . filemtime($avatar);
			}
		}

		return $user;
	}

	public function create(string $login, string $password, int $quota = DEFAULT_QUOTA, bool $is_admin = false)
	{
		$login = strtolower(trim($login));
		$hash = password_hash(trim($password), \PASSWORD_DEFAULT);
		DB::getInstance()->run('INSERT OR IGNORE INTO users (login, password, quota, is_admin) VALUES (?, ?, ?, ?);',
			$login, $hash, $quota * 1024 * 1024, $is_admin ? 1 : 0);
	}

	public function avatarToken(stdClass $user): string
	{
		return substr(md5($user->login), 0, 16);
	}

	protected function avatarBasePath(stdClass $user): string
	{
		return CACHE_PATH . '/avatars/' . $user->id;
	}

	public function avatarPath(stdClass $user): ?string
	{
		$files = glob($this->avatarBasePath($user) . '.*');
		return $files[0] ?? null;
	}

	public function avatarMimeType(string $path): string
	{
		$extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
		$mime = array_search($extension, AVATAR_MIME_TYPES, true);
		return is_string($mime) ? $mime : 'application/octet-stream';
	}

	public function getByAvatarToken(string $token): ?stdClass
	{
		$token = preg_replace('/\.(?:jpe?g|png|gif|webp)$/i', '', $token);

		if (preg_match('/^[a-f0-9]{16}$/', $token)) {
			foreach (DB::getInstance()->iterate('SELECT id, login FROM users;') as $user) {
				if ($token === $this->avatarToken($user)) {
					return $this->getById($user->id);
				}
			}
		}

		return $this->makeUserObjectGreatAgain($this->fetch($token));
	}

	public function saveAvatarFromUpload(stdClass $user, ?array $file): bool
	{
		$error = $file['error'] ?? UPLOAD_ERR_NO_FILE;

		if (!$file || $error === UPLOAD_ERR_NO_FILE) {
			return false;
		}

		if ($error !== UPLOAD_ERR_OK) {
			throw new UserException(_('Avatar upload failed.'));
		}

		if (($file['size'] ?? 0) > AVATAR_MAX_SIZE) {
			throw new UserException(_('Avatar file is too large.'));
		}

		$tmp = $file['tmp_name'] ?? null;

		if (!$tmp || !is_uploaded_file($tmp)) {
			throw new UserException(_('Invalid avatar upload.'));
		}

		$info = @getimagesize($tmp);
		$mime = $info['mime'] ?? null;

		if (!$mime || !isset(AVATAR_MIME_TYPES[$mime])) {
			throw new UserException(_('Avatar must be a JPEG, PNG, GIF or WebP image.'));
		}

		$dir = CACHE_PATH . '/avatars';

		if (!file_exists($dir)) {
			mkdir($dir, 0770, true);
		}

		$this->deleteAvatar($user);
		$target = $this->avatarBasePath($user) . '.' . AVATAR_MIME_TYPES[$mime];
		$format = $mime === 'image/jpeg' ? 'jpeg' : AVATAR_MIME_TYPES[$mime];

		try {
			$image = new Image($tmp, ['jpeg_quality' => 85, 'webp_quality' => 85]);
			$image->cropResize(AVATAR_SIZE, AVATAR_SIZE);

			if (!$image->save($target, $format)) {
				throw new \RuntimeException('Could not resize avatar');
			}
		}
		catch (\Throwable $e) {
			// If GD/Imagick is not available, still accept the avatar and rely on CSS
			// to display it at a sane size.
			if (!move_uploaded_file($tmp, $target)) {
				throw new UserException(_('Could not save avatar.'));
			}
		}

		return true;
	}

	public function deleteAvatar(stdClass $user): void
	{
		foreach (glob($this->avatarBasePath($user) . '.*') as $file) {
			@unlink($file);
		}
	}

	public function edit(int $id, array $data)
	{
		$old_user = $this->getById($id);

		if (!$old_user) {
			throw new \LogicException('User does not exist: ' . $id);
		}

		$params = [];
		$new_login = null;

		if (!empty($data['password'])) {
			$params['password'] = password_hash(trim($data['password']), \PASSWORD_DEFAULT);
		}

		if (!empty($data['login'])) {
			$new_login = strtolower(trim($data['login']));

			if ($new_login !== $old_user->login) {
				$exists = $this->get($new_login);
				$params['login'] = $new_login;

				if ($exists) {
					throw new \LogicException('User login already exists: ' . $params['login']);
				}
			}
			else {
				$new_login = null;
			}
		}

		if (isset($data['quota'])) {
			$params['quota'] = $data['quota'] <= 0 ? (int) $data['quota'] : (int) $data['quota'] * 1024 * 1024;
		}

		if (isset($data['is_admin'])) {
			$params['is_admin'] = (int) $data['is_admin'];
		}

		$update = array_map(fn($k) => $k . ' = ?', array_keys($params));
		$update = implode(', ', $update);
		$params = array_values($params);
		$params[] = $id;

		DB::getInstance()->run(sprintf('UPDATE users SET %s WHERE id = ?;', $update), ...$params);

		if ($new_login) {
			$path = sprintf(STORAGE_PATH, $new_login);
			$path = rtrim($path, '/') . '/';

			rename($old_user->path, $path);
		}
	}

	public function current(): ?stdClass
	{
		if ($this->current) {
			return $this->current;
		}

		$db = DB::getInstance();

		if (isset($_COOKIE[session_name()]) && !isset($_SESSION)) {
			session_start();
		}
		elseif (!empty($_COOKIE['permanent'])
			&& ($user = $db->first('SELECT * FROM users WHERE session_id = ?;', $_COOKIE['permanent']))) {
			@session_start();

			$_SESSION['user'] = $user;

			// Make sure this session_id cannot be reused
			$this->setPermanentSession($user->id);
		}

		$this->current = $this->makeUserObjectGreatAgain($_SESSION['user'] ?? null);

		return $this->current;
	}

	public function setCurrent(string $login): bool
	{
		$user = $this->get($login);

		if (!$user) {
			return false;
		}

		$this->current = $user;
		return true;
	}

	public function login(?string $login, ?string $password, bool $permanent = false): ?stdClass
	{
		$login = null !== $login ? strtolower(trim($login)) : null;

		// Check if user already has a session
		$current = $this->current();

		if ($current && (!$login || $current->login == $login)) {
			return $current;
		}

		if (!$login || !$password) {
			return null;
		}

		// If not, try to login
		$ok = false;

		if (LDAP::enabled()) {
			if (!LDAP::checkPassword($login, $password)) {
				return null;
			}

			$ok = true;
		}
		elseif (AUTH_CALLBACK) {
			$r = call_user_func(AUTH_CALLBACK, $login, $password);

			if ($r !== true) {
				return null;
			}

			$ok = true;
		}

		$user = $this->get($login);

		if (!$user && !$ok) {
			return null;
		}
		elseif (!$user && $ok) {
			$this->create($login, random_bytes(10));
			$user = $this->get($login);
		}

		if (!$ok && !password_verify(trim($password), $user->password)) {
			return null;
		}

		@session_start();
		$_SESSION['user'] = $user;

		if ($permanent) {
			$this->setPermanentSession($user->id);
		}

		return $user;
	}

	protected function setPermanentSession(int $id_user)
	{
		DB::getInstance()->run('UPDATE users SET session_id = ? WHERE id = ?;', session_id(), $id_user);

		setcookie('permanent', session_id(), [
			'expires'  => time() + 3600*24*365,
			'path'     => '/',
			'httponly' => true,
			'samesite' => 'Strict',
			'secure'   => parse_url(WWW_URL, PHP_URL_SCHEME) === 'https',
		]);
	}

	public function logout(): void
	{
		DB::getInstance()->run('UPDATE users SET session_id = NULL WHERE id = ?;', $this->current()->id);
		session_destroy();
	}

	public function appSessionCreate(?string $token = null): ?stdClass
	{
		$current = $this->current();

		if (!$current) {
			return null;
		}

		if (null !== $token) {
			if (!ctype_alnum($token) || strlen($token) > 100) {
				return null;
			}

			$expiry = '+10 minutes';
			$hash = null;
			$password = null;
		}
		else {
			$expiry = '+1 month';
			$password = $this->generatePassword();

			// The app password contains the user password hash
			// this way we can invalidate all sessions if we change
			// the user password
			$hash = password_hash($password . $current->password, \PASSWORD_DEFAULT);
			$token = $this->generatePassword();
		}

		DB::getInstance()->run(
			'INSERT OR IGNORE INTO app_sessions (user, password, expiry, token) VALUES (?, ?, datetime(\'now\', ?), ?);',
			$current->id, $hash, $expiry, $token);

		return (object) compact('password', 'token');
	}

	public function appSessionCreateAndGetRedirectURL(): string
	{
		$session = $this->appSessionCreate();
		$current = $this->current();

		return sprintf(NextCloud::AUTH_REDIRECT_URL, WWW_URL, $current->login, $session->token . ':' . $session->password);
	}

	public function appSessionValidateToken(string $token): ?stdClass
	{
		$session = DB::getInstance()->first('SELECT * FROM app_sessions WHERE token = ?;', $token);

		if (!$session) {
			return null;
		}

		// the token can only be exchanged against a session once,
		// so we set a password and remove the token
		$session->password = $this->generatePassword();

		// The app password contains the user password hash
		// this way we can invalidate all sessions if we change
		// the user password
		$user = $this->getById($session->user);
		$hash = password_hash($session->password . $user->password, \PASSWORD_DEFAULT);
		$session->token = self::generatePassword();
		$session->password = $session->token . ':' . $session->password;

		DB::getInstance()->run('UPDATE app_sessions
			SET token = ?, password = ?, expiry = datetime(\'now\', \'+1 month\')
			WHERE token = ?;',
			$session->token, $hash, $token);

		$session->user = $user;
		return $session;
	}

	public function appSessionLogin(?string $login, ?string $app_password): ?stdClass
	{
		// From time to time, clean up old sessions
		if (time() % 100 == 0) {
			DB::getInstance()->run('DELETE FROM app_sessions WHERE expiry < datetime();');
		}

		if (($user = $this->current()) && $login == $user->login) {
			return $user;
		}

		if (!$app_password) {
			$this->logAppSessionFailure('missing app password', $login, null);
			return null;
		}

		$token = strtok($app_password, ':');
		$password = strtok('');

		if (!is_string($token) || $token === '' || !is_string($password)) {
			$this->logAppSessionFailure('malformed app password', $login, is_string($token) ? $token : null);
			return null;
		}

		$user = DB::getInstance()->first('SELECT s.password AS app_hash, s.expiry AS app_expiry, u.*
			FROM app_sessions s INNER JOIN users u ON u.id = s.user
			WHERE s.token = ?;', $token);

		if (!$user) {
			$this->logAppSessionFailure('unknown token', $login, $token);
			return null;
		}

		if (strtotime((string)$user->app_expiry) <= time()) {
			$this->logAppSessionFailure('expired token', $login, $token);
			return null;
		}

		$password = trim($password) . $user->password;

		if (!password_verify($password, $user->app_hash)) {
			$this->logAppSessionFailure('password mismatch', $login, $token);
			return null;
		}

		// Treat app passwords as active sessions: as long as a client keeps using
		// them, keep them alive. This prevents quiet expiry of otherwise healthy
		// desktop/mobile clients after the initial login-flow lifetime.
		DB::getInstance()->run('UPDATE app_sessions SET expiry = datetime(\'now\', \'+1 month\') WHERE token = ?;', $token);

		@session_start();
		$_SESSION['user'] = $user;

		return $this->makeUserObjectGreatAgain($user);
	}

	protected function logAppSessionFailure(string $reason, ?string $login, ?string $token): void
	{
		if (!defined(__NAMESPACE__ . '\\LOG_FILE') || !LOG_FILE) {
			return;
		}

		$uri = $_SERVER['REQUEST_URI'] ?? '';
		$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$token_hint = $token ? substr($token, 0, 8) . '…' : 'none';

		http_log('AUTH: app session rejected: %s (login=%s token=%s uri=%s ua=%s)',
			$reason,
			$login ?? 'none',
			$token_hint,
			$uri,
			$ua
		);
	}

	public function quota(?stdClass $user = null, bool $with_trash = false): stdClass
	{
		$user ??= $this->current();
		$used = $total = $free = 0;
		$trash = null;

		if ($user) {
			if ($user->quota == -1) {
				$total = (int) @disk_total_space($user->path);
				$free = (int) @disk_free_space($user->path);
				$used = $total - $free;
			}
			elseif ($user->quota == 0) {
				$total = 0;
				$free = 0;
				$used = 0;
			}
			else {
				$used = Storage::getDirectorySize($user->path);
				$total = $user->quota;
				$free = max(0, $total - $used);
			}

			$trash = $with_trash ? Storage::getDirectorySize($user->path . '/.trash') : null;
		}

		return (object) compact('free', 'total', 'used', 'trash');
	}

	public function delete(?stdClass $user)
	{
		$this->deleteAvatar($user);
		Storage::deleteDirectory($user->path);
		DB::getInstance()->run('DELETE FROM users WHERE id = ?;', $user->id);
	}

	public function emptyTrash(?stdClass $user)
	{
		$path = rtrim($user->path, '/') . '/.trash';
		Storage::deleteDirectory($path);
	}

	public function indexAllFiles()
	{
		foreach ($this->list() as $user) {
			Storage::indexFiles($user, null);
		}
	}
}
