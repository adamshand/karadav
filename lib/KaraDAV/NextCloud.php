<?php

namespace KaraDAV;

use KD2\WebDAV\NextCloud as WebDAV_NextCloud;
use KD2\WebDAV\Exception as WebDAV_Exception;
use KD2\Graphics\SVG\Avatar;
use KD2\Graphics\Image;

class NextCloud extends WebDAV_NextCloud
{
	protected Users $users;
	protected ?\stdClass $user;
	protected string $temporary_chunks_path;

	public function __construct(Users $users)
	{
		$this->users = $users;
		$this->temporary_chunks_path =  sprintf(STORAGE_PATH, '_chunks');
		$this->setRootURL(WWW_URL);

		// KaraDAV users are allowed to try iOS clients if they wish
		// @see https://github.com/kd2org/karadav/issues/22
		$this->block_ios_clients = BLOCK_IOS_APPS;

		$this->theme = [
			'name'                 => 'KaraDAV',
			'url'                  => 'https://fossil.kd2.org/karadav/',
			'slogan'               => 'lighter than NextCloud',
			'color'                => '#6f918a',
			'color-text'           => '#ffffff',
			'color-element'        => '#6f918a',
			'color-element-bright' => '#6f918a',
			'color-element-dark'   => '#6f918a',
			'logo'                 => '',
			'background'           => '#d3dddb',
			'background-text'      => '#000000',
			'background-plain'     => false,
			'background-default'   => false,
			'logoheader'           => $this->root_url . '/logo.svg',
			'favicon'              => $this->root_url . '/logo.svg',
		];
	}

	public function auth(?string $login, ?string $password): bool
	{
		$user = $this->users->login($login, $password);

		if (!$user) {
			// Try app session
			$user = $this->users->appSessionLogin($login, $password);
		}

		if (!$user) {
			return false;
		}

		$this->user = $user;

		return true;
	}

	public function getUserName(): ?string
	{
		return $this->users->current()->login ?? null;
	}

	public function setUserName(string $login): bool
	{
		$ok = $this->users->setCurrent($login);

		if ($ok) {
			$this->user  = $this->users->current();
		}

		return $ok;
	}

	public function getUserQuota(): array
	{
		return (array) $this->users->quota($this->users->current());
	}

	public function generateToken(): string
	{
		return sha1(random_bytes(16));
	}

	public function validateToken(string $token): ?array
	{
		$session = $this->users->appSessionValidateToken($token);

		if (!$session) {
			return null;
		}

		return ['login' => $session->user->login, 'password' => $session->password];
	}

	public function getLoginURL(?string $token): string
	{
		if ($token) {
			return sprintf('%slogin.php?nc=%s', WWW_URL, $token);
		}
		else {
			return sprintf('%slogin.php?nc=redirect', WWW_URL);
		}
	}

	public function getDirectDownloadSecret(string $uri, string $login): string
	{
		$user = $this->users->get($login);

		if (!$user) {
			throw new WebDAV_Exception('No user with that name', 401);
		}

		return WebDAV::hmac([$uri, $user->login, $user->password]);
	}

	public function nc_capabilities(): array
	{
		$out = parent::nc_capabilities();
		$capabilities =& $out['ocs']['data']['capabilities'];

		$capabilities['files_sharing'] = [
			'api_enabled' => true,
			'default_permissions' => Shares::PERMISSION_READ,
			'group_sharing' => false,
			'resharing' => false,
			'sharebymail' => [
				'enabled' => false,
				'password' => ['enabled' => false, 'enforced' => false],
			],
			'public' => [
				'enabled' => true,
				'upload' => false,
				'multiple' => true,
				'supports_upload_only' => false,
				'password' => [
					'enforced' => false,
					'askForOptionalPassword' => false,
				],
				'expire_date' => [
					'enabled' => true,
					'enforced' => false,
					'days' => 0,
				],
			],
		];

		return $out;
	}

	public function nc_shares(string $uri = ''): array
	{
		$this->requireAuth();

		if (!preg_match('!ocs/v[12]\.php/apps/files_sharing/api/v1/shares(?:/(\d+))?$!', $uri, $match)) {
			return $this->ocsError('Invalid share endpoint', 404);
		}

		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
		$user = $this->users->current();
		$shares = new Shares;
		$id = isset($match[1]) ? (int)$match[1] : null;

		if ($method === 'GET') {
			if ($id) {
				$share = $shares->get($id, $user->id);
				return $share ? $this->ocsShare($share) : $this->ocsError('Share not found', 404);
			}

			$path = isset($_GET['path']) ? $this->normalizeSharePath($_GET['path']) : null;

			if ($path !== null && !$this->storage->exists($path)) {
				return $this->ocsError('File does not exist', 404);
			}

			return $this->ocsShares($shares->list($user, $path));
		}

		if ($method === 'POST' && !$id) {
			$path = $this->normalizeSharePath($_POST['path'] ?? '');
			$share_type = (int)($_POST['shareType'] ?? -1);

			if ($path === '') {
				return $this->ocsError('Sharing the root directory is not supported', 400);
			}

			if (!$this->storage->exists($path)) {
				return $this->ocsError('File does not exist', 404);
			}

			if ($share_type !== Shares::TYPE_PUBLIC_LINK) {
				return $this->ocsError('KaraDAV currently supports public link shares only', 400);
			}

			$share = $shares->create($user, $path, Shares::TYPE_PUBLIC_LINK, (int)($_POST['permissions'] ?? Shares::PERMISSION_READ), [
				'password' => $_POST['password'] ?? '',
				'expire_date' => $_POST['expireDate'] ?? '',
				'note' => $_POST['note'] ?? '',
				'label' => $_POST['label'] ?? '',
				'hide_download' => $this->requestBool($_POST['hideDownload'] ?? false),
			]);

			return $this->ocsShare($share);
		}

		if ($id && $method === 'PUT') {
			$share = $shares->get($id, $user->id);

			if (!$share) {
				return $this->ocsError('Share not found', 404);
			}

			parse_str(file_get_contents('php://input'), $params);
			$options = [];

			foreach (['permissions', 'password', 'note', 'label'] as $key) {
				if (array_key_exists($key, $params)) {
					$options[$key] = $params[$key];
				}
			}

			if (array_key_exists('expireDate', $params)) {
				$options['expire_date'] = $params['expireDate'];
			}

			if (array_key_exists('hideDownload', $params)) {
				$options['hide_download'] = $this->requestBool($params['hideDownload']);
			}

			$share = $shares->update($share, $options);

			return $this->ocsShare($share);
		}

		if ($id && $method === 'DELETE') {
			$share = $shares->get($id, $user->id);

			if (!$share) {
				return $this->ocsError('Share not found', 404);
			}

			$shares->delete($share);
			return $this->nc_ocs([], 200);
		}

		return $this->ocsError('Invalid request method', 405);
	}

	protected function ocsShares(array $shares): array
	{
		return $this->nc_ocs(array_map(fn($share) => $this->shareToOcs($share), $shares), 200);
	}

	protected function ocsShare(\stdClass $share): array
	{
		return $this->nc_ocs($this->shareToOcs($share), 200);
	}

	protected function ocsError(string $message, int $statuscode): array
	{
		return $this->nc_ocs([], $statuscode, 'failure', $message);
	}

	protected function shareToOcs(\stdClass $share): array
	{
		$owner = $this->users->getById((int)$share->user);
		$path = (string)$share->path;
		$props = $this->storage->propfind($path, ['DAV::resourcetype', 'DAV::getcontenttype', 'DAV::getcontentlength', self::PROP_OC_FILEID], 0) ?: [];
		$is_dir = ($props['DAV::resourcetype'] ?? null) === 'collection';
		$file_id = $props[self::PROP_OC_FILEID] ?? $this->storage->getFileId($path);
		$name = basename($path);
		$url = $share->share_type == Shares::TYPE_PUBLIC_LINK ? (new Shares)->publicUrl($share) : '';

		return [
			'id' => (int)$share->id,
			'share_type' => (int)$share->share_type,
			'uid_owner' => $owner->login ?? '',
			'displayname_owner' => $owner->login ?? '',
			'permissions' => (int)$share->permissions,
			'stime' => (int)$share->created,
			'parent' => '',
			'expiration' => $share->expire_date ?? '',
			'token' => $share->token,
			'uid_file_owner' => $owner->login ?? '',
			'note' => $share->note ?? '',
			'label' => $share->label ?? '',
			'displayname_file_owner' => $owner->login ?? '',
			'path' => '/' . $path,
			'item_type' => $is_dir ? 'folder' : 'file',
			'item_source' => $file_id,
			'file_source' => $file_id,
			'file_parent' => '',
			'file_target' => '/' . $name,
			'name' => $name,
			'url' => $url,
			'mimetype' => $is_dir ? 'httpd/unix-directory' : ($props['DAV::getcontenttype'] ?? 'application/octet-stream'),
			'storage_id' => 'home::' . ($owner->login ?? ''),
			'storage' => 0,
			'item_size' => $props['DAV::getcontentlength'] ?? 0,
			'share_with' => '',
			'share_with_displayname' => '',
			'password' => empty($share->password_hash) ? '' : '********',
			'send_password_by_talk' => false,
			'hide_download' => !empty($share->hide_download),
			'can_edit' => true,
			'can_delete' => true,
		];
	}

	protected function normalizeSharePath(string $path): string
	{
		$path = trim(rawurldecode($path));
		$path = trim($path, '/');

		if (str_contains($path, '..')) {
			throw new WebDAV_Exception('Invalid share path', 400);
		}

		return $path;
	}

	protected function requestBool($value): bool
	{
		return in_array($value, [true, 1, '1', 'true', 'yes', 'on'], true);
	}

	protected function cleanChunks(): void
	{
		$expire = time() - 36*3600;

		foreach (glob($this->temporary_chunks_path . '/*/*') as $dir) {
			$first_file = current(glob($dir . '/*'));

			if (filemtime($first_file) < $expire) {
				Storage::deleteDirectory($dir);
			}
		}
	}

	public function storeChunk(string $login, string $name, string $part, $pointer): void
	{
		$this->cleanChunks();

		$path = $this->temporary_chunks_path . '/' . $login . '/' . $name;
		@mkdir($path, 0777, true);

		$file_path = $path . '/' . $part;
		$out = fopen($file_path, 'wb');
		$quota = $this->getUserQuota();
		$used = $quota['used'] + Storage::getDirectorySize($path);

		while (!feof($pointer)) {
			$data = fread($pointer, 8192);
			$used += strlen($used);

			if ($used > $quota['free']) {
				$this->deleteChunks($login, $name);
				throw new WebDAV_Exception('Your quota does not allow for the upload of this file', 403);
			}

			fwrite($out, $data);
		}

		fclose($out);
		fclose($pointer);
	}

	public function listChunks(string $login, string $name): array
	{
		$path = $this->temporary_chunks_path . '/' . $name;
		$list = glob($path . '/*');
		$list = array_map(fn($a) => str_replace($path . '/', '', $a), $list);
		return $list;
	}

	public function deleteChunks(string $login, string $name): void
	{
		$path = $this->temporary_chunks_path . '/' . $login . '/' . $name;
		Storage::deleteDirectory($path);
	}

	public function assembleChunks(string $login, string $name, string $target, ?int $mtime): array
	{
		$target = $this->users->current()->path . $target;
		$parent = dirname($target);

		if (!is_dir($parent)) {
			throw new WebDAV_Exception('Target parent directory does not exist', 409);
		}

		$path = $this->temporary_chunks_path . '/' . $login . '/' . $name;
		$exists = file_exists($target);

		if ($exists && is_dir($target)) {
			throw new WebDAV_Exception('Target exists and is a directory', 409);
		}

		$out = fopen($target, 'wb');

		foreach (glob($path . '/*') as $file) {
			$in = fopen($file, 'rb');

			while (!feof($in)) {
				fwrite($out, fread($in, 8192));
			}

			fclose($in);
		}

		fclose($out);
		$this->deleteChunks($login, $name);

		if ($mtime) {
			touch($target, $mtime);
		}

		return ['created' => !$exists, 'etag' => md5(filemtime($target) . filesize($target))];
	}

	protected function nc_avatar(?string $uri = null): void
	{
		$token = null;
		$parts = explode('/', trim($uri ?? '', '/'));

		foreach (['avatars', 'avatar'] as $segment) {
			$index = array_search($segment, $parts, true);

			if ($index !== false && isset($parts[$index + 1])) {
				$token = $parts[$index + 1];
				break;
			}
		}

		if ($token && ($user = $this->users->getByAvatarToken($token)) && ($path = $this->users->avatarPath($user))) {
			header('Content-Type: ' . $this->users->avatarMimeType($path));
			header('Cache-Control: public, max-age=86400');
			readfile($path);
			return;
		}

		header('Content-Type: image/svg+xml; charset=utf-8');
		echo Avatar::beam($_SERVER['REQUEST_URI'] ?? '', ['colors' => ['#009', '#ccf', '#9cf']]);
	}

	/**
	 * File preview, new version, requires a file ID
	 */
	protected function nc_preview_v2(): void
	{
		$id = $_GET['fileId'] ?? null;
		$w = $_GET['x'] ?? null;
		$h = $_GET['y'] ?? null;

		if (!$id) {
			http_response_code(404);
			return;
		}

		$this->requireAuth();
		$uri = $this->storage->getFilePathFromId((int)$id);

		if (!$uri) {
			http_response_code(404);
			return;
		}

		$this->serveThumbnail($uri, $w, $h, false, true);
	}

	public function serveThumbnail(string $uri, int $width, int $height, bool $crop = false, bool $preview = false): void
	{
		if (!preg_match('/\.(?:jpe?g|gif|png|webp)$/i', $uri)) {
			http_response_code(404);
			return;
		}

		$this->requireAuth();
		$uri = preg_replace(self::WEBDAV_BASE_REGEXP, '', $uri);

		if (!$this->storage->exists($uri)) {
			throw new WebDAV_Exception('Not found', 404);
		}

		// If this PHP build lacks GD/Imagick, still return the original image
		// instead of 404. Nextcloud iOS prefers a real image response and will
		// cache it as a preview; this is less efficient but keeps the UI usable.
		if (!ENABLE_THUMBNAILS_OK) {
			$file = $this->storage->get($uri);
			$path = $file['path'] ?? null;

			if (!$path || !is_file($path)) {
				throw new WebDAV_Exception('Not found', 404);
			}

			header('Content-Type: ' . (@mime_content_type($path) ?: 'application/octet-stream'));
			header('Content-Length: ' . filesize($path));
			readfile($path);
			return;
		}

		if ($crop || $width < 300 || $height < 300) {
			$size = 150;
		}
		elseif ($width <= 600 || $height <= 600) {
			$size = 500;
		}
		else {
			$size = 1200;
		}

		$id = $this->storage->getFileId($uri);

		if (!$id) {
			throw new WebDAV_Exception('Not found', 404);
		}

		$cache_path = $this->storage->getThumbnailCachePath($id, $size);

		if (!file_exists($cache_path)) {
			$this->server->log('NC Creating thumbnail (%d): %s', $size, basename($cache_path));
			try {
				$i = new Image;
				$i->openFromBlob($this->storage->fetch($uri));

				if ($size === 150) {
					$i->cropResize($size);
				}
				else {
					$i->resize($size);
				}

				$perms = @fileperms(dirname(dirname(dirname($cache_path)))) ?: 0777;
				@mkdir(dirname($cache_path), $perms, true);
				$i->save($cache_path, 'webp');
				unset($i);
			}
			catch (\UnexpectedValueException $e) {
				throw new WebDAV_Exception('Not an image', 404);
			}
		}
		else {
			$this->server->log('NC Cached thumbnail (%d)', $size);
		}

		header('Content-Type: image/webp');
		readfile($cache_path);
	}
}
