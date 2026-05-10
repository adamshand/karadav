<?php

namespace KaraDAV;

use KD2\WebDAV\WOPI;

class Server
{
	public Users $users;
	public WebDAV $dav;
	public NextCloud $nc;

	public function __construct()
	{
		$users = new Users;
		$this->users = new Users;
		$this->dav = new WebDAV;
		$this->nc = new NextCloud($this->users);
		$storage = new Storage($this->users, $this->nc);
		$this->dav->setStorage($storage);
	}

	public function route(string $uri, string $relative_uri): bool
	{
		$method = $_SERVER['REQUEST_METHOD'] ?? null;

		// Always say YES to OPTIONS
		if ($method == 'OPTIONS') {
			$this->dav->http_options();
			return true;
		}

		if (WOPI_DISCOVERY_URL) {
			$wopi = new WOPI;
			$wopi->setServer($this->dav);

			if ($wopi->route($relative_uri)) {
				return true;
			}
		}

		if (preg_match('!^s/([a-f0-9]{32})(?:/(.*))?$!', trim($relative_uri, '/'), $match)) {
			return $this->servePublicShare($match[1], $match[2] ?? '', $relative_uri);
		}

		if (preg_match('!^index\.php/f/(\d+)$!', trim($relative_uri, '/'), $match)) {
			return $this->servePrivateFileLink((int)$match[1]);
		}

		$this->nc->setServer($this->dav);

		if ($r = $this->nc->route($relative_uri)) {
			// NextCloud route already replied something, stop here
			return true;
		}

		// If NextCloud layer didn't return anything
		// it means we fall back to the default WebDAV server
		// available on the root path. We need to handle a
		// classic login/password auth here.

		$base = rtrim(parse_url(WWW_URL, PHP_URL_PATH), '/');

		if (0 !== strpos($uri, $base . '/files/')) {
			return false;
		}

		$user = $this->users->login($_SERVER['PHP_AUTH_USER'] ?? null, $_SERVER['PHP_AUTH_PW'] ?? null);

		if (!$user) {
			http_response_code(401);
			header('WWW-Authenticate: Basic realm="Please login"');
			return true;
		}

		$this->dav->setBaseURI($base . '/files/' . $user->login . '/');

		return $this->dav->route($uri);
	}

	protected function servePrivateFileLink(int $file_id): bool
	{
		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

		if (!in_array($method, ['GET', 'HEAD'], true)) {
			http_response_code(405);
			return true;
		}

		$user = $this->users->login($_SERVER['PHP_AUTH_USER'] ?? null, $_SERVER['PHP_AUTH_PW'] ?? null)
			?? $this->users->appSessionLogin($_SERVER['PHP_AUTH_USER'] ?? null, $_SERVER['PHP_AUTH_PW'] ?? null);

		if (!$user) {
			http_response_code(401);
			header('WWW-Authenticate: Basic realm="Please login"');
			echo 'This private link requires access to the file.';
			return true;
		}

		$this->users->setCurrent($user->login);
		$path = $this->dav->getStorage()->getFilePathFromId($file_id);

		if (!$path) {
			http_response_code(404);
			echo 'File not found';
			return true;
		}

		header('Location: ' . WWW_URL . 'files/' . rawurlencode($user->login) . '/' . $this->encodePath($path));
		http_response_code(302);
		return true;
	}

	protected function servePublicShare(string $token, string $subpath, string $relative_uri): bool
	{
		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

		if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) {
			http_response_code(405);
			return true;
		}

		$shares = new Shares;
		$share = $shares->getByToken($token);

		if (!$share || $share->share_type != Shares::TYPE_PUBLIC_LINK) {
			http_response_code(404);
			echo 'Share not found';
			return true;
		}

		if ($shares->isExpired($share)) {
			http_response_code(410);
			echo 'Share has expired';
			return true;
		}

		if (!$this->checkPublicSharePassword($share)) {
			return true;
		}

		$owner = $this->users->getById((int)$share->user);

		if (!$owner || !$this->users->setCurrent($owner->login)) {
			http_response_code(404);
			echo 'Share owner not found';
			return true;
		}

		$subpath = trim(rawurldecode($subpath), '/');

		if (str_contains($subpath, '..')) {
			http_response_code(403);
			echo 'Invalid path';
			return true;
		}

		$target = trim($share->path . ($subpath !== '' ? '/' . $subpath : ''), '/');

		if (!$this->dav->getStorage()->exists($target)) {
			http_response_code(404);
			echo 'File not found';
			return true;
		}

		try {
			$props = $this->dav->getStorage()->propfind($target, ['DAV::resourcetype'], 0) ?: [];
			$is_collection = ($props['DAV::resourcetype'] ?? null) === 'collection';

			if ($is_collection) {
				if ($method === 'HEAD') {
					http_response_code(200);
					return true;
				}

				if (substr(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH), -1) !== '/') {
					header('Location: ' . WWW_URL . 's/' . $token . ($subpath !== '' ? '/' . $this->encodePath($subpath) : '') . '/');
					http_response_code(301);
					return true;
				}

				header('Content-Type: text/html; charset=utf-8');
				echo $this->publicDirectoryListing($token, $subpath, $target);
				return true;
			}

			$this->dav->original_uri = $relative_uri;
			$this->dav->setBaseURI('/s/' . $token . '/');

			if ($method === 'HEAD') {
				$this->dav->http_head($target);
			}
			else {
				$out = $this->dav->http_get($target);

				if (is_string($out)) {
					echo $out;
				}
			}
		}
		catch (\KD2\WebDAV\Exception $e) {
			http_response_code($e->getCode());
			echo $e->getMessage();
		}

		return true;
	}

	protected function checkPublicSharePassword(\stdClass $share): bool
	{
		if (empty($share->password_hash)) {
			return true;
		}

		$cookie = 'karadav_share_' . substr($share->token, 0, 16);
		$value = sha1($share->token . ':' . $share->password_hash);

		if (hash_equals($value, $_COOKIE[$cookie] ?? '')) {
			return true;
		}

		$password = $_POST['password'] ?? null;

		if (is_string($password) && password_verify($password, $share->password_hash)) {
			setcookie($cookie, $value, [
				'expires' => time() + 3600,
				'path' => parse_url(WWW_URL, PHP_URL_PATH) ?: '/',
				'samesite' => 'Lax',
				'httponly' => true,
				'secure' => parse_url(WWW_URL, PHP_URL_SCHEME) === 'https',
			]);
			return true;
		}

		http_response_code($password === null ? 200 : 403);
		header('Content-Type: text/html; charset=utf-8');
		echo '<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Password required</title></head><body>';
		echo '<h1>Password required</h1>';

		if ($password !== null) {
			echo '<p>Invalid password.</p>';
		}

		echo '<form method="post"><p><input type="password" name="password" autofocus required> <button type="submit">Open share</button></p></form>';
		echo '</body></html>';

		return false;
	}

	protected function publicDirectoryListing(string $token, string $subpath, string $target): string
	{
		$list = $this->dav->getStorage()->list($target, \KD2\WebDAV\Server::BASIC_PROPERTIES);
		$title = basename($target) ?: 'Shared files';
		$out = '<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>' . htmlspecialchars($title) . '</title>';
		$out .= '<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:2rem;line-height:1.4}table{border-collapse:collapse;min-width:50%}td,th{border-bottom:1px solid #ddd;padding:.6rem;text-align:left}a{color:#246}</style></head><body>';
		$out .= '<h1>' . htmlspecialchars($title) . '</h1><table>';

		if ($subpath !== '') {
			$out .= '<tr><th colspan="3"><a href="../">Back</a></th></tr>';
		}

		$empty = true;

		foreach ($list as $name => $props) {
			$empty = false;

			if ($props === null) {
				$props = $this->dav->getStorage()->propfind(trim($target . '/' . $name, '/'), \KD2\WebDAV\Server::BASIC_PROPERTIES, 0) ?: [];
			}

			$is_dir = ($props['DAV::resourcetype'] ?? null) === 'collection';
			$href = rawurlencode($name) . ($is_dir ? '/' : '');
			$size = $is_dir ? '' : $this->formatBytes((int)($props['DAV::getcontentlength'] ?? 0));
			$date = $props['DAV::getlastmodified'] ?? null;
			$date = $date instanceof \DateTimeInterface ? $date->format('Y-m-d H:i') : '';
			$out .= sprintf('<tr><td>%s</td><th><a href="%s">%s</a></th><td>%s</td><td>%s</td></tr>', $is_dir ? '[DIR]' : '', $href, htmlspecialchars($name), $size, $date);
		}

		$out .= '</table>';

		if ($empty) {
			$out .= '<p>This directory is empty.</p>';
		}

		return $out . '</body></html>';
	}

	protected function encodePath(string $path): string
	{
		return implode('/', array_map('rawurlencode', explode('/', trim($path, '/'))));
	}

	protected function formatBytes(int $size): string
	{
		if ($size >= 1024 * 1024) {
			return sprintf('%.1f MB', $size / 1024 / 1024);
		}

		if ($size >= 1024) {
			return sprintf('%.1f KB', $size / 1024);
		}

		return $size ? $size . ' B' : '';
	}
}
