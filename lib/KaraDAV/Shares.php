<?php

namespace KaraDAV;

use stdClass;

class Shares
{
	public const TYPE_USER = 0;
	public const TYPE_GROUP = 1;
	public const TYPE_PUBLIC_LINK = 3;

	public const PERMISSION_READ = 1;
	public const PERMISSION_UPDATE = 2;
	public const PERMISSION_CREATE = 4;
	public const PERMISSION_DELETE = 8;
	public const PERMISSION_SHARE = 16;

	public function create(stdClass $user, string $path, int $share_type, int $permissions = self::PERMISSION_READ, array $options = []): stdClass
	{
		$token = $this->generateToken();
		$password = trim((string)($options['password'] ?? ''));
		$password_hash = $password !== '' ? password_hash($password, PASSWORD_DEFAULT) : null;
		$now = time();

		DB::getInstance()->run(
			'INSERT INTO shares (user, path, token, share_type, permissions, password_hash, expire_date, note, label, hide_download, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);',
			$user->id,
			$path,
			$token,
			$share_type,
			$permissions,
			$password_hash,
			$this->normalizeDate($options['expire_date'] ?? null),
			$options['note'] ?? '',
			$options['label'] ?? '',
			!empty($options['hide_download']) ? 1 : 0,
			$now
		);

		return $this->get((int)DB::getInstance()->lastInsertRowID(), $user->id);
	}

	public function get(int $id, ?int $user_id = null): ?stdClass
	{
		if ($user_id !== null) {
			return DB::getInstance()->first('SELECT * FROM shares WHERE id = ? AND user = ?;', $id, $user_id);
		}

		return DB::getInstance()->first('SELECT * FROM shares WHERE id = ?;', $id);
	}

	public function getByToken(string $token): ?stdClass
	{
		if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
			return null;
		}

		return DB::getInstance()->first('SELECT * FROM shares WHERE token = ?;', $token);
	}

	public function list(?stdClass $user = null, ?string $path = null): array
	{
		$sql = 'SELECT * FROM shares';
		$where = [];
		$params = [];

		if ($user) {
			$where[] = 'user = ?';
			$params[] = $user->id;
		}

		if ($path !== null) {
			$where[] = 'path = ?';
			$params[] = $path;
		}

		if ($where) {
			$sql .= ' WHERE ' . implode(' AND ', $where);
		}

		$sql .= ' ORDER BY created DESC, id DESC;';

		return iterator_to_array(DB::getInstance()->iterate($sql, ...$params));
	}

	public function update(stdClass $share, array $options): ?stdClass
	{
		$fields = [];
		$params = [];

		if (array_key_exists('permissions', $options)) {
			$fields[] = 'permissions = ?';
			$params[] = (int)$options['permissions'];
		}

		if (array_key_exists('password', $options)) {
			$password = trim((string)$options['password']);
			$fields[] = 'password_hash = ?';
			$params[] = $password !== '' ? password_hash($password, PASSWORD_DEFAULT) : null;
		}

		if (array_key_exists('expire_date', $options)) {
			$fields[] = 'expire_date = ?';
			$params[] = $this->normalizeDate($options['expire_date']);
		}

		foreach (['note', 'label'] as $field) {
			if (array_key_exists($field, $options)) {
				$fields[] = $field . ' = ?';
				$params[] = (string)$options[$field];
			}
		}

		if (array_key_exists('hide_download', $options)) {
			$fields[] = 'hide_download = ?';
			$params[] = !empty($options['hide_download']) ? 1 : 0;
		}

		if (!$fields) {
			return $share;
		}

		$params[] = $share->id;
		DB::getInstance()->run('UPDATE shares SET ' . implode(', ', $fields) . ' WHERE id = ?;', ...$params);

		return $this->get((int)$share->id, (int)$share->user);
	}

	public function delete(stdClass $share): void
	{
		DB::getInstance()->run('DELETE FROM shares WHERE id = ?;', $share->id);
	}

	public function isExpired(stdClass $share): bool
	{
		if (empty($share->expire_date)) {
			return false;
		}

		$ts = strtotime($share->expire_date);
		return $ts !== false && $ts < time();
	}

	public function publicUrl(stdClass $share): string
	{
		return WWW_URL . 's/' . $share->token;
	}

	protected function generateToken(): string
	{
		do {
			$token = bin2hex(random_bytes(16));
		}
		while ($this->getByToken($token));

		return $token;
	}

	protected function normalizeDate($date): ?string
	{
		$date = trim((string)$date);

		if ($date === '') {
			return null;
		}

		$ts = strtotime($date);

		return $ts === false ? null : date('Y-m-d H:i:s', $ts);
	}
}
