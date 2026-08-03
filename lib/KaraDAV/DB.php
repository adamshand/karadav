<?php

namespace KaraDAV;

class DB extends \SQLite3
{
	const VERSION = 6;

	static protected $instance;

	static public function getInstance(): self
	{
		if (!isset(self::$instance)) {
			self::$instance = new self;
		}

		return self::$instance;
	}

	public function __construct()
	{
		if (isset(self::$instance)) {
			throw new \LogicException('Already started');
		}

		parent::__construct(DB_FILE);

		$this->busyTimeout(10 * 1000);
		$this->exec('PRAGMA foreign_keys = ON;');

		if (!(int) $this->querySingle('PRAGMA foreign_keys;')) {
			throw new \RuntimeException('SQLite foreign key enforcement could not be enabled');
		}

		$mode = strtoupper(DB_JOURNAL_MODE);
		$set_mode = $this->querySingle('PRAGMA journal_mode;');
		$set_mode = strtoupper($set_mode);

		// Only set journal mode if it is different, as setting it every time may be slow
		if ($set_mode !== $mode) {
			// WAL = performance enhancement
			// see https://www.cs.utexas.edu/~jaya/slides/apsys17-sqlite-slides.pdf
			// https://ericdraken.com/sqlite-performance-testing/
			$this->exec(sprintf(
				'PRAGMA journal_mode = %s; PRAGMA synchronous = NORMAL; PRAGMA journal_size_limit = %d;',
				$mode,
				32 * 1024 * 1024
			));
		}
	}

	public function run(string $sql, ...$params)
	{
		$st = $this->prepare($sql);

		foreach ($params as $key => $value) {
			$st->bindValue(is_int($key) ? $key+1 : ':' . $key, $value);
		}

		return $st->execute();
	}

	public function iterate(string $sql, ...$params): iterable
	{
		$res = $this->run($sql, ...$params);
		while ($row = $res->fetchArray(\SQLITE3_ASSOC)) {
			yield (object)$row;
		}
	}

	public function first(string $sql, ...$params)
	{
		$row = $this->run($sql, ...$params)->fetchArray(\SQLITE3_ASSOC);
		return $row ? (object) $row : null;
	}

	public function firstColumn(string $sql, ...$params)
	{
		return $this->run($sql, ...$params)->fetchArray(\SQLITE3_NUM)[0] ?? null;
	}

	public function getPathLikeExpression(string $path)
	{
		if ($path === '') {
			return '%';
		}

		return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $path) . '/%';
	}

	public function upgradeVersion(): void
	{
		$db_version = $this->firstColumn('PRAGMA user_version;');

		if ($db_version > self::VERSION) {
			throw new \RuntimeException(sprintf(
				'Database version %d is newer than supported version %d',
				$db_version,
				self::VERSION
			));
		}

		if ($db_version === self::VERSION) {
			return;
		}

		$this->exec('BEGIN;');

		if ($db_version < 1) {
			$this->exec(file_get_contents(ROOT . '/sql/migrate_0001.sql'));

			$users = new Users;
			$users->indexAllFiles();
		}

		// Re-index to create directories in cache
		if ($db_version < 2) {
			$users = new Users;
			$users->indexAllFiles();
		}

		if ($db_version < 3) {
			$this->exec(file_get_contents(ROOT . '/sql/migrate_0003.sql'));
		}

		if ($db_version < 4) {
			$this->exec(file_get_contents(ROOT . '/sql/migrate_0004.sql'));
		}

		if ($db_version < 5) {
			$this->exec(file_get_contents(ROOT . '/sql/migrate_0005.sql'));
		}

		if ($db_version < 6) {
			$this->exec(file_get_contents(ROOT . '/sql/migrate_0006.sql'));
		}

		$this->exec('PRAGMA user_version = ' . self::VERSION . ';');
		$this->exec('END;');
	}
}
