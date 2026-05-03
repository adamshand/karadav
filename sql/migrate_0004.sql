CREATE TABLE shares (
	id INTEGER PRIMARY KEY NOT NULL,
	user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	path TEXT NOT NULL,
	token TEXT NOT NULL,
	share_type INTEGER NOT NULL,
	permissions INTEGER NOT NULL DEFAULT 1,
	password_hash TEXT NULL,
	expire_date TEXT NULL,
	note TEXT NOT NULL DEFAULT '',
	label TEXT NOT NULL DEFAULT '',
	hide_download INTEGER NOT NULL DEFAULT 0,
	created INTEGER NOT NULL
);

CREATE UNIQUE INDEX shares_token ON shares(token);
CREATE INDEX shares_user_path ON shares(user, path);
