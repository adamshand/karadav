CREATE TABLE share_password_attempts (
	share_token TEXT NOT NULL REFERENCES shares(token) ON DELETE CASCADE,
	ip TEXT NOT NULL,
	failures INTEGER NOT NULL,
	retry_after INTEGER NOT NULL,
	PRIMARY KEY (share_token, ip)
);
