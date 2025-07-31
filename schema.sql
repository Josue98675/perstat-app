DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS perstat;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    last_name TEXT NOT NULL,
    rank TEXT NOT NULL,
    pin TEXT NOT NULL,
    squad TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
);
CREATE TABLE perstat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL,
    comment TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id)
);
