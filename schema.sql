CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    last_name TEXT NOT NULL,
    rank TEXT NOT NULL,
    pin TEXT NOT NULL,
    squad TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    email TEXT
);

CREATE TABLE ai_summaries (
    id SERIAL PRIMARY KEY,
    date TEXT NOT NULL UNIQUE,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE perstat (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL,
    comment TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    author_id INTEGER,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

