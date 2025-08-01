
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    last_name TEXT NOT NULL,
    rank TEXT NOT NULL,
    pin TEXT NOT NULL,
    squad TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS perstat (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    date DATE NOT NULL,
    status TEXT NOT NULL,
    comment TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    author_id INTEGER REFERENCES users(id),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);
