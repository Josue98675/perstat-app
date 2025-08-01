import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv
load_dotenv()

conn = psycopg2.connect(os.environ['DATABASE_URL'], cursor_factory=RealDictCursor)
cur = conn.cursor()

# Fetch users with plaintext PINs (assuming length < 60 means not hashed)
cur.execute("SELECT id, pin FROM users")
users = cur.fetchall()

for user in users:
    if len(user['pin']) < 60:  # crude check for unhashed PIN
        hashed = generate_password_hash(user['pin'])
        cur.execute("UPDATE users SET pin = %s WHERE id = %s", (hashed, user['id']))
        print(f"✅ Hashed PIN for user ID {user['id']}")

conn.commit()
cur.close()
conn.close()
print("🎉 All unhashed PINs are now secure!")
