from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, session, url_for, g, flash, Response
import psycopg2, os, csv
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
from functools import wraps
from email_utils import send_reminder_email
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret')

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        last_name = request.form['last_name'].strip().lower()
        rank = request.form['rank'].strip().upper()
        pin = request.form['pin'].strip()
        squad = request.form['squad']
        email = request.form.get('email')
        admin_ranks = ["SGT", "SSG", "SFC", "MSG", "1SG", "SGM", "CSM", "SMA", "2LT", "1LT", "LT", "CPT"]
        is_admin = rank in admin_ranks

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO users (last_name, rank, pin, squad, is_admin, email) VALUES (%s, %s, %s, %s, %s, %s)',
                (last_name, rank, pin, squad, is_admin, email)
            )
            conn.commit()
            cur.close()
            flash('Registration successful!')
            return redirect(url_for('login'))
        except Exception as e:
            print("❌ Registration Error:", e)
            flash('Registration failed.')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/robots.txt')
def robots_txt():
    return "User-agent: *\nDisallow: /", 200, {'Content-Type': 'text/plain'}


@app.before_request
def enforce_https_in_production():
    if os.environ.get('FLASK_ENV') == 'production' and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        last_name = request.form['last_name'].strip().lower()
        rank = request.form['rank'].strip().upper()
        pin = request.form['pin'].strip()

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                'SELECT id, is_admin FROM users WHERE LOWER(last_name) = %s AND UPPER(rank) = %s AND pin = %s',
                (last_name, rank, pin)
            )
            user = cur.fetchone()
            cur.close()

            if user:
                session['user_id'] = user['id']
                session['is_admin'] = user['is_admin']
                return redirect(url_for('roster'))
            else:
                flash('Login failed.')
        except Exception as e:
            print("❌ Login Error:", e)
            flash('Login failed due to internal error.')

    return render_template('login.html')

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        status = request.form['status']
        comment = request.form['comment']
        date = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
        user_id = session['user_id']
        conn = get_db()
        cur = conn.cursor()

        ten_days_ago = (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d')
        cur.execute('DELETE FROM perstat WHERE date < %s', (ten_days_ago,))

        cur.execute('SELECT * FROM perstat WHERE user_id = %s AND date = %s', (user_id, date))
        existing = cur.fetchone()

        if existing:
            cur.execute('UPDATE perstat SET status = %s, comment = %s WHERE user_id = %s AND date = %s',
                        (status, comment, user_id, date))
        else:
            cur.execute('INSERT INTO perstat (user_id, date, status, comment) VALUES (%s, %s, %s, %s)',
                        (user_id, date, status, comment))

        conn.commit()
        cur.close()
        flash('Submitted successfully!')
        return redirect(url_for('roster'))
    return render_template('submit.html')

@app.route('/roster')
@login_required
def roster():
    conn = get_db()
    cur = conn.cursor()
    today = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()
    cur.execute('SELECT * FROM perstat WHERE date = %s', (today,))
    statuses = cur.fetchall()
    cur.execute('SELECT * FROM messages ORDER BY created_at DESC LIMIT 3')
    messages = cur.fetchall()
    cur.close()

    summary = {}
    status_by_user = {s['user_id']: s for s in statuses}
    squads = {}
    for user in users:
        uid = user['id']
        squad = user['squad']
        user_data = dict(user)
        row = status_by_user.get(uid)
        user_data['status'] = row['status'] if row else 'Not Submitted'
        summary[user_data['status']] = summary.get(user_data['status'], 0) + 1
        squads.setdefault(squad, []).append(user_data)
    return render_template('roster.html', squads=squads, summary=summary, messages=messages, is_admin=session.get('is_admin'))

@app.route('/admin/generate_summary')
@login_required
def manual_generate_summary():
    if not session.get('is_admin'):
        return redirect(url_for('roster'))

    generate_ai_summary()
    flash("✅ AI Summary generated.")
    return redirect(url_for('roster'))


@app.route('/messages')
@login_required
def view_messages():
    conn = get_db()
    cur = conn.cursor()
    one_day_ago = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    cur.execute('DELETE FROM messages WHERE created_at < %s', (one_day_ago,))
    cur.execute('SELECT * FROM messages ORDER BY created_at DESC')
    messages = cur.fetchall()
    conn.commit()
    cur.close()
    return render_template('messages.html', messages=messages, is_admin=session.get('is_admin'))

@app.route('/messages/new', methods=['POST'])
@login_required
def post_message():
    if not session.get('is_admin'):
        return redirect(url_for('view_messages'))
    title = request.form['title']
    content = request.form['content']
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO messages (author_id, title, content, created_at) VALUES (%s, %s, %s, %s)",
                (session['user_id'], title, content, created_at))
    conn.commit()
    cur.close()
    return redirect(url_for('view_messages'))

@app.route('/messages/delete/<int:msg_id>', methods=['POST'])
@login_required
def delete_message(msg_id):
    if not session.get('is_admin'):
        return redirect(url_for('view_messages'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE id = %s", (msg_id,))
    conn.commit()
    cur.close()
    return redirect(url_for('view_messages'))

@app.route('/admin/export')
@login_required
def export_perstat():
    if not session.get('is_admin'):
        return redirect(url_for('roster'))

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT u.last_name, u.rank, u.squad, p.date, p.status, p.comment
        FROM perstat p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.date DESC
    ''')
    rows = cur.fetchall()
    cur.close()

    def generate():
        yield ','.join(['Last Name', 'Rank', 'Squad', 'Date', 'Status', 'Comment']) + '\n'
        for row in rows:
            yield ','.join([str(row['last_name']), row['rank'], row['squad'], row['date'], row['status'], row['comment'] or '']) + '\n'

    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=perstat_report.csv'})

@app.route('/admin/send_reminders')
@login_required
def send_reminders():
    if not session.get('is_admin'):
        return redirect(url_for('roster'))

    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT email, last_name FROM users WHERE email IS NOT NULL')
    users = cur.fetchall()
    cur.close()

    success = 0
    for u in users:
        if send_reminder_email(u['email'], u['last_name']):
            success += 1

    flash(f'Sent {success} reminder emails.')
    return redirect(url_for('view_users'))

@app.route('/admin/users')
@login_required
def view_users():
    if not session.get('is_admin'):
        return redirect(url_for('roster'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()
    cur.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('roster'))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cur.close()
    flash("User deleted.")
    return redirect(url_for('view_users'))

@app.route('/ai_summary')
@login_required
def ai_summary():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_summaries ORDER BY date DESC")
    summaries = cur.fetchall()
    cur.close()
    return render_template('ai_summary.html', summaries=summaries)

def generate_ai_summary():
    conn = get_db()
    cur = conn.cursor()

    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')

    # Get all squads
    cur.execute("SELECT DISTINCT squad FROM users")
    squads = [row['squad'] for row in cur.fetchall()]

    summary_lines = []

    for squad in squads:
        cur.execute('''
            SELECT u.rank, u.last_name, p.status
            FROM users u
            LEFT JOIN perstat p ON u.id = p.user_id AND p.date = %s
            WHERE u.squad = %s
        ''', (tomorrow, squad))

        data = cur.fetchall()
        total = len(data)
        status_count = {}

        for row in data:
            status = row['status'] if row['status'] else 'Not Submitted'
            status_count[status] = status_count.get(status, 0) + 1

        # Capitalize full status words (e.g., Present, Leave, Hospital)
        status_summary = ', '.join([f"{k.capitalize()}-{v}" for k, v in status_count.items()])

        summary_lines.append(f"{squad} Squad ({total}): {status_summary}")

    overall = '\n'.join(summary_lines)
    cur.execute('''
        INSERT INTO ai_summaries (date, summary, created_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (date) DO UPDATE SET summary = EXCLUDED.summary
    ''', (tomorrow, overall, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    conn.commit()
    cur.close()

# ✅ PWA Routes
@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')

@app.route('/register_sw.js')
def register_sw():
    return app.send_static_file('register_sw.js')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if os.environ.get('AUTO_INIT_DB') == 'true':
    def init_db():
        with app.app_context():
            conn = get_db()
            cur = conn.cursor()
            with open('schema.sql', 'r') as f:
                cur.execute(f.read())
            conn.commit()
            cur.close()
    init_db()

if __name__ == '__main__':
    app.run(debug=True)


