from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, session, url_for, g, flash, Response
import psycopg2, os, csv
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
from functools import wraps
from email_utils import send_reminder_email
from werkzeug.security import generate_password_hash, check_password_hash
import json
from pywebpush import webpush, WebPushException

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret')
DATABASE_URL = os.environ.get('DATABASE_URL')
from datetime import timedelta

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Keep login active for 30 days
app.config['SESSION_COOKIE_SECURE'] = True  # ✅ Ensures cookies only sent over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # ✅ Allows cross-site cookies (needed for some PWAs)

# ---- Roster helpers ----
SECTIONS_ORDER = [
    "Present", "Leave", "Gym detail", "Hospital", "School",
    "LWC", "Comp", "BMM", "Appointment", "Not Submitted"
]

def norm_status(raw):
    """Normalize any status text to one of our canonical labels."""
    if not raw:
        return "Not Submitted"
    t = str(raw).strip().lower()
    aliases = {
        "present": "Present",
        "leave": "Leave",
        "gym": "Gym detail",
        "gym detail": "Gym detail",
        "gymdetail": "Gym detail",
        "hospital": "Hospital",
        "school": "School",
        "lwc": "LWC",
        "comp": "Comp",
        "bmm": "BMM",
        "appointment": "Appointment",
        "appt": "Appointment",
        "not submitted": "Not Submitted",
        "notsubmitted": "Not Submitted",
        "": "Not Submitted",
        None: "Not Submitted",
    }
    return aliases.get(t, raw.strip().title())

def normalize_squad(val):
    """Force squad labels to '1st Squad' / '2nd Squad' / 'Unassigned'."""
    v = (val or "").strip().lower()
    if v in {"1st squad", "1st", "first", "1"}:
        return "1st Squad"
    if v in {"2nd squad", "2nd", "second", "2"}:
        return "2nd Squad"
    return "Unassigned"


@app.context_processor
def inject_vapid():
    return {"VAPID_PUBLIC_KEY": os.environ.get("VAPID_PUBLIC_KEY", "")}

# ---------------------- Database ----------------------
def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return g.db

# ✅ Add this directly below
def all_users_submitted(conn, target_date):
    cur = conn.cursor()

    # Count total users
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()['count']

    # Count submissions for that date
    cur.execute("SELECT COUNT(DISTINCT user_id) FROM perstat WHERE date = %s", (target_date,))
    submitted = cur.fetchone()['count']

    cur.close()
    return submitted == total_users


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ---------------------- Helpers ----------------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.before_request
def enforce_https_in_production():
    if os.environ.get('FLASK_ENV') == 'production' and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        return redirect(request.url.replace('http://', 'https://', 1))

# ---------------------- Routes ----------------------

VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY")
VAPID_CLAIMS = {"sub": "mailto:admin@yourapp.com"}

subscriptions = []  # replace this with a DB or session store in production

@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    subscriptions.append(data)
    return '', 201

@app.route('/admin/push_notify', methods=['POST'])
@login_required
def push_notify():
    if not session.get('is_admin'):
        return "Unauthorized", 403
    payload = json.dumps({
        "title": request.form['title'],
        "body": request.form['body']
    })
    for sub in subscriptions:
        try:
            webpush(subscription_info=sub,
                    data=payload,
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims=VAPID_CLAIMS)
        except WebPushException as ex:
            print("Push failed:", repr(ex))
    return redirect(url_for('view_messages'))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        last_name = request.form['last_name'].strip().lower()
        rank = request.form['rank'].strip().upper()
        pin = generate_password_hash(request.form['pin'].strip())
        squad = request.form['squad']
        email = request.form.get('email')
        is_admin = rank in ["SGT", "SSG", "SFC", "MSG", "1SG", "SGM", "CSM", "SMA", "2LT", "1LT", "LT", "CPT"]

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('INSERT INTO users (last_name, rank, pin, squad, is_admin, email) VALUES (%s, %s, %s, %s, %s, %s)',
                        (last_name, rank, pin, squad, is_admin, email))
            conn.commit()
            cur.close()
            flash('Registration successful!')
            return redirect(url_for('login'))
        except Exception as e:
            print("❌ Registration Error:", e)
            flash('Registration failed.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        last_name = request.form['last_name'].strip().lower()
        entered_pin = request.form['pin'].strip()

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                'SELECT id, pin, is_admin FROM users WHERE LOWER(last_name) = %s LIMIT 1',
                (last_name,)
            )
            user = cur.fetchone()
            cur.close()

            if user and check_password_hash(user['pin'], entered_pin):
                # ✅ Save session & keep it permanent
                session['user_id'] = user['id']
                session['is_admin'] = user['is_admin']
                session.permanent = True  # Keep signed in
                return redirect(url_for('roster'))

            flash('Login failed. Check name & PIN.')
        except Exception as e:
            print("❌ Login Error:", e)
            flash('Login failed due to internal error.')

    return render_template('login.html')

# --- keep ONLY this one block ---
@app.route('/admin/generate_summary', methods=['GET', 'POST'])
@login_required
def manual_generate_summary():
    if not session.get('is_admin'):
        return redirect(url_for('roster'))
    # Generate on GET or POST – nice and simple
    generate_ai_summary()
    flash('AI summary generated.')
    return redirect(url_for('ai_summary'))


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

        cur.execute('DELETE FROM perstat WHERE date < %s', ((datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d'),))
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

    target = (datetime.now() + timedelta(days=1))
    target_date = target.strftime('%Y-%m-%d')
    date_compact = target.strftime('%Y%m%d')
    weekday = target.strftime('%A')

    # All users
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()

    # Tomorrow's perstat rows
    cur.execute('SELECT * FROM perstat WHERE date = %s', (target_date,))
    statuses = cur.fetchall()

    # Recent messages (unchanged)
    cur.execute('SELECT * FROM messages ORDER BY created_at DESC LIMIT 3')
    messages = cur.fetchall()
    cur.close()

    # Map user_id -> status
    status_by_user = {s['user_id']: (s['status'] or 'Not Submitted') for s in statuses}

    # Normalize status labels to your desired headings
    def norm_status(raw):
        if not raw:
            return 'Not Submitted'
        r = raw.strip().lower()
        if r in ('present', 'p'):
            return 'Present'
        if r in ('leave', 'lv', 'on leave'):
            return 'Leave'
        if r in ('gym detail', 'gym', 'bmm', 'detail'):
            return 'GYM Detail'
        return raw.title()  # fallback

    # Build per-squad blocks
    squads = ['1st Squad', '2nd Squad']
    squad_blocks = {
        '1st Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
        '2nd Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
    }

    for u in users:
        squad_name = u.get('squad', '').strip()
        # Accept common inputs like '1st', '1st squad', '2nd', '2nd squad'
        if squad_name.lower().startswith('1st'):
            bucket = squad_blocks['1st Squad']
        elif squad_name.lower().startswith('2nd'):
            bucket = squad_blocks['2nd Squad']
        else:
            # If user has no/other squad, skip showing in these two panels
            continue

        bucket['Assigned'] += 1

        st = norm_status(status_by_user.get(u['id']))
        fullname = f"{u['rank']} {u['last_name']}".strip()
        # Only collect the sections we care about; others go under their own title
        if st in ('Present', 'Leave', 'GYM Detail'):
            bucket[st].append(fullname)
        else:
            bucket['Not Submitted'].append(fullname)

    # Pass everything to the template
    return render_template(
        'roster.html',
        date_compact=date_compact,
        weekday=weekday,
        squad_blocks=squad_blocks,
        messages=messages,
        is_admin=session.get('is_admin')
    )



@app.route('/messages')
@login_required
def view_messages():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM messages WHERE created_at < %s', ((datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S'),))
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
        yield 'Last Name,Rank,Squad,Date,Status,Comment\n'
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

    success = sum(1 for u in users if send_reminder_email(u['email'], u['last_name']))
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
    try:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        flash("User deleted.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting user: {e}", "danger")
    finally:
        cur.close()
    return redirect(url_for('view_users'))


@app.route('/admin/edit/<int:user_id>', methods=['GET'])
@login_required
def edit_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('roster'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if not user:
        flash("User not found.")
        return redirect(url_for('view_users'))
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/update/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('roster'))

    last_name = request.form['last_name'].strip().lower()
    rank = request.form['rank'].strip().upper()
    squad = request.form['squad']
    email = request.form['email']
    is_admin = rank in ["SGT", "SSG", "SFC", "MSG", "1SG", "SGM", "CSM", "SMA", "2LT", "1LT", "LT", "CPT"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        UPDATE users
        SET last_name = %s, rank = %s, squad = %s, email = %s, is_admin = %s
        WHERE id = %s
    ''', (last_name, rank, squad, email, is_admin, user_id))
    conn.commit()
    cur.close()
    flash("User updated.")
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

    target = (datetime.now() + timedelta(days=1))
    date_db = target.strftime('%Y-%m-%d')
    date_compact = target.strftime('%Y%m%d')
    weekday = target.strftime('%A')

    # Build per-squad lists like in roster
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()

    cur.execute('SELECT * FROM perstat WHERE date = %s', (date_db,))
    rows = cur.fetchall()
    cur.close()

    status_by_user = {r['user_id']: (r['status'] or 'Not Submitted') for r in rows}

    def norm_status(raw):
        if not raw:
            return 'Not Submitted'
        r = raw.strip().lower()
        if r in ('present', 'p'):
            return 'Present'
        if r in ('leave', 'lv', 'on leave'):
            return 'Leave'
        if r in ('gym detail', 'gym', 'bmm', 'detail'):
            return 'GYM Detail'
        return raw.title()

    squads = ['1st Squad', '2nd Squad']
    squad_blocks = {
        '1st Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
        '2nd Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
    }

    for u in users:
        sname = u.get('squad', '').strip()
        if sname.lower().startswith('1st'):
            block = squad_blocks['1st Squad']
        elif sname.lower().startswith('2nd'):
            block = squad_blocks['2nd Squad']
        else:
            continue

        block['Assigned'] += 1
        st = norm_status(status_by_user.get(u['id']))
        fullname = f"{u['rank']} {u['last_name']}".strip()
        if st in ('Present', 'Leave', 'GYM Detail'):
            block[st].append(fullname)
        else:
            block['Not Submitted'].append(fullname)

    # Format like your example, hiding empty sections
    def fmt_block(title, block):
        lines = []
        lines.append(f"{title} PerStats")
        lines.append(f"{date_compact}/ {weekday}")
        lines.append("")
        lines.append(f"Assigned: {block['Assigned']}")
        if block['Present']:
            lines.append(f"Present: {len(block['Present'])}")
        if block['Leave']:
            lines.append(f"Leave: {len(block['Leave'])}")
        if block['GYM Detail']:
            lines.append(f"GYM Detail: {len(block['GYM Detail'])}")
        if block['Not Submitted']:
            lines.append(f"Not Submitted: {len(block['Not Submitted'])}")
        lines.append("")
        lines.append("____________________")
        lines.append("")

        if block['Present']:
            lines.append("Present")
            for n in block['Present']:
                lines.append(n)
            lines.append("")

        if block['Leave']:
            lines.append("Leave")
            for n in block['Leave']:
                lines.append(n)
            lines.append("")

        if block['GYM Detail']:
            lines.append("Gym Detail")
            for n in block['GYM Detail']:
                lines.append(n)
            lines.append("")

        if block['Not Submitted']:
            lines.append("Not Submitted")
            for n in block['Not Submitted']:
                lines.append(n)
            lines.append("")

        return "\n".join(lines).rstrip()

    block_texts = []
    for sname in ['1st Squad', '2nd Squad']:
        block_texts.append(fmt_block(sname, squad_blocks[sname]))

    final_summary = "\n\n\n".join(block_texts)

    # Save (upsert) to ai_summaries and clean old ones
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO ai_summaries (date, summary, created_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (date) DO UPDATE SET summary = EXCLUDED.summary
    ''', (date_db, final_summary, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    # (Keep or remove the perstat clear if you still want a reset)
    # cur.execute('DELETE FROM perstat WHERE date = %s', (date_db,))

    # Delete summaries older than 2 days
    two_days_ago = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')
    cur.execute('DELETE FROM ai_summaries WHERE date < %s', (two_days_ago,))

    conn.commit()
    cur.close()

    # Optional: send via push or WhatsApp here if you want
    # broadcast_whatsapp(final_summary)


@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')

@app.route('/register_sw.js')
def register_sw():
    return app.send_static_file('register_sw.js')

# ---------------------- Init DB ----------------------
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
    app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    # Only run Flask's dev server if not running under gunicorn
    if os.environ.get("FLY_APP_NAME") is None:
        app.run(host='0.0.0.0', port=8080)



