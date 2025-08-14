from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, session, url_for, g, flash, Response
import psycopg2, os, csv, json
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta, date
from functools import wraps
from email_utils import send_reminder_email
from werkzeug.security import generate_password_hash, check_password_hash
from pywebpush import webpush, WebPushException
from zoneinfo import ZoneInfo

# ---------------------- App / Config ----------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret')
DATABASE_URL = os.environ.get('DATABASE_URL')

# ---- Long-lived login (effectively "one time") ----
from datetime import timedelta as _td
app.config['PERMANENT_SESSION_LIFETIME'] = _td(days=365*100)   # ~100 years
app.config['SESSION_REFRESH_EACH_REQUEST'] = True               # refresh on every request

# Cookie settings (needed for PWAs / iOS home-screen)
app.config['SESSION_COOKIE_SECURE']   = True        # only over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'None'      # allow cross-site/PWA
app.config['SESSION_COOKIE_HTTPONLY'] = True        # JS can't read the cookie
app.config['SESSION_COOKIE_PATH']     = '/'         # ensure path-wide
_cookie_domain = os.environ.get('SESSION_COOKIE_DOMAIN')  # optional
if _cookie_domain:
    app.config['SESSION_COOKIE_DOMAIN'] = _cookie_domain  # e.g., ".yourdomain.com"

# Always mark the session as permanent once a user has logged in
@app.before_request
def keep_session_fresh():
    if 'user_id' in session:
        session.permanent = True

# New York timezone
APP_TZ = ZoneInfo("America/New_York")

# Cutoff (NY time): roster switches day at 5pm
ROSTER_ROLLOVER_HOUR = 17  # 5pm

# ---- Labels / helpers ----
SECTIONS_ORDER = [
    "Present", "Leave", "Gym detail", "Hospital", "School",
    "LWC", "Comp", "BMM", "Appointment", "Not Submitted"
]

def norm_status(raw):
    if not raw:
        return "Not Submitted"
    t = str(raw).strip().lower()
    aliases = {
        "present": "Present", "p": "Present",
        "leave": "Leave", "lv": "Leave", "on leave": "Leave",
        "gym": "Gym detail", "gym detail": "Gym detail", "gymdetail": "Gym detail",
        "detail": "Gym detail", "bmm": "Gym detail",
        "hospital": "Hospital", "school": "School", "lwc": "LWC", "comp": "Comp",
        "appointment": "Appointment", "appt": "Appointment",
        "not submitted": "Not Submitted", "notsubmitted": "Not Submitted",
        "": "Not Submitted", None: "Not Submitted",
    }
    return aliases.get(t, raw.strip().title())

def normalize_squad(val):
    v = (val or "").strip().lower()
    if v in {"1st squad", "1st", "first", "1"}:
        return "1st Squad"
    if v in {"2nd squad", "2nd", "second", "2"}:
        return "2nd Squad"
    return "Unassigned"

def now_ny():
    return datetime.now(APP_TZ)

def fmt_day_header(d: date):
    return d.strftime('%Y%m%d'), d.strftime('%A')

def roster_target_date(ny_now: datetime) -> date:
    """
    Active roster date using a 5pm NY cutoff:
      - Before 5pm: today's date
      - 5pm or later: tomorrow's date
    """
    base = ny_now.date()
    return base + timedelta(days=1) if ny_now.hour >= ROSTER_ROLLOVER_HOUR else base

def cleanup_perstat_rollover(conn, ny_now: datetime):
    """
    Delete perstat rows for dates strictly before the active roster date.
    This makes the previous day's roster disappear right when we roll over (>=5pm).
    """
    active_date = roster_target_date(ny_now).strftime('%Y-%m-%d')
    cur = conn.cursor()
    cur.execute("DELETE FROM perstat WHERE date < %s", (active_date,))
    conn.commit()
    cur.close()

@app.context_processor
def inject_vapid():
    return {"VAPID_PUBLIC_KEY": os.environ.get("VAPID_PUBLIC_KEY", "")}

# ---------------------- Database ----------------------
def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return g.db

def ensure_leaves_table():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS leaves (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            start_date DATE NOT NULL,
            end_date   DATE NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT now()
        );
    """)
    conn.commit()
    cur.close()

def users_on_leave_for_date(conn, target_date_str):
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id
        FROM leaves
        WHERE %s::date BETWEEN start_date AND end_date
    """, (target_date_str,))
    rows = cur.fetchall()
    cur.close()
    return {r['user_id'] for r in rows}

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ---------------------- Auth helpers ----------------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.before_request
def enforce_https_in_production():
    # Make sure you actually serve via HTTPS in production, or cookies won't persist on iOS PWAs
    if os.environ.get('FLASK_ENV') == 'production' and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        return redirect(request.url.replace('http://', 'https://', 1))

# ---------------------- Push ----------------------
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY")
VAPID_CLAIMS = {"sub": "mailto:admin@yourapp.com"}

subscriptions = []  # replace with DB in production

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

# ---------------------- Routes ----------------------
@app.route('/')
def index():
    # If already logged in, go straight to roster
    if 'user_id' in session:
        return redirect(url_for('roster'))
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
            cur.execute('SELECT id, pin, is_admin FROM users WHERE LOWER(last_name) = %s LIMIT 1', (last_name,))
            user = cur.fetchone()
            cur.close()
            if user and check_password_hash(user['pin'], entered_pin):
                session['user_id'] = user['id']
                session['is_admin'] = user['is_admin']
                session.permanent = True
                return redirect(url_for('roster'))
            flash('Login failed. Check name & PIN.')
        except Exception as e:
            print("❌ Login Error:", e)
            flash('Login failed due to internal error.')
    return render_template('login.html')

# Manual AI summary trigger
@app.route('/admin/generate_summary', methods=['GET', 'POST'])
@login_required
def manual_generate_summary():
    if not session.get('is_admin'):
        return redirect(url_for('roster'))
    generate_ai_summary()
    flash('AI summary generated.')
    return redirect(url_for('ai_summary'))

# ---------------------- Leave range ----------------------
@app.route('/leave/new', methods=['POST'])
@login_required
def create_leave():
    try:
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        sd = datetime.strptime(start_date, '%Y-%m-%d').date()
        ed = datetime.strptime(end_date, '%Y-%m-%d').date()
        if ed < sd:
            flash("End date must be after start date.", "warning")
            return redirect(url_for('roster'))
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO leaves (user_id, start_date, end_date) VALUES (%s, %s, %s)",
                    (session['user_id'], sd, ed))
        conn.commit()
        cur.close()
        flash("Leave period saved.", "success")
    except Exception as e:
        print("❌ Leave Error:", e)
        flash("Could not save leave.", "danger")
    return redirect(url_for('roster'))

# ---------------------- Submit PERSTAT ----------------------
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        status = request.form['status']
        comment = request.form['comment']
        ny_now = now_ny()

        conn = get_db()
        # cleanup at 5pm rollover
        cleanup_perstat_rollover(conn, ny_now)

        # Save to the same date the roster is showing (so it updates what users see)
        target_date = roster_target_date(ny_now).strftime('%Y-%m-%d')

        user_id = session['user_id']
        cur = conn.cursor()
        cur.execute('SELECT * FROM perstat WHERE user_id = %s AND date = %s', (user_id, target_date))
        existing = cur.fetchone()

        if existing:
            cur.execute('UPDATE perstat SET status = %s, comment = %s WHERE user_id = %s AND date = %s',
                        (status, comment, user_id, target_date))
        else:
            cur.execute('INSERT INTO perstat (user_id, date, status, comment) VALUES (%s, %s, %s, %s)',
                        (user_id, target_date, status, comment))
        conn.commit()
        cur.close()

        flash('Submitted successfully!')
        return redirect(url_for('roster'))
    return render_template('submit.html')

# ---------------------- Roster (NY 5pm cycle) ----------------------
@app.route('/roster')
@login_required
def roster():
    ensure_leaves_table()

    conn = get_db()
    ny_now = now_ny()

    # cleanup at 5pm rollover
    cleanup_perstat_rollover(conn, ny_now)

    # Active roster date (today before 5pm, tomorrow at/after 5pm)
    target_date_obj = roster_target_date(ny_now)
    target_date_str = target_date_obj.strftime('%Y-%m-%d')
    date_compact, weekday = fmt_day_header(target_date_obj)

    cur = conn.cursor()
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()

    cur.execute('SELECT * FROM perstat WHERE date = %s', (target_date_str,))
    rows = cur.fetchall()

    cur.execute('SELECT * FROM messages ORDER BY created_at DESC LIMIT 3')
    messages = cur.fetchall()
    cur.close()

    perstat_status = {r['user_id']: (r['status'] or 'Not Submitted') for r in rows}
    leave_set = users_on_leave_for_date(conn, target_date_str)

    def friendly_status_for(u_id):
        if u_id in leave_set:
            return 'Leave'
        return norm_status(perstat_status.get(u_id))

    squad_blocks = {
        '1st Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
        '2nd Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
    }

    for u in users:
        sname = normalize_squad(u.get('squad'))
        if sname not in squad_blocks:
            continue

        block = squad_blocks[sname]
        block['Assigned'] += 1

        st = friendly_status_for(u['id'])
        fullname = f"{u['rank']} {u['last_name']}".strip()
        if st in ('Present', 'Leave', 'GYM Detail'):
            block[st].append(fullname)
        else:
            block['Not Submitted'].append(fullname)

    def build_block_text(title, block):
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
            lines.extend(block['Present'])
            lines.append("")
        if block['Leave']:
            lines.append("Leave")
            lines.extend(block['Leave'])
            lines.append("")
        if block['GYM Detail']:
            lines.append("Gym Detail")
            lines.extend(block['GYM Detail'])
            lines.append("")
        if block['Not Submitted']:
            lines.append("Not Submitted")
            lines.extend(block['Not Submitted'])
            lines.append("")
        return "\n".join(lines).rstrip()

    roster_text_parts = []
    for name in ['1st Squad', '2nd Squad']:
        roster_text_parts.append(build_block_text(name, squad_blocks[name]))
    roster_text = "\n\n\n".join(roster_text_parts)

    return render_template(
        'roster.html',
        weekday=weekday,
        date_compact=date_compact,
        squad_blocks=squad_blocks,
        messages=messages,
        roster_text=roster_text,
        is_admin=session.get('is_admin')
    )

# ---------------------- Messages ----------------------
@app.route('/messages')
@login_required
def view_messages():
    conn = get_db()
    cur = conn.cursor()
    cutoff_ts = (now_ny() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    cur.execute('DELETE FROM messages WHERE created_at < %s', (cutoff_ts,))
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
    created_at = now_ny().strftime('%Y-%m-%d %H:%M:%S')
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

# ---------------------- Admin Users ----------------------
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

# ---------------------- AI Summary (NY 5pm cycle) ----------------------
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
    ensure_leaves_table()

    conn = get_db()
    cur = conn.cursor()

    ny_now = now_ny()
    # Same target date as roster (5pm rule)
    target_date_obj = roster_target_date(ny_now)
    date_db = target_date_obj.strftime('%Y-%m-%d')
    date_compact, weekday = fmt_day_header(target_date_obj)

    cur.execute('SELECT * FROM users')
    users = cur.fetchall()

    cur.execute('SELECT * FROM perstat WHERE date = %s', (date_db,))
    rows = cur.fetchall()
    cur.close()

    perstat_status = {r['user_id']: (r['status'] or 'Not Submitted') for r in rows}
    leave_set = users_on_leave_for_date(conn, date_db)

    def friendly_status_for(u_id):
        if u_id in leave_set:
            return 'Leave'
        return norm_status(perstat_status.get(u_id))

    squad_blocks = {
        '1st Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
        '2nd Squad': {'Assigned': 0, 'Present': [], 'Leave': [], 'GYM Detail': [], 'Not Submitted': []},
    }

    for u in users:
        sname = normalize_squad(u.get('squad'))
        if sname not in squad_blocks:
            continue
        block = squad_blocks[sname]
        block['Assigned'] += 1
        st = friendly_status_for(u['id'])
        fullname = f"{u['rank']} {u['last_name']}".strip()
        if st in ('Present', 'Leave', 'GYM Detail'):
            block[st].append(fullname)
        else:
            block['Not Submitted'].append(fullname)

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

    cur = conn.cursor()
    cur.execute('''
        INSERT INTO ai_summaries (date, summary, created_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (date) DO UPDATE SET summary = EXCLUDED.summary
    ''', (date_db, final_summary, now_ny().strftime('%Y-%m-%d %H:%M:%S')))

    two_days_ago = (now_ny().date() - timedelta(days=2)).strftime('%Y-%m-%d')
    cur.execute('DELETE FROM ai_summaries WHERE date < %s', (two_days_ago,))
    conn.commit()
    cur.close()

# ---------------------- Static files ----------------------
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
            ensure_leaves_table()
    init_db()
else:
    with app.app_context():
        try:
            ensure_leaves_table()
        except Exception:
            pass

# ---------------------- Run ----------------------
if __name__ == '__main__':
    if os.environ.get("FLY_APP_NAME") is None:
        app.run(host='0.0.0.0', port=8080)
