from flask import Flask, render_template, request, redirect, session, url_for, g, flash
import sqlite3, os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = os.path.join('instance', 'perstat.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        print("✅ Database initialized")

if not os.path.exists(DATABASE):
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    init_db()

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
        admin_ranks = ["SGT", "SSG", "SFC", "MSG", "1SG", "SGM", "CSM", "SMA", "2LT", "1LT", "LT", "CPT"]
        is_admin = 1 if rank in admin_ranks else 0

        db = get_db()
        db.execute('INSERT INTO users (last_name, rank, pin, squad, is_admin) VALUES (?, ?, ?, ?, ?)',
                   (last_name, rank, pin, squad, is_admin))
        db.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        last_name = request.form['last_name'].strip().lower()
        rank = request.form['rank'].strip().upper()
        pin = request.form['pin'].strip()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE LOWER(last_name) = ? AND UPPER(rank) = ? AND pin = ?',
                          (last_name, rank, pin)).fetchone()
        if user:
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('roster'))
        flash('Login failed.')
    return render_template('login.html')

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        status = request.form['status']
        comment = request.form['comment']
        date = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
        user_id = session['user_id']
        db = get_db()
        existing = db.execute('SELECT * FROM perstat WHERE user_id = ? AND date = ?', (user_id, date)).fetchone()
        if existing:
            db.execute('UPDATE perstat SET status = ?, comment = ? WHERE user_id = ? AND date = ?',
                       (status, comment, user_id, date))
        else:
            db.execute('INSERT INTO perstat (user_id, date, status, comment) VALUES (?, ?, ?, ?)',
                       (user_id, date, status, comment))
        db.commit()
        flash('Submitted successfully!')
        return redirect(url_for('roster'))
    return render_template('submit.html')

@app.route('/roster')
@login_required
def roster():
    db = get_db()
    today = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    users = db.execute('SELECT * FROM users').fetchall()
    statuses = db.execute('SELECT * FROM perstat WHERE date = ?', (today,)).fetchall()
    summary = {}
    status_by_user = {s['user_id']: s for s in statuses}
    squads = {'1st Squad': [], '2nd Squad': []}
    for user in users:
        uid = user['id']
        squad = user['squad']
        user_data = dict(user)
        row = status_by_user.get(uid)
        user_data['status'] = row['status'] if row else 'Not Submitted'
        summary[user_data['status']] = summary.get(user_data['status'], 0) + 1
        squads[squad].append(user_data)
    return render_template('roster.html', squads=squads, summary=summary, is_admin=session.get('is_admin'))

@app.route('/admin/users')
@login_required
def view_users():
    if not session.get('is_admin'):
        return redirect(url_for('roster'))
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)