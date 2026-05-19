"""学术日志系统 - 多账号认证版"""

import os, json, sqlite3, uuid, secrets, hashlib, base64, requests as req_lib
from datetime import datetime, date, timedelta
from pathlib import Path
from functools import wraps

if os.environ.get('FLASK_ENV') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from requests_oauthlib import OAuth2Session

app = Flask(__name__)

BASE_DIR        = Path(__file__).parent
DB_PATH         = BASE_DIR / 'journal.db'
DATABASE_URL    = os.environ.get('DATABASE_URL', '').replace('postgres://', 'postgresql://')
GOOGLE_CREDS    = BASE_DIR / 'client_secrets.json'
MS_CREDS        = BASE_DIR / 'microsoft_secrets.json'

# Secret key: 优先用环境变量（生产环境 Render 注入），其次用文件持久化（本地）
if os.environ.get('SECRET_KEY'):
    app.secret_key = os.environ['SECRET_KEY']
else:
    _KEY_FILE = BASE_DIR / '.secret_key'
    if _KEY_FILE.exists():
        app.secret_key = _KEY_FILE.read_text().strip()
    else:
        _k = secrets.token_hex(32)
        _KEY_FILE.write_text(_k)
        app.secret_key = _k

# ── OAuth 常量 ────────────────────────────────────────────────
GOOGLE_SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/drive.readonly',
]
MS_AUTH_URL  = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
MS_TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
MS_SCOPES    = ['openid', 'profile', 'email', 'User.Read']

ACTIVITY_CATEGORIES = [
    ('reading',  '📖 文献阅读'), ('writing',  '✍️ 论文写作'),
    ('research', '🔬 实验研究'), ('lecture',  '🎓 听课学习'),
    ('discuss',  '💬 学术讨论'), ('coding',   '💻 编程分析'),
    ('data',     '📊 数据处理'), ('other',    '🌐 其他'),
]
MOODS = ['😫', '😟', '😐', '😊', '😄']

# ── Database ──────────────────────────────────────────────────
class _DB:
    """统一 SQLite（?）和 PostgreSQL（%s）的参数占位符，保持接口一致。"""
    def __init__(self, conn, pg=False):
        self._c  = conn
        self._pg = pg

    def execute(self, sql, params=()):
        if self._pg:
            sql = sql.replace('?', '%s')
        cur = self._c.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):    self._c.commit()
    def rollback(self):  self._c.rollback()
    def close(self):     self._c.close()


def _open_db():
    if DATABASE_URL:
        import psycopg2, psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL,
                                cursor_factory=psycopg2.extras.RealDictCursor)
        return _DB(conn, pg=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return _DB(conn, pg=False)


def get_db():
    if 'db' not in g:
        g.db = _open_db()
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()


def init_db():
    db = _open_db()
    # 建表（user_id 已包含在初始 schema 中，新库无需 ALTER TABLE）
    for sql in [
        """CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL, password TEXT,
            provider TEXT DEFAULT 'local', provider_id TEXT DEFAULT '',
            avatar TEXT DEFAULT '', created_at TEXT, last_login TEXT)""",
        """CREATE TABLE IF NOT EXISTS entries (
            id TEXT PRIMARY KEY, user_id TEXT,
            date TEXT NOT NULL, title TEXT NOT NULL,
            study_hours REAL DEFAULT 0, mood INTEGER DEFAULT 3,
            activities TEXT DEFAULT '[]', reflections TEXT DEFAULT '',
            insights TEXT DEFAULT '[]', tags TEXT DEFAULT '[]',
            created_at TEXT, updated_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS drive_links (
            id TEXT PRIMARY KEY, entry_id TEXT NOT NULL, user_id TEXT,
            file_id TEXT NOT NULL, file_name TEXT NOT NULL,
            file_url TEXT NOT NULL, mime_type TEXT DEFAULT '', linked_at TEXT)""",
    ]:
        db.execute(sql)
    db.commit()
    # SQLite 旧库迁移（本地开发用）
    if not db._pg:
        for sql in [
            "ALTER TABLE entries ADD COLUMN user_id TEXT",
            "ALTER TABLE drive_links ADD COLUMN user_id TEXT",
        ]:
            try: db.execute(sql); db.commit()
            except: pass
    # 建索引
    for sql in [
        "CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(user_id, date DESC)",
        "CREATE INDEX IF NOT EXISTS idx_drive_entry  ON drive_links(entry_id)",
    ]:
        try: db.execute(sql); db.commit()
        except Exception:
            if db._pg: db.rollback()
    db.close()

# ── Helpers ───────────────────────────────────────────────────
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('请先登录', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def drive_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('google_credentials'):
            return jsonify({'error': '请先连接 Google Drive'}), 401
        return f(*args, **kwargs)
    return decorated

def entry_to_dict(row):
    d = dict(row)
    d['activities'] = json.loads(d.get('activities') or '[]')
    d['insights']   = json.loads(d.get('insights')   or '[]')
    d['tags']       = json.loads(d.get('tags')        or '[]')
    return d

def mime_icon(mime):
    if not mime: return '📄'
    if 'document'     in mime: return '📝'
    if 'spreadsheet'  in mime: return '📊'
    if 'presentation' in mime: return '📋'
    if 'folder'       in mime: return '📁'
    if 'pdf'          in mime: return '📕'
    if 'image'        in mime: return '🖼️'
    return '📄'

def _pkce_pair():
    v = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
    return v, c

def _find_or_create_oauth_user(email, name, provider, provider_id, avatar=''):
    """OAuth 登录：找到已有账号或新建。"""
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE provider=? AND provider_id=?",
        (provider, provider_id)).fetchone()
    if not row:
        row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    now = datetime.now().isoformat()
    if row:
        db.execute("UPDATE users SET last_login=?,avatar=?,provider_id=? WHERE id=?",
                   (now, avatar, provider_id, row['id']))
        db.commit()
        return dict(row)
    uid = str(uuid.uuid4())
    db.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?)",
               (uid, email, name, None, provider, provider_id, avatar, now, now))
    db.commit()
    return {'id': uid, 'email': email, 'name': name, 'avatar': avatar}

@app.context_processor
def inject_user():
    u = current_user()
    return {'current_user': u, 'mime_icon': mime_icon, 'moods': MOODS}

# ── 本地邮箱+密码登录 ─────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        row = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row and row['password'] and check_password_hash(row['password'], password):
            session['user_id'] = row['id']
            get_db().execute("UPDATE users SET last_login=? WHERE id=?",
                             (datetime.now().isoformat(), row['id']))
            get_db().commit()
            flash(f'欢迎回来，{row["name"]}！', 'success')
            return redirect(url_for('index'))
        flash('邮箱或密码错误', 'error')
    return render_template('login.html',
        has_google=GOOGLE_CREDS.exists(),
        has_ms=MS_CREDS.exists())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        email    = request.form.get('email', '').strip().lower()
        pw       = request.form.get('password', '')
        pw2      = request.form.get('password2', '')
        if not name or not email or not pw:
            flash('请填写所有必填项', 'error')
            return render_template('register.html')
        if pw != pw2:
            flash('两次密码不一致', 'error')
            return render_template('register.html')
        if len(pw) < 6:
            flash('密码至少6位', 'error')
            return render_template('register.html')
        existing = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            flash('该邮箱已注册', 'error')
            return render_template('register.html')
        uid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        get_db().execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?)",
                         (uid, email, name, generate_password_hash(pw),
                          'local', '', '', now, now))
        get_db().commit()
        session['user_id'] = uid
        flash(f'注册成功，欢迎 {name}！', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ── Google OAuth ──────────────────────────────────────────────
@app.route('/auth/google')
def google_login():
    if not GOOGLE_CREDS.exists():
        flash('Google OAuth 未配置，请先完成设置', 'error')
        return redirect(url_for('login_page'))
    v, c = _pkce_pair()
    session['code_verifier'] = v
    flow = Flow.from_client_secrets_file(
        str(GOOGLE_CREDS), scopes=GOOGLE_SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True))
    auth_url, state = flow.authorization_url(
        access_type='offline', prompt='consent',
        code_challenge=c, code_challenge_method='S256')
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    state, verifier = session.pop('oauth_state', None), session.pop('code_verifier', None)
    if not state:
        flash('登录状态异常', 'error')
        return redirect(url_for('login_page'))
    flow = Flow.from_client_secrets_file(
        str(GOOGLE_CREDS), scopes=GOOGLE_SCOPES, state=state,
        redirect_uri=url_for('oauth2callback', _external=True))
    try:
        flow.fetch_token(authorization_response=request.url, code_verifier=verifier)
    except Exception as e:
        flash(f'Google 登录失败: {e}', 'error')
        return redirect(url_for('login_page'))
    creds = flow.credentials
    try:
        svc  = build('oauth2', 'v2', credentials=creds)
        info = svc.userinfo().get().execute()
        email  = info.get('email', '')
        name   = info.get('name', email)
        avatar = info.get('picture', '')
        pid    = info.get('id', '')
    except Exception:
        flash('获取 Google 用户信息失败', 'error')
        return redirect(url_for('login_page'))
    user = _find_or_create_oauth_user(email, name, 'google', pid, avatar)
    session['user_id'] = user['id']
    # 保存 Drive 凭据（仅 Google 用户有）
    session['google_credentials'] = {
        'token': creds.token, 'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri, 'client_id': creds.client_id,
        'client_secret': creds.client_secret, 'scopes': list(creds.scopes or GOOGLE_SCOPES),
    }
    flash(f'欢迎，{name}！', 'success')
    return redirect(url_for('index'))

# ── Microsoft OAuth ───────────────────────────────────────────
@app.route('/auth/microsoft')
def ms_login():
    if not MS_CREDS.exists():
        flash('Microsoft OAuth 未配置', 'error')
        return redirect(url_for('login_page'))
    ms = json.loads(MS_CREDS.read_text())
    oauth = OAuth2Session(ms['client_id'], scope=MS_SCOPES,
                          redirect_uri=url_for('ms_callback', _external=True))
    auth_url, state = oauth.authorization_url(MS_AUTH_URL)
    session['ms_state'] = state
    return redirect(auth_url)

@app.route('/auth/microsoft/callback')
def ms_callback():
    if not MS_CREDS.exists():
        return redirect(url_for('login_page'))
    ms    = json.loads(MS_CREDS.read_text())
    state = session.pop('ms_state', None)
    oauth = OAuth2Session(ms['client_id'], state=state,
                          redirect_uri=url_for('ms_callback', _external=True))
    try:
        oauth.fetch_token(MS_TOKEN_URL, client_secret=ms['client_secret'],
                          authorization_response=request.url)
        me     = oauth.get('https://graph.microsoft.com/v1.0/me').json()
        email  = me.get('mail') or me.get('userPrincipalName', '')
        name   = me.get('displayName', email)
        pid    = me.get('id', '')
    except Exception as e:
        flash(f'Microsoft 登录失败: {e}', 'error')
        return redirect(url_for('login_page'))
    user = _find_or_create_oauth_user(email, name, 'microsoft', pid)
    session['user_id'] = user['id']
    flash(f'欢迎，{name}！', 'success')
    return redirect(url_for('index'))

# ── 连接 / 断开 Drive（已登录用户的附加操作）────────────────
@app.route('/drive/connect')
@login_required
def drive_connect():
    """已登录用户额外连接 Google Drive"""
    if not GOOGLE_CREDS.exists():
        flash('Google OAuth 未配置', 'error')
        return redirect(url_for('index'))
    v, c = _pkce_pair()
    session['code_verifier'] = v
    session['drive_connect_mode'] = True      # 标记：仅连接 Drive，不切换账号
    flow = Flow.from_client_secrets_file(
        str(GOOGLE_CREDS), scopes=GOOGLE_SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True))
    auth_url, state = flow.authorization_url(
        access_type='offline', prompt='consent',
        code_challenge=c, code_challenge_method='S256')
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/drive/disconnect')
@login_required
def drive_disconnect():
    session.pop('google_credentials', None)
    flash('已断开 Google Drive 连接', 'success')
    return redirect(url_for('index'))

# ── 日志 CRUD ─────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    uid = session['user_id']
    db  = get_db()
    entries = [entry_to_dict(r) for r in
               db.execute("SELECT * FROM entries WHERE user_id=? ORDER BY date DESC LIMIT 10",
                          (uid,)).fetchall()]
    total      = db.execute("SELECT COUNT(*) c FROM entries WHERE user_id=?", (uid,)).fetchone()['c']
    hours      = db.execute("SELECT COALESCE(SUM(study_hours),0) h FROM entries WHERE user_id=?", (uid,)).fetchone()['h']
    this_month = date.today().strftime('%Y-%m')
    m_hours    = db.execute(
        "SELECT COALESCE(SUM(study_hours),0) h FROM entries WHERE user_id=? AND date LIKE ?",
        (uid, f'{this_month}%')).fetchone()['h']
    streak, check = 0, date.today()
    while db.execute("SELECT id FROM entries WHERE user_id=? AND date=?",
                     (uid, str(check))).fetchone():
        streak += 1; check -= timedelta(days=1)
    cal_dates = [r['date'] for r in
                 db.execute("SELECT DISTINCT date FROM entries WHERE user_id=? AND date LIKE ?",
                            (uid, f'{this_month}%')).fetchall()]
    has_drive = bool(session.get('google_credentials'))
    return render_template('index.html',
        entries=entries, total=total, total_hours=round(hours,1),
        month_hours=round(m_hours,1), streak=streak,
        cal_dates=cal_dates, today=str(date.today()),
        has_drive=has_drive)

@app.route('/entry/new')
@login_required
def new_entry():
    return render_template('new_entry.html',
        today=str(date.today()), categories=ACTIVITY_CATEGORIES, entry=None,
        has_drive=bool(session.get('google_credentials')))

@app.route('/entry', methods=['POST'])
@login_required
def create_entry():
    uid, data = session['user_id'], request.form
    acts = []
    for k in [k for k in data if k.startswith('act_desc_')]:
        idx  = k.split('_')[-1]
        desc = data.get(f'act_desc_{idx}', '').strip()
        if desc:
            acts.append({'desc': desc,
                         'category': data.get(f'act_cat_{idx}', 'other'),
                         'hours': float(data.get(f'act_hours_{idx}', 0) or 0)})
    insights = [l.strip() for l in data.get('insights','').split('\n') if l.strip()]
    tags     = [t.strip() for t in data.get('tags','').split(',')     if t.strip()]
    total_h  = sum(a['hours'] for a in acts) or float(data.get('study_hours',0) or 0)
    eid, now = str(uuid.uuid4()), datetime.now().isoformat()
    get_db().execute(
        "INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid, uid, data['date'], data['title'], total_h,
         int(data.get('mood',3)),
         json.dumps(acts, ensure_ascii=False),
         data.get('reflections',''),
         json.dumps(insights, ensure_ascii=False),
         json.dumps(tags, ensure_ascii=False), now, now))
    get_db().commit()
    flash('日志已保存 ✓', 'success')
    return redirect(url_for('view_entry', entry_id=eid))

@app.route('/entry/<entry_id>')
@login_required
def view_entry(entry_id):
    uid = session['user_id']
    row = get_db().execute("SELECT * FROM entries WHERE id=? AND user_id=?",
                           (entry_id, uid)).fetchone()
    if not row:
        flash('日志不存在', 'error'); return redirect(url_for('index'))
    drives = get_db().execute(
        "SELECT * FROM drive_links WHERE entry_id=? ORDER BY linked_at DESC",
        (entry_id,)).fetchall()
    return render_template('entry.html',
        entry=entry_to_dict(row), drives=[dict(d) for d in drives],
        categories=dict(ACTIVITY_CATEGORIES),
        has_drive=bool(session.get('google_credentials')))

@app.route('/entry/<entry_id>/edit')
@login_required
def edit_entry(entry_id):
    uid = session['user_id']
    row = get_db().execute("SELECT * FROM entries WHERE id=? AND user_id=?",
                           (entry_id, uid)).fetchone()
    if not row: return redirect(url_for('index'))
    return render_template('new_entry.html',
        today=row['date'], categories=ACTIVITY_CATEGORIES,
        entry=entry_to_dict(row),
        has_drive=bool(session.get('google_credentials')))

@app.route('/entry/<entry_id>/update', methods=['POST'])
@login_required
def update_entry(entry_id):
    uid, data = session['user_id'], request.form
    acts = []
    for k in [k for k in data if k.startswith('act_desc_')]:
        idx = k.split('_')[-1]
        desc = data.get(f'act_desc_{idx}','').strip()
        if desc:
            acts.append({'desc': desc,
                         'category': data.get(f'act_cat_{idx}','other'),
                         'hours': float(data.get(f'act_hours_{idx}',0) or 0)})
    insights = [l.strip() for l in data.get('insights','').split('\n') if l.strip()]
    tags     = [t.strip() for t in data.get('tags','').split(',')     if t.strip()]
    total_h  = sum(a['hours'] for a in acts) or float(data.get('study_hours',0) or 0)
    get_db().execute(
        """UPDATE entries SET date=?,title=?,study_hours=?,mood=?,
           activities=?,reflections=?,insights=?,tags=?,updated_at=?
           WHERE id=? AND user_id=?""",
        (data['date'], data['title'], total_h, int(data.get('mood',3)),
         json.dumps(acts, ensure_ascii=False), data.get('reflections',''),
         json.dumps(insights, ensure_ascii=False),
         json.dumps(tags, ensure_ascii=False),
         datetime.now().isoformat(), entry_id, uid))
    get_db().commit()
    flash('日志已更新 ✓', 'success')
    return redirect(url_for('view_entry', entry_id=entry_id))

@app.route('/entry/<entry_id>/delete', methods=['POST'])
@login_required
def delete_entry(entry_id):
    get_db().execute("DELETE FROM entries WHERE id=? AND user_id=?",
                     (entry_id, session['user_id']))
    get_db().commit()
    flash('日志已删除', 'success')
    return redirect(url_for('index'))

# ── Drive API ─────────────────────────────────────────────────
def _drive_service():
    cd = session.get('google_credentials')
    if not cd: return None
    return build('drive', 'v3', credentials=Credentials(
        token=cd['token'], refresh_token=cd.get('refresh_token'),
        token_uri=cd['token_uri'], client_id=cd['client_id'],
        client_secret=cd['client_secret'], scopes=cd['scopes']))

@app.route('/api/drive/files')
@drive_login_required
def drive_files():
    svc = _drive_service()
    try:
        r = svc.files().list(pageSize=20, orderBy='modifiedTime desc',
            fields='files(id,name,mimeType,modifiedTime,webViewLink)',
            q='trashed=false').execute()
        files = r.get('files', [])
        for f in files: f['icon'] = mime_icon(f.get('mimeType',''))
        return jsonify({'files': files})
    except HttpError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/drive/search')
@drive_login_required
def drive_search():
    q = request.args.get('q','').strip()
    if not q: return jsonify({'files': []})
    svc = _drive_service()
    try:
        r = svc.files().list(pageSize=15, orderBy='modifiedTime desc',
            fields='files(id,name,mimeType,modifiedTime,webViewLink)',
            q=f"name contains '{q}' and trashed=false").execute()
        files = r.get('files', [])
        for f in files: f['icon'] = mime_icon(f.get('mimeType',''))
        return jsonify({'files': files})
    except HttpError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/entry/<entry_id>/drive', methods=['POST'])
@login_required
def link_drive(entry_id):
    data = request.json
    lid  = str(uuid.uuid4())
    get_db().execute("INSERT INTO drive_links VALUES (?,?,?,?,?,?,?,?)",
        (lid, entry_id, session['user_id'], data['file_id'],
         data['file_name'], data['file_url'],
         data.get('mime_type',''), datetime.now().isoformat()))
    get_db().commit()
    return jsonify({'success': True, 'id': lid})

@app.route('/api/entry/<entry_id>/drive/<link_id>', methods=['DELETE'])
@login_required
def unlink_drive(entry_id, link_id):
    get_db().execute("DELETE FROM drive_links WHERE id=? AND entry_id=?",
                     (link_id, entry_id))
    get_db().commit()
    return jsonify({'success': True})

# ── Setup ─────────────────────────────────────────────────────
@app.route('/setup')
def setup():
    return render_template('setup.html',
        has_google=GOOGLE_CREDS.exists(),
        has_ms=MS_CREDS.exists(),
        app_dir=str(BASE_DIR))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    if debug:
        print("\n✅  学术日志已启动")
        print(f"📌  请在浏览器打开: http://localhost:{port}\n")
    app.run(debug=debug, host='0.0.0.0', port=port)
