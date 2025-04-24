import sqlite3
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
import bcrypt # 비밀번호 해싱

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                points INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT 'available'
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                resolved INTEGER DEFAULT 0
            )
        """)
        # 후기 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS review (
                id TEXT PRIMARY KEY,
                product_id TEXT,
                reviewer_id TEXT NOT NULL,
                target_user_id TEXT NOT NULL,
                rating INTEGER NOT NULL,
                content TEXT NOT NULL
            )
        """)
        # 거래 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS point_transaction (
                id TEXT PRIMARY KEY,
                product_id TEXT,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,  -- 'charge', 'transfer', 'purchase', 'refund'
                created_at TEXT NOT NULL
            )
        """)
        # 채팅 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                is_read INTEGER DEFAULT 0
            )
        """)

        db.commit()

# 관리자 계정 생성
@app.route('/create_admin')  # 🔒 만들고 나면 꼭 삭제하거나 막아!
def create_admin():
    db = get_db()
    cursor = db.cursor()

    # admin 계정이 이미 존재하는지 확인
    cursor.execute("SELECT * FROM user WHERE username = 'admin'")
    if cursor.fetchone():
        return "이미 관리자 계정이 존재합니다."

    import uuid
    admin_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO user (id, username, password, bio, points, is_admin)
        VALUES (?, ?, ?, '', 0, 1)
    """, (admin_id, 'admin', 'admin123'))  # 필요하면 비밀번호는 hash 처리 가능

    db.commit()
    return "✅ 관리자 계정 생성 완료! 아이디: admin / 비밀번호: admin123"

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())  # ✅ bytes 상태로 유지

        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            (user_id, username, hashed_pw)
        )
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))
    return render_template('register.html')
       
# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user['password']):
            if user['is_blocked']:
                flash('해당 계정은 차단되었습니다.')
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            return redirect(url_for('admin_dashboard' if user['is_admin'] else 'dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')


# 로그인한 사용자 정보 자동으로 변수 전달
@app.context_processor
def inject_user():
    user = None
    has_unread_chat = False
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        # ✅ 안 읽은 채팅이 하나라도 있는지 확인
        cursor.execute("""
            SELECT COUNT(*) FROM chat
            WHERE receiver_id = ? AND is_read = 0
        """, (session['user_id'],))
        has_unread_chat = cursor.fetchone()[0] > 0

    return dict(user=user, has_unread_chat=has_unread_chat)

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 검색어 처리
    query = request.args.get('q')
    if query:
        cursor.execute("""
            SELECT product.*, user.username 
            FROM product
            JOIN user ON product.seller_id = user.id
            WHERE (product.title LIKE ? 
                   OR product.description LIKE ? 
                   OR user.username LIKE ?)
              AND user.is_blocked = 0
        """, (f"%{query}%", f"%{query}%", f"%{query}%"))
    else:
        cursor.execute("""
            SELECT product.*, user.username 
            FROM product
            JOIN user ON product.seller_id = user.id
            WHERE user.is_blocked = 0
        """)

    all_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        if 'bio' in request.form:
            bio = request.form.get('bio', '')
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
            db.commit()
            flash('프로필이 업데이트되었습니다.')
            return redirect(url_for('profile'))
        elif 'current_password' in request.form:
            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            current_hashed = cursor.fetchone()['password']
            if not bcrypt.checkpw(request.form['current_password'].encode(), current_hashed):
                flash('현재 비밀번호가 일치하지 않습니다.')
                return redirect(url_for('profile'))

            new_hashed = bcrypt.hashpw(request.form['new_password'].encode(), bcrypt.gensalt())
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_hashed, session['user_id']))
            db.commit()
            flash('비밀번호가 변경되었습니다.')
            return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 불러오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
  
    # 후기 목록
    cursor.execute("""
        SELECT review.*, user.username AS reviewer_name FROM review
        JOIN user ON review.reviewer_id = user.id
        WHERE review.target_user_id = ?
    """, (product['seller_id'],))
    reviews = cursor.fetchall()
   
    # 구매 여부 확인
    can_review = False
    if 'user_id' in session:
        cursor.execute("""
            SELECT * FROM point_transaction
            WHERE sender_id = ? 
                AND receiver_id = ?
                AND transaction_type = 'purchase'
                AND product_id = ?
        """, (session['user_id'], product['seller_id'], product_id))
        can_review = cursor.fetchone() is not None

    is_owner = ('user_id' in session and session['user_id'] == product['seller_id'])
    
    return render_template(
        'view_product.html',
        product=product,
        seller=seller,
        reviews=reviews,
        can_review=can_review,
        is_owner=is_owner
    )


# 신고하기
@app.route('/report/<target_type>/<target_id>', methods=['GET', 'POST'])
def report_target(target_type, target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        reason = request.form['reason']
        report_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_type, target_id, reason, resolved)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (report_id, session['user_id'], target_type, target_id, reason))
        db.commit()
        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))

    # 대상 이름 불러오기
    if target_type == 'user':
        cursor.execute("SELECT username FROM user WHERE id = ?", (target_id,))
    else:
        cursor.execute("SELECT title FROM product WHERE id = ?", (target_id,))
    target = cursor.fetchone()

    return render_template("report.html", target_type=target_type, target_id=target_id, target=target)

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 1대1 채팅
@app.route('/chat/<receiver_id>', methods=['GET', 'POST'])
def chat(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()

    # ✅ 안 읽은 메시지 읽음 처리
    cursor.execute("""
        UPDATE chat SET is_read = 1 
        WHERE receiver_id = ? AND sender_id = ?
    """, (session['user_id'], receiver_id))
    db.commit()
    
    if request.method == 'POST':
        msg = request.form['message']
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        chat_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO chat (id, sender_id, receiver_id, message, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (chat_id, session['user_id'], receiver_id, msg, timestamp))
        db.commit()
        return redirect(url_for('chat', receiver_id=receiver_id))

    cursor.execute("""
        SELECT chat.*, sender.username AS sender_name FROM chat
        JOIN user AS sender ON chat.sender_id = sender.id
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], receiver_id, receiver_id, session['user_id']))
    chats = cursor.fetchall()

    cursor.execute("SELECT username FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()
    return render_template('chat.html', chats=chats, receiver=receiver)

# 1대1 채팅 목록록
@app.route('/chats')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT DISTINCT
            CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS partner_id,
            MAX(timestamp) as last_time
        FROM chat
        WHERE sender_id = ? OR receiver_id = ?
        GROUP BY partner_id
        ORDER BY last_time DESC
    """, (session['user_id'], session['user_id'], session['user_id']))
    entries = cursor.fetchall()
    partners = []
    for entry in entries:
        cursor.execute("SELECT username FROM user WHERE id = ?", (entry['partner_id'],))
        user = cursor.fetchone()
        partners.append({'id': entry['partner_id'], 'username': user['username']})
    return render_template('chat_list.html', partners=partners)

# 채팅 확인 여부
@app.context_processor
def inject_user():
    user = None
    has_unread_chat = False
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        cursor.execute("""
            SELECT COUNT(*) FROM chat 
            WHERE receiver_id = ? AND is_read = 0
        """, (session['user_id'],))
        has_unread_chat = cursor.fetchone()[0] > 0
    return dict(user=user, has_unread_chat=has_unread_chat)

# 후기 작성
@app.route('/review/<target_user_id>/<product_id>', methods=['GET', 'POST'])
def write_review(target_user_id, product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 중복 후기 확인
    cursor.execute("""
        SELECT * FROM review
        WHERE reviewer_id = ? AND target_user_id = ? AND product_id = ?
    """, (session['user_id'], target_user_id, product_id))
    if cursor.fetchone():
        flash("이미 이 상품에 대해 후기를 작성하셨습니다.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        rating = int(request.form['rating'])
        content = request.form['content']
        review_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO review (id, reviewer_id, target_user_id, rating, content)
            VALUES (?, ?, ?, ?, ?)
        """, (review_id, session['user_id'], target_user_id, rating, content))
        db.commit()
        flash("후기가 작성되었습니다.")
        return redirect(url_for('dashboard'))

    # 대상 유저 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_user_id,))
    target_user = cursor.fetchone()
    return render_template('write_review.html', target=target_user)

# 포인트 충전 (프로필에서)
@app.route('/charge', methods=['POST'])
def charge():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    try:
        amount = int(request.form['amount'])
        if amount <= 0:
            flash("0보다 큰 금액을 입력하세요.")
            return redirect(url_for('profile'))  # ⚠️ 리디렉션도 프로필로!

        # 포인트 충전
        cursor.execute("UPDATE user SET points = points + ? WHERE id = ?", (amount, session['user_id']))

        # 거래 기록 추가
        import uuid, datetime
        transaction_id = str(uuid.uuid4())
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO point_transaction (id, sender_id, receiver_id, amount, transaction_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (transaction_id, session['user_id'], session['user_id'], amount, 'charge', now))

        db.commit()
        flash("포인트가 충전되었습니다.")
        return redirect(url_for('profile'))  # ✅ 충전 후 프로필로 되돌아가게
    except Exception as e:
        print("충전 오류:", e)
        flash("유효한 숫자를 입력하세요.")
        return redirect(url_for('profile'))

# 거래하기 
@app.route('/purchase/<product_id>', methods=['POST'])
def purchase(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 판매자 정보
    seller_id = product['seller_id']
    buyer_id = session['user_id']
    price = int(product['price'])

    # 본인이 자기 상품 구매 금지
    if seller_id == buyer_id:
        flash("자기 상품은 구매할 수 없습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    # 구매자 포인트 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (buyer_id,))
    buyer = cursor.fetchone()
    if buyer['points'] < price:
        flash("포인트가 부족합니다.")
        return redirect(url_for('view_product', product_id=product_id))

    # 거래 처리
    cursor.execute("UPDATE user SET points = points - ? WHERE id = ?", (price, buyer_id))
    cursor.execute("UPDATE user SET points = points + ? WHERE id = ?", (price, seller_id))

    # 상품 상태 'sold'로 변경
    cursor.execute("UPDATE product SET status = 'sold' WHERE id = ?", (product_id,))

    # 거래 기록
    import uuid, datetime
    tx_id = str(uuid.uuid4())
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO point_transaction (id, product_id, sender_id, receiver_id, amount, transaction_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (tx_id, product_id, buyer_id, seller_id, price, 'purchase', now))

    db.commit()
    flash("거래가 완료되었습니다.")
    return redirect(url_for('view_product', product_id=product_id))

# 관리자용 대대시보드
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if user['is_admin'] != 1:
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    # 관리자용 데이터
    cursor.execute("SELECT COUNT(*) FROM user")
    user_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM product")
    product_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM report")
    report_count = cursor.fetchone()[0]

    return render_template("admin_dashboard.html", 
        user=user, 
        user_count=user_count,
        product_count=product_count,
        report_count=report_count
    )

# 관리자용 유저 관리 페이지
@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 유저가 관리자 권한인지 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    if current_user['is_admin'] != 1:
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    # 전체 유저 목록 조회
    cursor.execute("SELECT id, username, is_admin, points FROM user WHERE is_blocked = 0")
    users = cursor.fetchall()

    return render_template('admin_users.html', users=users)

# 관리자용 상품 목록 페이지
@app.route('/admin/products')
def admin_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT product.*, user.username AS seller_name
        FROM product
        JOIN user ON product.seller_id = user.id
        WHERE user.is_blocked = 0
    """)

    products = cursor.fetchall()

    return render_template("admin_products.html", products=products)

# 관리자용 신고 목록
@app.route('/admin/reports')
def admin_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT report.*, 
            reporter.username AS reporter_name,
            target.username AS target_name,
            product.title AS product_title
        FROM report
        JOIN user AS reporter ON report.reporter_id = reporter.id
        LEFT JOIN user AS target ON report.target_type = 'user' AND report.target_id = target.id
        LEFT JOIN product AS product ON report.target_type = 'product' AND report.target_id = product.id
    """)
    reports = cursor.fetchall()

    return render_template("admin_reports.html", reports=reports)

# 관리자용 신고된 유저 차단 기능
@app.route('/admin/reports/block_user/<user_id>/<report_id>', methods=['POST'])
def block_user(user_id, report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_blocked = 1 WHERE id = ?", (user_id,))
    cursor.execute("UPDATE report SET resolved = 1 WHERE id = ?", (report_id,))
    db.commit()
    flash("해당 유저를 차단하고 신고를 처리했습니다.")
    return redirect(url_for('admin_reports'))

# 관리자용 신고된 상품 삭제 기능
@app.route('/admin/reports/delete_product/<product_id>/<report_id>', methods=['POST'])
def delete_reported_product(product_id, report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))

    # 상품에 대한 신고 처리 표시시
    cursor.execute("""
        UPDATE report SET resolved = 1 
        WHERE target_id = ? AND target_type = 'product'
    """, (product_id,))

    db.commit()
    flash("상품을 삭제하고 신고를 처리했습니다.")
    return redirect(url_for('admin_reports'))

# 신고 처리 완료
@app.route('/admin/reports/resolve/<report_id>', methods=['POST'])
def resolve_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE report SET resolved = 1 WHERE id = ?", (report_id,))
    db.commit()
    flash("신고를 처리 완료로 표시했습니다.")
    return redirect(url_for('admin_reports'))

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

