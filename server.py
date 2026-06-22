#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
企业AI应用与技能需求调查问卷 - 后端服务 v2.7
Flask + SQLite + gunicorn，前后端分离，管理后台独立
支持云端部署：Render.com / Railway / any PaaS
v2.7: 云部署适配（PORT环境变量、gunicorn支持、GPG密钥安全优化）
"""

import os
import json
import hashlib
import sqlite3
import secrets
import time
from collections import defaultdict
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory

# 应用根目录（兼容本地开发和云端gunicorn部署）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# 管理员密码 - SHA256哈希存储
ADMIN_PASSWORD_HASH = '6051fc84a7a0d74c225fb18a496b09952da5642e60723ecae543298edd7d82d6'
ADMIN_TOKEN = secrets.token_hex(32)

# 数据库路径（云端部署用 /tmp，本地开发用当前目录）
_DB_DIR = '/tmp' if 'RENDER' in os.environ else os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(_DB_DIR, 'survey.db')

# ===== 速率限制 =====
_login_attempts = {}  # {ip: [(timestamp, ...)]}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 60


def check_login_rate(ip):
    """检查登录速率，返回 (allowed: bool, wait_seconds: int)"""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # 清理过期记录
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SEC]
    _login_attempts[ip] = attempts

    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        wait = int(LOGIN_WINDOW_SEC - (now - attempts[0]))
        return False, max(wait, 1)
    return True, 0


def record_login_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())


# ===== B1跳过选项标记 =====
B1_SKIP_VALUE = 'I. 尚未应用任何AI技术'
# 被B1跳过的题目
B1_SKIPPED_QUESTIONS = {'B2', 'B3', 'B4', 'B5', 'B6', 'B7'}

# ===== 字段中文名称映射 =====
FIELD_CN_NAMES = {
    'A1': '企业所属行业', 'A2': '企业规模', 'A3': '企业经营状况',
    'A4': '企业员工人数', 'A5': 'AI相关投入占比', 'A6': 'AI投入变化趋势',
    'A7': 'AI技术决策者', 'A8': 'AI部门设置', 'A9': '技能人才短缺程度',
    'A10': '人才缺口填补周期', 'B1': 'AI技术应用领域',
    'B2': '已应用的AI技术', 'B3': '使用的AI工具/平台',
    'B4': 'AI技术应用起始时间', 'B5': 'AI相关年度投入金额',
    'B6': 'AI应用效果评估', 'B7': 'AI导入后岗位变化数量',
    'B8': '未应用AI的主要障碍', 'B9': '未来AI投入计划',
    'B10': '南通相比于长三角AI水平', 'C1': 'AI对技能需求的影响',
    'D1': '产教融合满意度', 'E1': 'AI相关政策了解程度',
}


def get_client_ip(req):
    """获取客户端真实IP（考虑反向代理）"""
    if req.headers.get('X-Forwarded-For'):
        return req.headers.get('X-Forwarded-For').split(',')[0].strip()
    if req.headers.get('X-Real-IP'):
        return req.headers.get('X-Real-IP').strip()
    return req.remote_addr or ''


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute('''
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_data TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            submit_time TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            duration_seconds INTEGER DEFAULT 0
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            expires_at TEXT NOT NULL
        )
    ''')
    # 问卷开关状态表
    db.execute('''
        CREATE TABLE IF NOT EXISTS survey_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    # 默认开启
    db.execute('''
        INSERT OR IGNORE INTO survey_config (key, value) VALUES ('survey_open', '1')
    ''')
    # 起止时间（默认为空 = 不限制）
    db.execute('''
        INSERT OR IGNORE INTO survey_config (key, value) VALUES ('start_time', '')
    ''')
    db.execute('''
        INSERT OR IGNORE INTO survey_config (key, value) VALUES ('end_time', '')
    ''')
    db.commit()
    db.close()


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_admin_token(token):
    if token != ADMIN_TOKEN:
        db = sqlite3.connect(DATABASE)
        row = db.execute(
            "SELECT * FROM admin_sessions WHERE token = ? AND expires_at > datetime('now','localtime')",
            (token,)
        ).fetchone()
        db.close()
        return row is not None
    return True


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Admin-Token', '')
        if not verify_admin_token(token):
            return jsonify({'error': '未授权访问，请先登录'}), 401
        return f(*args, **kwargs)
    return decorated


# ==================== 前端路由 ====================

@app.route('/')
def serve_survey():
    return send_from_directory(STATIC_DIR, 'index.html')


@app.route('/admin')
def serve_admin():
    return send_from_directory(STATIC_DIR, 'admin.html')


@app.route('/<path:filename>')
def serve_static(filename):
    """服务静态资源（CSS/JS/图片等），API路由优先匹配"""
    return send_from_directory(STATIC_DIR, filename)


# ==================== 问卷API ====================

def get_config_values(db):
    """从 survey_config 返回所有 key→value 的字典"""
    rows = db.execute("SELECT key, value FROM survey_config").fetchall()
    return {r[0]: r[1] for r in rows}


def is_survey_open_now(cfg):
    """根据配置判断当前是否允许提交：开关 + 时间窗口"""
    if cfg.get('survey_open', '1') != '1':
        return False, '问卷已暂停收集，请稍后再试'

    now_str = datetime.now().strftime('%Y-%m-%dT%H:%M')
    start = cfg.get('start_time', '').strip()
    end   = cfg.get('end_time',   '').strip()

    if start and now_str < start:
        return False, f'问卷尚未开放，开放时间：{start.replace("T"," ")}'
    if end and now_str > end:
        return False, f'问卷已于 {end.replace("T"," ")} 结束，感谢您的关注'

    return True, ''


@app.route('/api/survey/status', methods=['GET'])
def survey_status():
    """检查问卷是否开放（含时间窗口判断）+ 当前IP是否已提交"""
    db = sqlite3.connect(DATABASE)
    cfg = get_config_values(db)
    ok, msg = is_survey_open_now(cfg)
    start = cfg.get('start_time', '')
    end   = cfg.get('end_time',   '')

    # 检查当前IP是否已提交过
    ip = get_client_ip(request)
    already_submitted = False
    if ip:
        row = db.execute(
            "SELECT COUNT(*) FROM responses WHERE ip_address = ?", (ip,)
        ).fetchone()
        already_submitted = row[0] > 0
    db.close()

    return jsonify({
        'open': ok,
        'message': msg,
        'start_time': start,
        'end_time': end,
        'already_submitted': already_submitted
    })


# ===== 后端必填字段校验 =====
REQUIRED_A_FIELDS = ['A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10']

def validate_survey_data(data):
    """
    后端必填字段校验，防止绕过前端直接提交不完整数据。
    返回 (valid: bool, error_msg: str)
    """
    if not isinstance(data, dict):
        return False, '无效的数据格式'

    # 1) A1-A10 必填
    for field in REQUIRED_A_FIELDS:
        val = data.get(field)
        if val is None or val == '' or (isinstance(val, list) and len(val) == 0):
            name = FIELD_CN_NAMES.get(field, field)
            return False, f'"{name}"（{field}）为必填项，请作答后重新提交'

    # 2) B1 必填（决定跳题逻辑）
    b1 = data.get('B1')
    if b1 is None or (isinstance(b1, list) and len(b1) == 0) or b1 == '':
        return False, '"AI技术应用领域"（B1）为必填项，请选择后重新提交'

    # 规范化 B1 为 list
    if isinstance(b1, str):
        b1 = [b1]

    has_skip = B1_SKIP_VALUE in b1

    # 2.5) B1 排他性校验：若选了"尚未应用AI"，不应同时选其他AI技术选项
    if has_skip and len(b1) > 1:
        return False, '"尚未应用任何AI技术"为排他选项，请勿与其他AI技术同时勾选，请修改后重新提交'

    # 3) B1 跳题逻辑校验
    if has_skip:
        # 选了"尚未应用AI"，B2-B7 应跳过；B8 必填
        b8 = data.get('B8')
        if b8 is None or (isinstance(b8, list) and len(b8) == 0) or b8 == '':
            return False, '您选择了"尚未应用任何AI技术"，"' + FIELD_CN_NAMES.get('B8', 'B8') + '"（B8）为必填项，请作答后重新提交'
    else:
        # 已应用AI：B3、B4、B5 必填
        for field in ['B3', 'B4', 'B5']:
            val = data.get(field)
            if val is None or val == '' or (isinstance(val, list) and len(val) == 0):
                name = FIELD_CN_NAMES.get(field, field)
                return False, f'您已选择应用AI技术，"{name}"（{field}）为必填项，请作答后重新提交'

    # 4) B9、B10 必填（不论是否跳题）
    for field in ['B9', 'B10']:
        val = data.get(field)
        if val is None or val == '' or (isinstance(val, list) and len(val) == 0):
            name = FIELD_CN_NAMES.get(field, field)
            return False, f'"{name}"（{field}）为必填项，请作答后重新提交'

    # 5) C 节核心题校验
    c1 = data.get('C1')
    if c1 is None or (isinstance(c1, list) and len(c1) == 0) or c1 == '':
        return False, '"AI对技能需求的影响"（C1）为必填项，请作答后重新提交'

    # 6) D 节核心题校验
    d1 = data.get('D1')
    if d1 is None or d1 == '':
        return False, '"产教融合满意度"（D1）为必填项，请作答后重新提交'

    # 7) E 节核心题校验
    e1 = data.get('E1')
    if e1 is None or e1 == '':
        return False, '"AI相关政策了解程度"（E1）为必填项，请作答后重新提交'

    # 8) duration 校验
    duration = data.get('_duration', 0)
    if not isinstance(duration, (int, float)) or duration < 0:
        data['_duration'] = 0

    return True, ''


# ===== 健康检查（无需认证，用于监控和启动验证）=====
@app.route('/api/health', methods=['GET'])
def health_check():
    """服务器健康检查端点，返回服务状态和数据库状态"""
    import platform
    try:
        db = sqlite3.connect(DATABASE)
        total = db.execute('SELECT COUNT(*) FROM responses').fetchone()[0]
        db_is_open = get_config_values(db).get('survey_open', True)
        db.close()
        return jsonify({
            'status': 'ok',
            'service': '企业AI应用与技能需求调查问卷系统',
            'version': 'v2.7',
            'database': 'connected',
            'total_responses': total,
            'survey_open': db_is_open,
            'server_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'python_version': platform.python_version()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/survey/submit', methods=['POST'])
def submit_survey():
    """提交问卷数据 - 无需登录"""
    # 检查问卷开关 + 时间窗口
    db_check = sqlite3.connect(DATABASE)
    cfg = get_config_values(db_check)
    ok, msg = is_survey_open_now(cfg)
    if not ok:
        db_check.close()
        return jsonify({'error': msg}), 403

    # 检查IP是否已提交过
    ip = get_client_ip(request)
    if ip:
        row = db_check.execute(
            "SELECT COUNT(*) FROM responses WHERE ip_address = ?", (ip,)
        ).fetchone()
        if row[0] > 0:
            db_check.close()
            return jsonify({'error': '您已提交过问卷，每人仅可提交一次，感谢您的参与！'}), 409
    db_check.close()

    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400

        # 后端必填字段校验
        valid, err_msg = validate_survey_data(data)
        if not valid:
            return jsonify({'error': f'数据校验失败：{err_msg}'}), 400

        response_data = json.dumps(data, ensure_ascii=False)
        ua = request.headers.get('User-Agent', '')[:500]
        duration = data.get('_duration', 0)

        db = get_db()
        db.execute(
            "INSERT INTO responses (response_data, ip_address, user_agent, duration_seconds) VALUES (?, ?, ?, ?)",
            (response_data, ip, ua, duration)
        )
        db.commit()

        return jsonify({'success': True, 'message': '提交成功，感谢您的参与！'})
    except Exception as e:
        return jsonify({'error': f'提交失败: {str(e)}'}), 500


# ==================== 管理API ====================

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """管理员登录（含速率限制）"""
    ip = get_client_ip(request)

    allowed, wait = check_login_rate(ip)
    if not allowed:
        return jsonify({'error': f'登录尝试过于频繁，请{wait}秒后再试'}), 429

    data = request.get_json(force=True)
    password = data.get('password', '')

    if hash_password(password) != ADMIN_PASSWORD_HASH:
        record_login_attempt(ip)
        return jsonify({'error': '密码错误'}), 401

    # 创建session
    session_token = secrets.token_hex(32)
    db = sqlite3.connect(DATABASE)
    db.execute(
        "INSERT INTO admin_sessions (token, expires_at) VALUES (?, datetime('now','localtime','+24 hours'))",
        (session_token,)
    )
    db.commit()
    db.close()

    # 清除该IP的登录尝试记录
    _login_attempts.pop(ip, None)

    return jsonify({'success': True, 'token': session_token, 'message': '登录成功'})


@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    token = request.headers.get('X-Admin-Token', '')
    if token and token != ADMIN_TOKEN:
        db = sqlite3.connect(DATABASE)
        db.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
        db.commit()
        db.close()
    return jsonify({'success': True})


def compute_statistics(all_data):
    """计算所有题目的统计数据（处理B1跳题逻辑）"""
    stats = {}

    for response in all_data:
        # 判断该问卷是否选择了"尚未应用AI"
        b1_vals = response.get('B1', [])
        if isinstance(b1_vals, str):
            b1_vals = [b1_vals]
        has_skip = B1_SKIP_VALUE in b1_vals

        for key, value in response.items():
            if key.startswith('_'):
                continue

            # B1跳题过滤：选了"尚未应用AI"的跳过B2-B7
            if has_skip and key in B1_SKIPPED_QUESTIONS:
                continue

            if key not in stats:
                stats[key] = {'counts': {}, 'total_responses': 0}

            stats[key]['total_responses'] += 1

            if isinstance(value, list):
                for v in value:
                    clean_v = v.strip() if isinstance(v, str) else str(v)
                    stats[key]['counts'][clean_v] = stats[key]['counts'].get(clean_v, 0) + 1
            elif isinstance(value, str):
                clean_v = value.strip()
                if clean_v:
                    stats[key]['counts'][clean_v] = stats[key]['counts'].get(clean_v, 0) + 1

    return {'sections': stats}


@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def get_stats():
    """获取统计数据"""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM responses").fetchone()[0]

    if total == 0:
        return jsonify({'total': 0, 'sections': {}, 'summary': {}, 'raw_responses': []})

    # 概要指标
    today_count = db.execute(
        "SELECT COUNT(*) FROM responses WHERE date(submit_time) = date('now','localtime')"
    ).fetchone()[0]
    avg_duration = db.execute(
        "SELECT AVG(duration_seconds) FROM responses WHERE duration_seconds > 0"
    ).fetchone()[0] or 0
    latest_time = db.execute(
        "SELECT submit_time FROM responses ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]

    # 获取最近200条原始数据用于查看
    rows = db.execute(
        "SELECT id, response_data, submit_time, duration_seconds FROM responses ORDER BY id DESC LIMIT 200"
    ).fetchall()

    raw_responses = []
    for row in rows:
        raw_responses.append({
            'id': row['id'],
            'data': json.loads(row['response_data']),
            'submit_time': row['submit_time'],
            'duration': row['duration_seconds']
        })

    # 汇总统计
    all_data = []
    all_rows = db.execute("SELECT response_data FROM responses").fetchall()
    for row in all_rows:
        all_data.append(json.loads(row['response_data']))

    stats = compute_statistics(all_data)
    stats['total'] = total
    stats['summary'] = {
        'today_count': today_count,
        'avg_duration': round(avg_duration),
        'latest_time': latest_time
    }
    stats['raw_responses'] = raw_responses

    return jsonify(stats)


@app.route('/api/admin/trend', methods=['GET'])
@require_admin
def get_trend():
    """获取每日提交趋势"""
    db = get_db()
    rows = db.execute('''
        SELECT date(submit_time) as day, COUNT(*) as cnt
        FROM responses
        GROUP BY day
        ORDER BY day ASC
    ''').fetchall()

    trend = [{'date': r['day'], 'count': r['cnt']} for r in rows] if rows else []
    # 计算累计
    cumulative = 0
    for t in trend:
        cumulative += t['count']
        t['cumulative'] = cumulative

    return jsonify({'trend': trend})


@app.route('/api/admin/cross', methods=['GET'])
@require_admin
def get_cross_analysis():
    """
    交叉分析：AI应用率 × 企业规模
    返回每个规模分组中应用了AI的企业数和总数
    """
    db = get_db()
    all_rows = db.execute("SELECT response_data FROM responses").fetchall()

    # 规模分组统计
    size_groups = defaultdict(lambda: {'total': 0, 'has_ai': 0})

    for row in all_rows:
        data = json.loads(row['response_data'])
        size = data.get('A2', '')
        if not size:
            continue

        # 简化规模标签
        if '2000万元及以上' in size or '规上' in size:
            key = '规上企业'
        elif '1000-2000万元' in size:
            key = '1000-2000万'
        elif '500-1000万元' in size:
            key = '500-1000万'
        elif '500万元以下' in size:
            key = '500万以下'
        else:
            key = size[:10]

        size_groups[key]['total'] += 1

        b1 = data.get('B1', [])
        if isinstance(b1, str):
            b1 = [b1]
        if B1_SKIP_VALUE not in b1:
            size_groups[key]['has_ai'] += 1

    result = []
    for label in ['500万以下', '500-1000万', '1000-2000万', '规上企业']:
        if label in size_groups:
            g = size_groups[label]
            result.append({
                'label': label,
                'total': g['total'],
                'has_ai': g['has_ai'],
                'rate': round(g['has_ai'] / g['total'] * 100) if g['total'] > 0 else 0
            })

    # 行业 × AI应用
    industry_groups = defaultdict(lambda: {'total': 0, 'has_ai': 0})
    for row in all_rows:
        data = json.loads(row['response_data'])
        industry = data.get('A1', '')
        if not industry:
            continue
        # 清理标签
        industry = industry.replace('A. ', '').replace('B. ', '').replace('C. ', '').replace('D. ', '').replace('E. ', '').replace('F. ', '').replace('G. ', '').replace('H. ', '')
        industry_groups[industry]['total'] += 1

        b1 = data.get('B1', [])
        if isinstance(b1, str):
            b1 = [b1]
        if B1_SKIP_VALUE not in b1:
            industry_groups[industry]['has_ai'] += 1

    industry_result = []
    for ind, g in sorted(industry_groups.items(), key=lambda x: x[1]['total'], reverse=True):
        industry_result.append({
            'label': ind,
            'total': g['total'],
            'has_ai': g['has_ai'],
            'rate': round(g['has_ai'] / g['total'] * 100) if g['total'] > 0 else 0
        })

    return jsonify({
        'by_size': result,
        'by_industry': industry_result
    })


@app.route('/api/admin/status', methods=['GET'])
@require_admin
def get_survey_status():
    """获取问卷开关状态及时间计划"""
    db = sqlite3.connect(DATABASE)
    cfg = get_config_values(db)
    db.close()
    ok, _ = is_survey_open_now(cfg)
    return jsonify({
        'open': cfg.get('survey_open', '1') == '1',
        'effective_open': ok,
        'start_time': cfg.get('start_time', ''),
        'end_time':   cfg.get('end_time',   '')
    })


@app.route('/api/admin/status', methods=['POST'])
@require_admin
def set_survey_status():
    """设置问卷开关状态（仅手动开关，不影响时间计划）"""
    data = request.get_json(force=True)
    is_open = '1' if data.get('open', True) else '0'

    db = sqlite3.connect(DATABASE)
    db.execute("INSERT OR REPLACE INTO survey_config (key, value) VALUES ('survey_open', ?)", (is_open,))
    db.commit()
    cfg = get_config_values(db)
    db.close()

    ok, _ = is_survey_open_now(cfg)
    return jsonify({
        'success': True,
        'open': is_open == '1',
        'effective_open': ok
    })


@app.route('/api/admin/schedule', methods=['GET'])
@require_admin
def get_schedule():
    """获取当前时间计划"""
    db = sqlite3.connect(DATABASE)
    cfg = get_config_values(db)
    db.close()
    return jsonify({
        'start_time': cfg.get('start_time', ''),
        'end_time':   cfg.get('end_time',   '')
    })


@app.route('/api/admin/schedule', methods=['POST'])
@require_admin
def set_schedule():
    """设置问卷起止时间（传空字符串表示不限制）"""
    data = request.get_json(force=True)
    start = data.get('start_time', '').strip()
    end   = data.get('end_time',   '').strip()

    # 格式校验：允许空串或 YYYY-MM-DDTHH:MM 格式
    import re
    pat = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$'
    if start and not re.match(pat, start):
        return jsonify({'error': '开始时间格式有误，请使用 YYYY-MM-DDTHH:MM'}), 400
    if end and not re.match(pat, end):
        return jsonify({'error': '结束时间格式有误，请使用 YYYY-MM-DDTHH:MM'}), 400
    if start and end and start >= end:
        return jsonify({'error': '结束时间必须晚于开始时间'}), 400

    db = sqlite3.connect(DATABASE)
    db.execute("INSERT OR REPLACE INTO survey_config (key, value) VALUES ('start_time', ?)", (start,))
    db.execute("INSERT OR REPLACE INTO survey_config (key, value) VALUES ('end_time',   ?)", (end,))
    db.commit()
    db.close()

    return jsonify({
        'success': True,
        'start_time': start,
        'end_time': end,
        'message': '时间计划已保存'
    })


@app.route('/api/admin/reset', methods=['POST'])
@require_admin
def reset_data():
    """清空所有问卷数据（危险操作，需要二次确认码）"""
    data = request.get_json(force=True)
    confirm_code = data.get('confirm', '')
    if confirm_code != 'CONFIRM_RESET':
        return jsonify({'error': '确认码错误，清空操作未执行'}), 400

    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
    db.execute("DELETE FROM responses")
    # 重置自增序列
    db.execute("DELETE FROM sqlite_sequence WHERE name='responses'")
    db.commit()

    return jsonify({
        'success': True,
        'message': f'已清空 {count} 条问卷数据，系统已还原到初始状态',
        'deleted_count': count
    })


@app.route('/api/admin/responses', methods=['GET'])
@require_admin
def get_responses():
    """获取问卷回复列表（支持搜索和筛选）"""
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    # 筛选参数
    industry = request.args.get('industry', '').strip()
    size = request.args.get('size', '').strip()
    search = request.args.get('search', '').strip()

    # 构建查询 - 需要从response_data JSON中筛选
    all_rows = db.execute(
        "SELECT id, response_data, submit_time, duration_seconds FROM responses ORDER BY id DESC"
    ).fetchall()

    # 在内存中筛选（SQLite JSON函数支持有限）
    filtered = []
    for row in all_rows:
        data = json.loads(row['response_data'])

        # 搜索：匹配任意字段
        if search:
            match = False
            for key, value in data.items():
                if key.startswith('_'):
                    continue
                val_str = '; '.join(value) if isinstance(value, list) else str(value)
                if search.lower() in val_str.lower():
                    match = True
                    break
            if not match:
                continue

        # 行业筛选
        if industry and industry not in data.get('A1', ''):
            continue

        # 规模筛选
        if size:
            a2 = data.get('A2', '')
            if size == '1' and ('规上' in a2 or '2000万元及以上' in a2):
                pass
            elif size == '2' and '1000-2000万元' in a2:
                pass
            elif size == '3' and '500-1000万元' in a2:
                pass
            elif size == '4' and '500万元以下' in a2:
                pass
            else:
                continue

        filtered.append(row)

    total = len(filtered)
    offset = (page - 1) * per_page
    page_rows = filtered[offset:offset + per_page]

    responses = []
    for row in page_rows:
        responses.append({
            'id': row['id'],
            'data': json.loads(row['response_data']),
            'submit_time': row['submit_time'],
            'duration': row['duration_seconds']
        })

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, (total + per_page - 1) // per_page),
        'items': responses
    })


@app.route('/api/admin/responses/<int:response_id>', methods=['GET'])
@require_admin
def get_response_detail(response_id):
    """获取单条问卷详情"""
    db = get_db()
    row = db.execute(
        "SELECT id, response_data, submit_time, duration_seconds, ip_address FROM responses WHERE id = ?",
        (response_id,)
    ).fetchone()

    if not row:
        return jsonify({'error': '记录不存在'}), 404

    return jsonify({
        'id': row['id'],
        'data': json.loads(row['response_data']),
        'submit_time': row['submit_time'],
        'duration': row['duration_seconds'],
        'ip': row['ip_address']
    })


@app.route('/api/admin/responses/<int:response_id>', methods=['DELETE'])
@require_admin
def delete_response(response_id):
    """删除单条问卷记录"""
    db = get_db()
    db.execute("DELETE FROM responses WHERE id = ?", (response_id,))
    db.commit()
    return jsonify({'success': True, 'message': '已删除'})


@app.route('/api/admin/export', methods=['GET'])
@require_admin
def export_data():
    """导出问卷数据为CSV"""
    db = get_db()
    rows = db.execute(
        "SELECT id, response_data, submit_time, duration_seconds FROM responses ORDER BY id ASC"
    ).fetchall()

    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)

    all_keys = set()
    parsed = []
    for row in rows:
        data = json.loads(row['response_data'])
        parsed.append(data)
        for k in data:
            if not k.startswith('_'):
                all_keys.add(k)

    sorted_keys = sorted(all_keys)
    headers = ['ID', '提交时间', '填写耗时(秒)'] + sorted_keys
    writer.writerow(headers)

    for i, (row, data) in enumerate(zip(rows, parsed)):
        row_data = [row['id'], row['submit_time'], row['duration_seconds']]
        for k in sorted_keys:
            val = data.get(k, '')
            if isinstance(val, list):
                val = '; '.join(str(v) for v in val)
            row_data.append(val)
        writer.writerow(row_data)

    csv_content = output.getvalue()
    output.close()

    from flask import Response
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=survey_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    )


@app.route('/api/admin/check', methods=['GET'])
def check_admin():
    """检查管理员token是否有效"""
    token = request.headers.get('X-Admin-Token', '')
    if verify_admin_token(token):
        return jsonify({'valid': True})
    return jsonify({'valid': False}), 401


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 8080))
    print("=" * 50)
    print("  企业AI应用与技能需求调查问卷系统 v2.7")
    print(f"  问卷地址: http://0.0.0.0:{port}/")
    print(f"  管理后台: http://0.0.0.0:{port}/admin")
    print("  管理密码: admin2026")
    print("  部署模式: " + ("云端(gunicorn)" if os.environ.get('RENDER') else "本地(Flask)"))
    print("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
