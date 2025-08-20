from __future__ import annotations

import os
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Any, Dict, List

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    abort,
)
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
from supabase import create_client, Client

# =============================================================
# Environment & App Setup
# =============================================================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32))

# Harden cookies (works on HTTPS; set SECURE only in prod if needed)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_KEY in environment")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# =============================================================
# Simple rate limiters (in-memory)
# =============================================================
# Basic sliding window limiter per IP for sensitive endpoints
_LOGIN_ATTEMPTS: Dict[str, deque] = defaultdict(deque)
_PIN_ATTEMPTS: Dict[str, deque] = defaultdict(deque)

RATE_WINDOW_SEC = 300  # 5 minutes
MAX_LOGIN_ATTEMPTS = 10
MAX_PIN_ATTEMPTS = 20

def _rate_limited(bucket: Dict[str, deque], max_events: int, window_sec: int) -> bool:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "-")
    dq = bucket[ip]
    now = time.time()
    # drop old
    while dq and (now - dq[0] > window_sec):
        dq.popleft()
    # check
    if len(dq) >= max_events:
        return True
    dq.append(now)
    return False

# =============================================================
# Helpers
# =============================================================
# ⬇️ อนุญาตเฉพาะฟิลด์เหล่านี้ (ไม่มี vip และเพิ่ม profile)
SAFE_CUSTOMER_FIELDS = {"name", "phone", "birthMonth", "note", "profile"}

def login_required(view_func):
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

def normalize_opd(opd: Any) -> str:
    if opd is None:
        return ""
    return str(opd).strip().zfill(4)

def safe_date_str(d: Any) -> str:
    # Expect 'YYYY-MM-DD...' and keep first 10 chars
    if not d:
        return ""
    return str(d)[:10]

# --- NEW: sanitize helper — แปลง -, – , — ให้เป็นค่าว่าง ---
def _clean_dash(v):
    if v is None:
        return None
    s = str(v).strip()
    return "" if s in {"-", "–", "—"} else s

# =============================================================
# Auth Views
# =============================================================
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if _rate_limited(_LOGIN_ATTEMPTS, MAX_LOGIN_ATTEMPTS, RATE_WINDOW_SEC):
            error = 'พยายามเข้าสู่ระบบถี่เกินไป กรุณารอสักครู่'
            return render_template('login.html', error=error), 429

        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()

        try:
            result = supabase.table("users").select("*").eq("username", username).single().execute()
            user = result.data
            if user:
                stored = user.get('password_hash') or ''
                ok = False
                try:
                    # supports werkzeug hash e.g. pbkdf2:sha256:...
                    ok = check_password_hash(stored, password)
                except Exception:
                    ok = False
                # Fallback for legacy plain-text (encourage migrating to hashes)
                if ok or stored == password:
                    session.permanent = True
                    session['username'] = user.get('username', username)
                    session['role'] = user.get('role', '')
                    return redirect(url_for('dashboard'))
            error = 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
        except Exception:
            error = 'เกิดข้อผิดพลาดในการเชื่อมต่อกับระบบ'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/pin-login', methods=['POST'])
def pin_login():
    if _rate_limited(_PIN_ATTEMPTS, MAX_PIN_ATTEMPTS, RATE_WINDOW_SEC):
        return jsonify({"success": False, "error": "too_many_requests"}), 429
    data = request.get_json(silent=True) or {}
    pin = (data.get('pin') or '').strip()
    try:
        result = supabase.table("users").select("*").eq("pin", pin).single().execute()
        user = result.data
        if user:
            session.permanent = True
            session['username'] = user.get('username')
            session['role'] = user.get('role', '')
            return jsonify({"success": True})
        return jsonify({"success": False})
    except Exception as e:
        app.logger.error(f"PIN LOGIN ERROR: {e}")
        return jsonify({"success": False})

# =============================================================
# Page Views (UI)
# =============================================================
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'], role=session.get('role', ''))

@app.route('/record_sales')
@login_required
def record_sales():
    return render_template('record_sales.html')

@app.route('/sale_summary')
@login_required
def sale_summary():
    return render_template('sale-summary.html')

@app.route('/record_customer')
@login_required
def record_customer():
    return render_template('record_customer.html')

@app.route('/customer_list')
@login_required
def customer_list():
    return render_template('customer_list.html')

@app.route('/oldsaledata')
@login_required
def oldsaledata():
    return render_template('oldsaledata.html')

@app.route('/inventory')
@login_required
def inventory():
    return render_template('inventory.html')

@app.route('/appointments')
@login_required
def appointments():
    return render_template('appointments.html')

@app.route('/sales_chart')
@login_required
def sales_chart():
    return render_template('sales_chart.html')

@app.route('/daily_sales_graph')
@login_required
def daily_sales_graph():
    return render_template('daily_sales_graph.html')

@app.route('/crm')
@login_required
def crm():
    return render_template('crm.html')

@app.route('/staff')
@login_required
def staff():
    return render_template('staff.html')

# =============================================================
# API — Sales & Customers
# =============================================================
@app.route('/api/test')
def test_route():
    return jsonify({"status": "ok"})

@app.route('/api/customers')
@login_required
def api_customers():
    """
    ดึงลูกค้าทั้งหมด + แนบฟิลด์จากวิวสรุป Sales Pitch:
      - sales_pitch_compact  : ล่าสุด 2 รายการ (สำหรับโชว์ในตาราง)
      - sales_pitch_full     : รวมทั้งหมด (แสดงใน modal)
      - pitch_count          : จำนวนรายการทั้งหมด
    """
    try:
        # 1) customers
        cust_res = supabase.table("customers").select("*").execute()
        customers = cust_res.data or []

        # 2) pitch latest 2 (compact)
        lat_res = supabase.table("v_customer_pitch_latest2").select("*").execute()
        latest_map: Dict[str, str] = {}
        for r in lat_res.data or []:
            latest_map[str(r.get("opd") or "")] = r.get("pitch_latest2") or ""

        # 3) full summary (all)
        sum_res = supabase.table("v_customer_pitch_summary").select("*").execute()
        summary_map: Dict[str, Dict[str, Any]] = {}
        for r in sum_res.data or []:
            summary_map[str(r.get("opd") or "")] = {
                "pitch_summary": r.get("pitch_summary") or "",
                "pitch_count": r.get("pitch_count") or 0,
            }

        # 4) merge
        for c in customers:
            opd = str(c.get("opd") or "")
            sm = summary_map.get(opd, {})
            c["sales_pitch_compact"] = latest_map.get(opd, "")
            c["sales_pitch_full"] = sm.get("pitch_summary", "")
            c["pitch_count"] = sm.get("pitch_count", 0)

        return jsonify(customers)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/update_customer', methods=['POST'])
@login_required
def update_customer():
    data = request.get_json(force=True)
    opd = normalize_opd(data.get('opd'))
    field = (data.get('field') or '').strip()
    value = data.get('value')

    if field not in SAFE_CUSTOMER_FIELDS:
        return jsonify({"error": "field_not_allowed"}), 400

    try:
        res = supabase.table("customers").update({field: value}).eq("opd", opd).execute()
        return jsonify({"message": "อัปเดตสำเร็จ", "debug": res.data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/add_customer', methods=['POST'])
@login_required
def add_customer():
    data = request.get_json(force=True)
    data = dict(data or {})
    data['opd'] = normalize_opd(data.get('opd'))
    try:
        check = supabase.table("customers").select("opd").eq("opd", data['opd']).execute()
        if check.data:
            return jsonify({"error": "มี OPD นี้อยู่แล้ว"}), 400
        payload = {k: v for k, v in data.items() if k in (SAFE_CUSTOMER_FIELDS | {"opd"})}
        supabase.table("customers").insert(payload).execute()
        return jsonify({"message": "เพิ่มลูกค้าสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete_customer', methods=['POST'])
@login_required
def delete_customer_legacy():
    # legacy behavior: delete sales by OPD only (keeps customer row)
    data = request.get_json(force=True)
    opd = normalize_opd(data.get('opd'))
    try:
        supabase.table("sales_records").delete().eq("opd", opd).execute()
        return jsonify({"message": "ลบสำเร็จ (เฉพาะยอดขาย)"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete_customer_and_sales', methods=['POST'])
@login_required
def delete_customer_and_sales():
    data = request.get_json(force=True)
    opd = normalize_opd(data.get('opd'))
    try:
        supabase.table('sales_records').delete().eq('opd', opd).execute()
        supabase.table('customers').delete().eq('opd', opd).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/sales')
@login_required
def api_sales():
    try:
        opd = normalize_opd(request.args.get('opd', '').strip()) if request.args.get('opd') else ''
        date = safe_date_str(request.args.get('date', '').strip()) if request.args.get('date') else ''
        q = supabase.table("sales_records").select("*")
        if opd:
            q = q.eq("opd", opd)
        if date:
            q = q.eq("date", date)
        # paginate manually (range cap)
        start = 0
        limit = 1000
        all_data: List[Dict[str, Any]] = []
        while True:
            resp = q.range(start, start + limit - 1).execute()
            batch = resp.data or []
            all_data.extend(batch)
            if len(batch) < limit:
                break
            start += limit
        for r in all_data:
            if 'item' in r:
                try:
                    r['items'] = json.loads(r['item'])
                except Exception:
                    r['items'] = []
        return jsonify(all_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/save_sales', methods=['POST'])
@login_required
def save_sales():
    # Accept a list of records. Each record may include `id` for update.
    data = request.get_json(force=True)
    if not isinstance(data, list):
        return jsonify({"error": "payload_must_be_list"}), 400

    inserted_count = 0
    updated_count = 0

    try:
        for rec in data:
            if not isinstance(rec, dict):
                # skip malformed rows
                continue
            # normalize
            date = safe_date_str(rec.get('date'))
            opd_4 = normalize_opd(rec.get('opd'))

            # upsert customers from sales info (optional fields)
            if opd_4 and rec.get('name'):
                customer_data = {
                    'opd': opd_4,
                    'name': rec.get('name', ''),
                    'phone': rec.get('phone', ''),
                    'birthMonth': rec.get('birthMonth', ''),
                    # 'vip': rec.get('vip', ''),  # ⬅️ ไม่มีแล้ว
                    'note': rec.get('note', ''),
                    'profile': rec.get('profile', ''),  # ⬅️ เพิ่ม
                }
                supabase.table('customers').upsert(customer_data, on_conflict=['opd']).execute()

            # prepare record for sales_records
            items = rec.get('items') or []
            rec_db = {
                'date': date,
                'opd': opd_4,
                'name': rec.get('name', ''),
                'phone': rec.get('phone', ''),
                'amount': rec.get('amount'),
                'payment': rec.get('payment'),
                'note': rec.get('note', ''),
                'item': json.dumps(items, ensure_ascii=False),
            }

            # UPDATE if id provided
            rec_id = rec.get('id')
            if rec_id:
                supabase.table('sales_records').update(rec_db).eq('id', rec_id).execute()
                updated_count += 1
                continue

            # Basic duplicate guard (same opd+date+amount+payment+item+note)
            dup_q = (
                supabase.table('sales_records')
                .select('id')
                .eq('opd', rec_db['opd'])
                .eq('date', rec_db['date'])
                .eq('item', rec_db['item'])
            )
            if rec_db.get('amount') is not None:
                dup_q = dup_q.eq('amount', rec_db['amount'])
            if rec_db.get('payment') is not None:
                dup_q = dup_q.eq('payment', rec_db['payment'])
            if rec_db.get('note'):
                dup_q = dup_q.eq('note', rec_db['note'])

            dup = dup_q.execute().data
            if dup:
                # skip insert if duplicate
                continue

            supabase.table('sales_records').insert(rec_db).execute()
            inserted_count += 1

        return jsonify({
            "message": "บันทึกสำเร็จ",
            "inserted": inserted_count,
            "updated": updated_count,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete_sales_record', methods=['POST'])
@login_required
def delete_sales_record():
    try:
        payload = request.get_json(force=True) or {}
        record_id = payload.get('id')
        if not record_id:
            return jsonify({"error": "Missing ID"}), 400
        supabase.table("sales_records").delete().eq("id", record_id).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cleanup_duplicates')
@login_required
def cleanup_duplicates():
    try:
        response = supabase.table("sales_records").select("*").execute()
        all_data = response.data or []
        seen: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
        for row in all_data:
            key = (row.get('opd'), safe_date_str(row.get('date')), row.get('amount'), row.get('payment'), row.get('item'), row.get('note'))
            seen[key].append(row)
        deleted = 0
        for rows in seen.values():
            if len(rows) > 1:
                # keep the first, delete the rest
                ids_to_delete = [r['id'] for r in rows[1:] if 'id' in r]
                if ids_to_delete:
                    supabase.table("sales_records").delete().in_("id", ids_to_delete).execute()
                    deleted += len(ids_to_delete)
        return jsonify({"message": f"ลบรายการซ้ำทั้งหมด {deleted} รายการเรียบร้อยแล้ว"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================
# API — Sales Pitch (NEW)
# =============================================================
@app.route('/api/pitches')
@login_required
def get_pitches():
    """ดึงรายการ pitch ทั้งหมดของลูกค้า (ล่าสุดก่อน)"""
    opd = normalize_opd(request.args.get("opd", ""))
    if not opd:
        return jsonify({"error": "missing opd"}), 400
    try:
        res = (
            supabase.table("customer_pitch_logs")
            .select("*")
            .eq("opd", opd)
            .order("created_at", desc=True)
            .execute()
        )
        return jsonify(res.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/add_pitch', methods=['POST'])
@login_required
def add_pitch():
    """เพิ่มบันทึก pitch ใหม่ (append)"""
    data = request.get_json(force=True) or {}
    opd = normalize_opd(data.get("opd"))
    content = _clean_dash(data.get("content") or "")
    channel = data.get("channel")
    outcome = data.get("outcome")
    author = session.get("username") or data.get("author")

    if not opd or content is None:
        return jsonify({"error": "opd and content required"}), 400

    try:
        ins = {
            "opd": opd,
            "content": content,
            "channel": channel,
            "outcome": outcome,
            "author": author,
        }
        if 'promotion' in data:
            ins["promotion"] = _clean_dash(data.get("promotion"))
        r = supabase.table("customer_pitch_logs").insert(ins).execute()
        row = (r.data or [{}])[0]
        return jsonify({"message": "ok", "id": row.get("id"), "created_at": row.get("created_at")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/add_pitches_bulk', methods=['POST'])
@login_required
def add_pitches_bulk():
    """
    รับหลายรายการในครั้งเดียว (batch)
    Payload: [{date:'YYYY-MM-DD', opd:'0123', promotion:'...', outcome:'...', content:'...', channel:'call'}]
    หมายเหตุ: ถ้ายังไม่ได้เพิ่มคอลัมน์ promotion ใน DB ฟิลด์นี้จะถูกละเลย (ไม่ทำให้พัง)
    """
    # ให้แน่ใจว่า to_insert มีอยู่แม้ throw ก่อน
    to_insert: List[Dict[str, Any]] = []
    try:
        rows = request.get_json(force=True)
        if not isinstance(rows, list):
            return jsonify({"error": "payload_must_be_list"}), 400

        author = session.get('username', '')

        for r in rows:
            date_str = (r.get('date') or '')[:10]
            if not date_str:
                date_str = datetime.utcnow().strftime('%Y-%m-%d')
            # ใส่เวลา 12:00 UTC เพื่อกัน timezone ตัดวัน
            created_at_iso = f"{date_str}T12:00:00Z"

            rec: Dict[str, Any] = {
                "opd": normalize_opd(r.get('opd')),
                "content": _clean_dash(r.get('content') or ''),
                "channel": r.get('channel') or None,
                "outcome": r.get('outcome') or None,
                "author": author or None,
                "created_at": created_at_iso,
            }
            # แนบ promotion เฉพาะถ้ามีใน payload
            if 'promotion' in r and r.get('promotion') is not None:
                rec["promotion"] = _clean_dash(r.get('promotion'))

            to_insert.append(rec)

        if not to_insert:
            return jsonify({"error": "empty"}), 400

        supabase.table('customer_pitch_logs').insert(to_insert).execute()
        return jsonify({"inserted": len(to_insert), "message": "ok"})
    except Exception as e:
        msg = str(e)
        if 'promotion' in msg.lower() and to_insert:
            try:
                cleaned = [{k:v for k,v in r.items() if k != 'promotion'} for r in to_insert]
                supabase.table('customer_pitch_logs').insert(cleaned).execute()
                return jsonify({"inserted": len(cleaned), "message": "ok (promotion skipped)"}), 200
            except Exception as e2:
                return jsonify({"error": str(e2)}), 500
        return jsonify({"error": msg}), 500

@app.route('/api/pitches_by_date')
@login_required
def pitches_by_date():
    """
    ดึงประวัติ Pitch ตามช่วงวัน (ใช้ created_at)
    Query:
      from=YYYY-MM-DD  to=YYYY-MM-DD
      q=keyword (optional)  outcome=...  channel=...
    Return: list of logs (เรียงใหม่→เก่า)
    """
    try:
        q_from = (request.args.get('from') or '').strip()
        q_to = (request.args.get('to') or '').strip()
        kw = (request.args.get('q') or '').strip().lower()
        outcome = (request.args.get('outcome') or '').strip()
        channel = (request.args.get('channel') or '').strip()

        if not q_from or not q_to:
            today = datetime.utcnow().strftime('%Y-%m-%d')
            q_to = q_to or today
            q_from = q_from or today

        qry = (
            supabase.table('customer_pitch_logs')
            .select('*')
            .gte('created_at', f'{q_from}T00:00:00Z')
            .lte('created_at', f'{q_to}T23:59:59Z')
            .order('created_at', desc=True)
        )
        if outcome:
            qry = qry.eq('outcome', outcome)
        if channel:
            qry = qry.eq('channel', channel)

        resp = qry.execute()
        rows = resp.data or []

        # กรอง keyword ฝั่งแอป (รวม promotion ด้วยถ้ามี)
        if kw:
            tmp = []
            for r in rows:
                s = ' '.join([
                    str(r.get('opd') or ''),
                    str(r.get('content') or ''),
                    str(r.get('outcome') or ''),
                    str(r.get('channel') or ''),
                    str(r.get('author') or ''),
                    str(r.get('promotion') or ''),
                ]).lower()
                if kw in s:
                    tmp.append(r)
            rows = tmp

        # แนบ date ช่วย (YYYY-MM-DD)
        for r in rows:
            ts = str(r.get('created_at') or '')
            r['date'] = ts[:10] if ts else None

        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== NEW: Update / Delete Pitch for inline editing =====
@app.route('/api/update_pitch', methods=['PUT'])
@login_required
def update_pitch():
    """
    อัปเดตรายการ pitch ที่บันทึกไว้แล้ว
    Body JSON: { id, promotion?, outcome?, content?, channel? }
    """
    data = request.get_json(force=True) or {}
    rec_id = data.get('id')
    if not rec_id:
        return jsonify({"error": "missing id"}), 400

    allowed = {'promotion', 'outcome', 'content', 'channel'}
    payload = {k: _clean_dash(v) for k, v in data.items() if k in allowed}

    if not payload:
        return jsonify({"error": "no_fields_to_update"}), 400

    try:
        res = supabase.table('customer_pitch_logs').update(payload).eq('id', rec_id).execute()
        if not res.data:
            return jsonify({"error": "not_found"}), 404
        return jsonify({"message": "updated", "row": res.data[0]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete_pitch', methods=['DELETE'])
@login_required
def delete_pitch():
    """
    ลบรายการ pitch
    ใช้ได้ทั้ง query string ?id=... หรือ ส่ง JSON {"id": ...}
    """
    rec_id = request.args.get('id')
    if not rec_id:
        body = request.get_json(silent=True) or {}
        rec_id = body.get('id') if isinstance(body, dict) else None
    if not rec_id:
        return jsonify({"error": "missing id"}), 400

    try:
        res = supabase.table('customer_pitch_logs').delete().eq('id', rec_id).execute()
        # Supabase จะคืน [] หากไม่มีแถวที่ลบ
        if res.data is not None and len(res.data) == 0:
            pass
        return jsonify({"message": "deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- NEW: one-off cleanup endpoint เพื่อล้างค่าขีดที่บันทึกค้างใน DB ---
@app.route('/api/cleanup_pitch_dash', methods=['POST', 'GET'])
@login_required
def cleanup_pitch_dash():
    try:
        supabase.table('customer_pitch_logs').update({'content': ''}).in_('content', ['-', '–', '—']).execute()
        supabase.table('customer_pitch_logs').update({'promotion': ''}).in_('promotion', ['-', '–', '—']).execute()
        return jsonify({"message": "cleaned"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Oldsale & Inventory (kept for compatibility)
# =============================================================
@app.route('/api/oldsaledata')
@login_required
def api_oldsaledata():
    try:
        response = supabase.table("oldsaledata").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        app.logger.error(f"ERROR loading oldsaledata: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/inventory")
@login_required
def api_inventory():
    try:
        res = supabase.table("inventory").select("*").execute()
        return jsonify(res.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/save_inventory", methods=["POST"])
@login_required
def api_save_inventory():
    data = request.get_json(force=True)
    try:
        supabase.table("inventory").insert(data).execute()
        return jsonify({"message": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================
# Main
# =============================================================
if __name__ == '__main__':
    # In production, run behind a proper WSGI server and set SESSION_COOKIE_SECURE=true
    app.run(debug=True)
