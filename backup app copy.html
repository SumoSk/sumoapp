from __future__ import annotations

import os
import re
import json
import time
import hashlib
import zipfile
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from math import isfinite
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    send_file,
)
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
from supabase import create_client, Client
from functools import wraps

# --- Libraries for New Features ---
import cloudinary
import cloudinary.uploader
import google.generativeai as genai
import requests
from PIL import Image
from io import BytesIO

# =============================================================
# Environment & App Setup
# =============================================================
# ใช้การโหลด .env แบบใหม่ที่เสถียรกว่า (Pathlib)
env_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32))

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

# --- Cloudinary Setup ---
cloudinary.config(
  cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME"),
  api_key = os.getenv("CLOUDINARY_API_KEY"),
  api_secret = os.getenv("CLOUDINARY_API_SECRET")
)

# --- Gemini Setup ---
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# =============================================================
# ✅ Helper: Save Image to Cloud (ฟังก์ชั่นสำคัญสำหรับระบบใหม่)
# =============================================================
def save_image_to_cloud(image_file):
    """
    รับไฟล์รูป -> ส่งไป Cloudinary -> คืนค่าเป็น URL
    """
    try:
        # folder='clinic_customers' คือตั้งชื่อโฟลเดอร์ใน cloud ให้เป็นระเบียบ
        upload_result = cloudinary.uploader.upload(image_file, folder="clinic_customers")
        return upload_result['secure_url']
    except Exception as e:
        print(f"Upload failed: {e}")
        return None

# =============================================================
# Simple rate limiters (in-memory)
# =============================================================
_LOGIN_ATTEMPTS: Dict[str, deque] = defaultdict(deque)
_PIN_ATTEMPTS: Dict[str, deque] = defaultdict(deque)

RATE_WINDOW_SEC = 300
MAX_LOGIN_ATTEMPTS = 10
MAX_PIN_ATTEMPTS = 20


def _rate_limited(bucket: Dict[str, deque], max_events: int, window_sec: int) -> bool:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "-")
    dq = bucket[ip]
    now = time.time()
    while dq and (now - dq[0] > window_sec):
        dq.popleft()
    if len(dq) >= max_events:
        return True
    dq.append(now)
    return False


# =============================================================
# Helpers
# =============================================================
SAFE_CUSTOMER_FIELDS = {"name", "phone", "birthMonth", "note", "profile"}


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def normalize_opd(opd: Any) -> str:
    if opd is None:
        return ""
    return str(opd).strip().zfill(4)


def safe_date_str(d: Any) -> str:
    if not d:
        return ""
    return str(d)[:10]


def _clean_dash(v):
    if v is None:
        return None
    s = str(v).strip()
    return "" if s in {"-", "–", "—"} else s


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# =============================================================
# ✅ Helpers: Bulletproof Data Handlers (จาก Code เก่าที่เสถียร)
# =============================================================
def _ensure_items(val: Any) -> Any:
    try:
        if val is None: return []
        if isinstance(val, (list, dict)): return val
        if isinstance(val, str):
            s = val.strip()
            if not s: return []
            try: return json.loads(s)
            except: return [s] 
        return []
    except Exception:
        return []

def _ensure_item_list(val: Any) -> List[Any]:
    try:
        raw = _ensure_items(val)
        if isinstance(raw, list): return raw
        if isinstance(raw, dict): return [raw]
        return []
    except Exception:
        return []

def _to_int(v: Any, default: int = 1) -> int:
    try:
        if v is None or v == "":
            return default
        return int(float(v))
    except Exception:
        return default


def _item_obj_to_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x.strip()

    if isinstance(x, dict):
        name = (x.get("name") or x.get("product") or x.get("title") or "").strip()
        category = (x.get("category") or x.get("group") or "").strip()
        qty = _to_int(x.get("qty") or x.get("quantity") or x.get("count"), default=1)

        price = x.get("price") or x.get("unit_price") or x.get("default_price")

        if category and name:
            base = f"{category} ({name})"
        else:
            base = name or category or ""

        if base and price is not None and str(price) != "":
            p = _to_int(price, default=0)
            return f"{base} - {qty} ชิ้น x {p}"
        if base:
            return f"{base} - {qty} ชิ้น"
        return ""

    try:
        return str(x)
    except Exception:
        return ""


def _coerce_items_to_text_list(val: Any) -> List[str]:
    raw = _ensure_items(val)

    if isinstance(raw, list):
        out: List[str] = []
        for it in raw:
            s = _item_obj_to_text(it)
            if s:
                out.append(s)
        return out

    if isinstance(raw, dict):
        s = _item_obj_to_text(raw)
        return [s] if s else []

    if isinstance(raw, str):
        s = raw.strip()
        return [s] if s else []

    return []


def _parse_year_from_date(date_s: str) -> Optional[int]:
    if not date_s:
        return None
    s = safe_date_str(date_s)
    if len(s) >= 4 and s[:4].isdigit():
        try:
            return int(s[:4])
        except Exception:
            return None
    return None


def _pad4(n: int) -> str:
    return str(int(n)).zfill(4)


def make_idempotency_key(
    date: Any,
    opd: Any,
    amount: Any,
    payment_method: Any,
    items: Any,
) -> str:
    opd_4 = normalize_opd(opd)
    date_s = safe_date_str(date)
    try:
        amt = float(amount)
    except Exception:
        amt = 0.0

    pm = (payment_method or "")
    items_norm = _ensure_items(items)

    canonical_items = items_norm
    try:
        if isinstance(items_norm, list):
            canonical_items = sorted(
                items_norm,
                key=lambda x: json.dumps(x, ensure_ascii=False, sort_keys=True)
                if isinstance(x, (dict, list))
                else str(x),
            )
    except Exception:
        canonical_items = items_norm

    payload = {
        "date": date_s,
        "opd": opd_4,
        "amount": round(amt, 2),
        "payment_method": str(pm),
        "items": canonical_items,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _validate_issue_payload(data: Dict[str, Any]) -> Tuple[bool, str]:
    opd = normalize_opd(data.get("opd"))
    if not opd or len(opd) != 4:
        return False, "invalid_opd"

    date_s = safe_date_str(data.get("date"))
    if not date_s:
        return False, "missing_date"
    y = _parse_year_from_date(date_s)
    if not y or y < 2000 or y > 2100:
        return False, "invalid_date"

    amt = data.get("amount")
    try:
        amt_f = float(amt)
    except Exception:
        return False, "invalid_amount"
    if amt_f <= 0:
        return False, "amount_must_be_positive"

    items = _ensure_items(data.get("items"))
    if not isinstance(items, list) or len(items) == 0:
        return False, "items_required"

    return True, ""


def _ensure_counter_row(year: int) -> None:
    try:
        existing = (
            supabase.table("receipt_counters_orig")
            .select("year,next_seq")
            .eq("year", year)
            .maybe_single()
            .execute()
        )
        if existing.data:
            return
    except Exception:
        try:
            ex2 = (
                supabase.table("receipt_counters_orig")
                .select("year,next_seq")
                .eq("year", year)
                .execute()
            )
            if ex2.data:
                return
        except Exception:
            pass

    try:
        supabase.table("receipt_counters_orig").insert({"year": year, "next_seq": 1}).execute()
    except Exception:
        return


def _next_orig_seq_atomic(year: int, max_retries: int = 10) -> int:
    _ensure_counter_row(year)

    last_err: Optional[Exception] = None
    for _ in range(max_retries):
        try:
            res = (
                supabase.table("receipt_counters_orig")
                .select("next_seq")
                .eq("year", year)
                .single()
                .execute()
            )
            curr = int(res.data.get("next_seq") or 1)

            upd = (
                supabase.table("receipt_counters_orig")
                .update({"next_seq": curr + 1})
                .eq("year", year)
                .eq("next_seq", curr)
                .execute()
            )
            if upd.data:
                return curr
        except Exception as e:
            last_err = e
            time.sleep(0.03)

    if last_err:
        raise last_err
    raise RuntimeError("failed_to_increment_counter")




def _receipt_fields_for_sale_record(date_s: str, opd_4: str, amount: Any, payment_method: Any, items: Any, status: str = "recorded") -> Dict[str, Any]:
    """Create receipt numbering fields for every saved sales record.

    RC is the original immutable number. RB is the display number and can be rebuilt
    later for neat year ordering. This helper is intentionally used by /api/save_sales
    so every sales save has a receipt/bill number even if the user does not press
    the receipt button.
    """
    year = _parse_year_from_date(date_s)
    if not year or year < 2000 or year > 2100:
        return {}

    seq = _next_orig_seq_atomic(year)
    orig_no = f"RC-{year}-{_pad4(seq)}"
    disp_no = f"RB-{year}-{_pad4(seq)}"

    try:
        amt = float(amount or 0)
    except Exception:
        amt = 0.0

    return {
        "orig_year": year,
        "orig_seq": seq,
        "orig_no": orig_no,
        "orig_issued_at": _utc_now_iso(),
        "disp_year": year,
        "disp_seq": seq,
        "disp_no": disp_no,
        "receipt_status": status or "recorded",
        "idempotency_key": make_idempotency_key(
            date=date_s,
            opd=opd_4,
            amount=amt,
            payment_method=payment_method,
            items=items,
        ),
    }


def _sale_row_has_receipt_no(row: Dict[str, Any]) -> bool:
    return bool((row or {}).get("orig_no") or (row or {}).get("disp_no"))


def _ensure_sale_row_receipt_number(row: Dict[str, Any], status: str = "recorded") -> Dict[str, Any]:
    """If an old row has no receipt/bill number, assign one safely.

    Existing RC/RB numbers are never overwritten here. RB ordering can be rebuilt
    separately with /api/rebuild_display_receipts.
    """
    if not row or not row.get("id") or _sale_row_has_receipt_no(row):
        return row or {}

    date_s = safe_date_str(row.get("date"))
    opd_4 = normalize_opd(row.get("opd"))
    raw_items = row.get("item") if row.get("item") is not None else row.get("items")
    items = _coerce_items_to_text_list(raw_items)
    fields = _receipt_fields_for_sale_record(
        date_s=date_s,
        opd_4=opd_4,
        amount=row.get("amount"),
        payment_method=row.get("payment"),
        items=items,
        status=status or row.get("receipt_status") or "recorded",
    )
    if not fields:
        return row

    supabase.table("sales_records").update(fields).eq("id", row.get("id")).execute()
    out = dict(row)
    out.update(fields)
    return out


def _fetch_sales_rows_by_date_range(start_date: str, end_date: str) -> List[Dict[str, Any]]:
    q = (
        supabase.table("sales_records")
        .select("*")
        .gte("date", start_date)
        .lte("date", end_date)
        .order("date", desc=False)
        .order("created_at", desc=False)
    )
    all_rows: List[Dict[str, Any]] = []
    start = 0
    limit = 1000
    while True:
        resp = q.range(start, start + limit - 1).execute()
        batch = resp.data or []
        all_rows.extend(batch)
        if len(batch) < limit:
            break
        start += limit
    return all_rows


def _receipt_range_bounds(range_key: str) -> Tuple[str, str, str]:
    today = datetime.now().date()
    key = (range_key or "today").strip().lower()

    if key == "year":
        start_d = today.replace(month=1, day=1)
        end_d = today.replace(month=12, day=31)
        label = f"ปี {today.year}"
    elif key == "month":
        start_d = today.replace(day=1)
        if today.month == 12:
            end_d = today.replace(month=12, day=31)
        else:
            next_month = today.replace(month=today.month + 1, day=1)
            end_d = next_month - timedelta(days=1)
        label = f"เดือน {today.month:02d}/{today.year}"
    else:
        start_d = today
        end_d = today
        label = "วันนี้"

    return start_d.isoformat(), end_d.isoformat(), label

# =============================================================
# Auth Views
# =============================================================
@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if _rate_limited(_LOGIN_ATTEMPTS, MAX_LOGIN_ATTEMPTS, RATE_WINDOW_SEC):
            error = "พยายามเข้าสู่ระบบถี่เกินไป กรุณารอสักครู่"
            return render_template("login.html", error=error), 429

        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        try:
            result = (
                supabase.table("users")
                .select("*")
                .eq("username", username)
                .single()
                .execute()
            )
            user = result.data
            if user:
                stored = user.get("password_hash") or ""
                ok = False
                try:
                    ok = check_password_hash(stored, password)
                except Exception:
                    ok = False

                if ok or stored == password:
                    session.permanent = True
                    session["username"] = user.get("username", username)
                    session["role"] = user.get("role", "")
                    return redirect(url_for("dashboard"))
            error = "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
        except Exception:
            error = "เกิดข้อผิดพลาดในการเชื่อมต่อกับระบบ"

    return render_template("login.html", error=error)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/pin-login", methods=["POST"])
def pin_login():
    if _rate_limited(_PIN_ATTEMPTS, MAX_PIN_ATTEMPTS, RATE_WINDOW_SEC):
        return jsonify({"success": False, "error": "too_many_requests"}), 429

    data = request.get_json(silent=True) or {}
    pin = (data.get("pin") or "").strip()
    try:
        result = supabase.table("users").select("*").eq("pin", pin).single().execute()
        user = result.data
        if user:
            session.permanent = True
            session["username"] = user.get("username")
            session["role"] = user.get("role", "")
            return jsonify({"success": True})
        return jsonify({"success": False})
    except Exception as e:
        app.logger.error(f"PIN LOGIN ERROR: {e}")
        return jsonify({"success": False})


# =============================================================
# Page Views (UI)
# =============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html", username=session["username"], role=session.get("role", "")
    )


@app.route("/record_sales")
@login_required
def record_sales():
    return render_template("record_sales.html")


@app.route("/sale_summary")
@login_required
def sale_summary():
    return render_template("sale-summary.html")


@app.route("/record_customer")
@login_required
def record_customer():
    return render_template("record_customer.html")


@app.route("/customer_list")
@login_required
def customer_list():
    return render_template("customer_list.html")


@app.route("/oldsaledata")
@login_required
def oldsaledata():
    return render_template("oldsaledata.html")


@app.route("/inventory")
@login_required
def inventory():
    return render_template("inventory.html")


@app.route("/appointments")
@login_required
def appointments():
    return render_template("appointments.html")


@app.route("/sales_chart")
@login_required
def sales_chart():
    return render_template("sales_chart.html")


@app.route("/daily_sales_graph")
@login_required
def daily_sales_graph():
    return render_template("daily_sales_graph.html")


@app.route("/crm")
@login_required
def crm():
    return render_template("crm.html")


@app.route("/staff")
@login_required
def staff():
    return render_template("staff.html")


@app.route("/tax")
@login_required
def tax_page():
    return render_template("tax.html", username=session["username"])


@app.route("/appsettings")
@login_required
def appsettings():
    return render_template(
        "appsettings.html",
        username=session.get("username"),
        role=session.get("role", ""),
    )

@app.route("/tax2")
@login_required
def tax2_page():
    return render_template("tax2.html", username=session["username"])


@app.route("/api/update_customer_global", methods=["POST"])
@login_required
def update_customer_global():
    data = request.get_json(force=True)
    old_opd = normalize_opd(data.get("old_opd"))
    new_opd = normalize_opd(data.get("new_opd"))
    name = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()

    if not old_opd or not new_opd:
        return jsonify({"error": "missing_opd"}), 400

    try:
        # ถ้าเปลี่ยนเลข OPD ต้องเช็กก่อนว่าเลขใหม่มีคนใช้ไปหรือยัง
        if old_opd != new_opd:
            check = supabase.table("customers").select("opd").eq("opd", new_opd).execute()
            if check.data:
                return jsonify({"error": f"เลข OPD ใหม่ ({new_opd}) มีในระบบแล้ว กรุณาใช้เลขอื่น"}), 400

        # 1. อัปเดตในตาราง customers
        supabase.table("customers").update({
            "opd": new_opd,
            "name": name,
            "phone": phone
        }).eq("opd", old_opd).execute()

        # 2. อัปเดตในตาราง sales_records ทุกใบ
        supabase.table("sales_records").update({
            "opd": new_opd,
            "name": name,
            "phone": phone
        }).eq("opd", old_opd).execute()

        return jsonify({"message": "อัปเดตข้อมูลลูกค้าและบิลย้อนหลังเรียบร้อยแล้ว"})
    
    except Exception as e:
        app.logger.error(f"Global Update Error: {e}")
        return jsonify({"error": str(e)}), 500
# =============================================================
# API — Health
# =============================================================
@app.route("/api/test")
def test_route():
    return jsonify({"status": "ok"})


# =============================================================
# API — Customers
# =============================================================
@app.route("/api/customers")
@login_required
def api_customers():
    try:
        cust_res = supabase.table("customers").select("*").execute()
        customers = cust_res.data or []

        lat_res = supabase.table("v_customer_pitch_latest2").select("*").execute()
        latest_map: Dict[str, str] = {}
        for r in lat_res.data or []:
            latest_map[str(r.get("opd") or "")] = r.get("pitch_latest2") or ""

        sum_res = supabase.table("v_customer_pitch_summary").select("*").execute()
        summary_map: Dict[str, Dict[str, Any]] = {}
        for r in sum_res.data or []:
            summary_map[str(r.get("opd") or "")] = {
                "pitch_summary": r.get("pitch_summary") or "",
                "pitch_count": r.get("pitch_count") or 0,
            }

        for c in customers:
            opd = str(c.get("opd") or "")
            sm = summary_map.get(opd, {})
            c["sales_pitch_compact"] = latest_map.get(opd, "")
            c["sales_pitch_full"] = sm.get("pitch_summary", "")
            c["pitch_count"] = sm.get("pitch_count", 0)

        return jsonify(customers)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/update_customer", methods=["POST"])
@login_required
def update_customer():
    data = request.get_json(force=True)
    opd = normalize_opd(data.get("opd"))
    field = (data.get("field") or "").strip()
    value = data.get("value")

    if field not in SAFE_CUSTOMER_FIELDS:
        return jsonify({"error": "field_not_allowed"}), 400

    try:
        res = supabase.table("customers").update({field: value}).eq("opd", opd).execute()
        return jsonify({"message": "อัปเดตสำเร็จ", "debug": res.data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/add_customer", methods=["POST"])
@login_required
def add_customer():
    data = request.get_json(force=True)
    data = dict(data or {})
    data["opd"] = normalize_opd(data.get("opd"))
    try:
        check = supabase.table("customers").select("opd").eq("opd", data["opd"]).execute()
        if check.data:
            return jsonify({"error": "มี OPD นี้อยู่แล้ว"}), 400
        payload = {k: v for k, v in data.items() if k in (SAFE_CUSTOMER_FIELDS | {"opd"})}
        supabase.table("customers").insert(payload).execute()
        return jsonify({"message": "เพิ่มลูกค้าสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/add_customer_full", methods=["POST"])
@login_required
def add_customer_full():
    try:
        data = request.get_json(force=True) or {}
        opd = normalize_opd(data.get("opd"))
        
        if not opd or len(opd) != 4:
            return jsonify({"error": "invalid_opd"}), 400

        check = supabase.table("customers").select("opd").eq("opd", opd).execute()
        if check.data:
            return jsonify({"error": "duplicate_opd", "message": "มีเลข OPD นี้ในระบบแล้ว"}), 400

        payload = {
            "opd": opd,
            "name": (data.get("name") or "").strip() or None,
            "full_name": (data.get("full_name") or "").strip() or None,
            "phone": (data.get("phone") or "").strip() or None,
            "birthMonth": (data.get("birthMonth") or "").strip().zfill(2) if data.get("birthMonth") else None,
            "birth_th_ddmmyyyy": (data.get("birth_th_ddmmyyyy") or "").strip() or None,
            "facebook_name": (data.get("facebook_name") or "").strip() or None,
            "national_id": (data.get("national_id") or "").strip() or None,
            "vip": (data.get("vip") or "").strip() or None,
            "address": (data.get("address") or "").strip() or None,
            "profile": (data.get("profile") or "").strip() or None,
            "note": (data.get("note") or "").strip() or None
        }

        supabase.table("customers").insert(payload).execute()
        return jsonify({"message": "เพิ่มลูกค้าสำเร็จ"})

    except Exception as e:
        app.logger.error(f"Error add_customer_full: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/update_customer_patch", methods=["POST"])
@login_required
def update_customer_patch():
    try:
        data = request.get_json(force=True) or {}
        opd = normalize_opd(data.get("opd"))
        patch = data.get("patch") or {}

        if not opd:
            return jsonify({"error": "missing_opd"}), 400
        if not patch:
            return jsonify({"message": "nothing_to_update"}), 200

        clean_patch = {}
        allowed_fields = {
            "name", "full_name", "phone", "birthMonth", "birth_th_ddmmyyyy",
            "facebook_name", "national_id", "vip", "address", "profile", "note"
        }

        for k, v in patch.items():
            if k in allowed_fields:
                if isinstance(v, str):
                    v = v.strip()
                    if v == "": v = None
                clean_patch[k] = v

        if not clean_patch:
            return jsonify({"message": "no_valid_fields"}), 200

        supabase.table("customers").update(clean_patch).eq("opd", opd).execute()
        return jsonify({"message": "อัปเดตข้อมูลสำเร็จ"})

    except Exception as e:
        app.logger.error(f"Error update_customer_patch: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_customer", methods=["POST"])
@login_required
def delete_customer():
    data = request.get_json(force=True) or {}
    opd = normalize_opd(data.get("opd"))
    if not opd:
        return jsonify({"error": "missing_opd"}), 400
    try:
        supabase.table("sales_records").delete().eq("opd", opd).execute()
        supabase.table("customers").delete().eq("opd", opd).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_customer_sales_only", methods=["POST"])
@login_required
def delete_customer_sales_only():
    data = request.get_json(force=True) or {}
    opd = normalize_opd(data.get("opd"))
    if not opd:
        return jsonify({"error": "missing_opd"}), 400
    try:
        supabase.table("sales_records").delete().eq("opd", opd).execute()
        return jsonify({"message": "ลบสำเร็จ (เฉพาะยอดขาย)"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_customer_and_sales", methods=["POST"])
@login_required
def delete_customer_and_sales():
    data = request.get_json(force=True) or {}
    opd = normalize_opd(data.get("opd"))
    if not opd:
        return jsonify({"error": "missing_opd"}), 400
    try:
        supabase.table("sales_records").delete().eq("opd", opd).execute()
        supabase.table("customers").delete().eq("opd", opd).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Receipt System
# =============================================================
@app.route("/api/sales_issue_receipt", methods=["POST"])
@login_required
def sales_issue_receipt():
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "invalid_payload"}), 400

        ok, err = _validate_issue_payload(data)
        if not ok:
            return jsonify({"success": False, "error": err}), 400

        date_s = safe_date_str(data.get("date"))
        year = _parse_year_from_date(date_s)
        assert year is not None

        opd_4 = normalize_opd(data.get("opd"))
        amount = float(data.get("amount"))
        items = _coerce_items_to_text_list(data.get("items"))

        payment_method = data.get("payment_method")
        if payment_method is None:
            payment_method = data.get("payment")

        idempotency_key = make_idempotency_key(
            date=date_s,
            opd=opd_4,
            amount=amount,
            payment_method=payment_method,
            items=items,
        )

        dup = (
            supabase.table("sales_records")
            .select("*")
            .eq("idempotency_key", idempotency_key)
            .not_.is_("orig_no", "null")
            .order("orig_issued_at", desc=True)
            .limit(1)
            .execute()
        ).data
        if dup:
            row = dup[0]
            # The sale was already recorded through /api/save_sales. Do not create
            # a second sales row; just mark it as issued and reuse the same number.
            try:
                update_dup = {"receipt_status": "issued"}
                if data.get("patient_info") is not None:
                    update_dup["patient_info"] = data.get("patient_info") or ""
                supabase.table("sales_records").update(update_dup).eq("id", row.get("id")).execute()
                row.update(update_dup)
            except Exception as e:
                app.logger.warning(f"Failed to mark duplicate receipt as issued: {e}")

            return jsonify(
                {
                    "success": True,
                    "id": row.get("id"),
                    "orig_no": row.get("orig_no"),
                    "disp_no": row.get("disp_no"),
                    "receipt_status": row.get("receipt_status") or "issued",
                    "idempotency_key": row.get("idempotency_key"),
                    "duplicate": True,
                }
            ), 200

        seq = _next_orig_seq_atomic(year)
        orig_no = f"RC-{year}-{_pad4(seq)}"

        insert_payload = {
            "date": date_s,
            "opd": opd_4,
            "name": data.get("name", "") or "",
            "phone": data.get("phone", "") or "",
            "amount": amount,
            "payment": payment_method,
            "note": data.get("note", "") or "",
            "item": items,
            "orig_year": year,
            "orig_seq": seq,
            "orig_no": orig_no,
            "orig_issued_at": _utc_now_iso(),
            "disp_year": year,
            "disp_seq": seq,
            "disp_no": f"RB-{year}-{_pad4(seq)}",
            "receipt_status": (data.get("receipt_status") or "issued"),
            "idempotency_key": idempotency_key,
            "patient_info": data.get("patient_info") or "",
        }

        ins = supabase.table("sales_records").insert(insert_payload).execute()
        row = (ins.data or [{}])[0]

        return jsonify(
            {
                "success": True,
                "id": row.get("id"),
                "orig_no": orig_no,
                "disp_no": row.get("disp_no"),
                "receipt_status": row.get("receipt_status") or "issued",
                "idempotency_key": idempotency_key,
            }
        ), 200

    except Exception as e:
        app.logger.error(f"/api/sales_issue_receipt error: {e}")
        return jsonify({"success": False, "error": "server_error", "detail": str(e)}), 500

@app.route("/api/rebuild_display_receipts", methods=["POST"])
@login_required
def rebuild_display_receipts():
    """Fill missing RC numbers and rebuild RB display numbers for a whole year.

    Existing RC/original numbers are preserved. Missing old sales rows get an RC
    number so every saved sale can be shown/exported as a receipt. RB/display
    numbers are then rebuilt in date order for readability.
    """
    try:
        data = request.get_json(silent=True) or {}
        year = int(data.get("year") or 0)

        if year < 2000 or year > 2100:
            return jsonify({"success": False, "error": "Invalid year"}), 400

        start_date = f"{year}-01-01"
        end_date = f"{year}-12-31"

        all_rows = _fetch_sales_rows_by_date_range(start_date, end_date)

        def sort_key(r):
            return (r.get("date") or "", r.get("created_at") or "", str(r.get("id") or ""))

        all_rows.sort(key=sort_key)

        ensured_rc = 0
        for i, row in enumerate(all_rows):
            if not _sale_row_has_receipt_no(row):
                all_rows[i] = _ensure_sale_row_receipt_number(row, status=row.get("receipt_status") or "recorded")
                ensured_rc += 1

        updated = 0
        seq = 1
        for row in all_rows:
            rid = row.get("id")
            if not rid:
                continue
            new_disp_no = f"RB-{year}-{str(seq).zfill(4)}"
            update_payload = {
                "disp_year": year,
                "disp_seq": seq,
                "disp_no": new_disp_no,
                "receipt_status": row.get("receipt_status") or "recorded",
            }
            supabase.table("sales_records").update(update_payload).eq("id", rid).execute()
            updated += 1
            seq += 1

        return jsonify({"success": True, "count": updated, "ensured_rc": ensured_rc})

    except Exception as e:
        app.logger.error(f"/api/rebuild_display_receipts error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/receipt_records_for_pdf")
@login_required
def receipt_records_for_pdf():
    """Return sales rows for bulk receipt PDF export.

    range=today|month|year. Only rows that have an RC/RB number are returned.
    New saves always have numbers; old rows can be filled by Rebuild Display.
    """
    try:
        range_key = (request.args.get("range") or "today").strip().lower()
        start_date, end_date, label = _receipt_range_bounds(range_key)

        rows = _fetch_sales_rows_by_date_range(start_date, end_date)
        out = []
        for r in rows:
            if not _sale_row_has_receipt_no(r):
                continue
            r["opd"] = normalize_opd(r.get("opd"))
            raw_item = r.get("item")
            if raw_item is None and r.get("items") is not None:
                raw_item = r.get("items")
            normalized_item_list = _ensure_item_list(raw_item)
            r["item"] = normalized_item_list
            r["items"] = _coerce_items_to_text_list(normalized_item_list)
            out.append(r)

        return jsonify({
            "success": True,
            "range": range_key,
            "label": label,
            "start_date": start_date,
            "end_date": end_date,
            "count": len(out),
            "rows": out,
        })
    except Exception as e:
        app.logger.error(f"/api/receipt_records_for_pdf error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# =============================================================
# API — Sales (IMPORTANT: Using core logic from old robust code)
# =============================================================
@app.route("/api/sales")
@login_required
def api_sales():
    try:
        opd = normalize_opd(request.args.get("opd", "").strip()) if request.args.get("opd") else ""
        date = safe_date_str(request.args.get("date", "").strip()) if request.args.get("date") else ""
        start_date = safe_date_str(request.args.get("start_date", "").strip()) if request.args.get("start_date") else ""
        end_date = safe_date_str(request.args.get("end_date", "").strip()) if request.args.get("end_date") else ""

        q = supabase.table("sales_records").select("*")
        if opd:
            q = q.eq("opd", opd)
        if date:
            q = q.eq("date", date)
        if start_date:
            q = q.gte("date", start_date)
        if end_date:
            q = q.lte("date", end_date)

        start = 0
        limit = 1000
        all_data = []
        while True:
            resp = q.range(start, start + limit - 1).execute()
            batch = resp.data or []
            all_data.extend(batch)
            if len(batch) < limit:
                break
            start += limit

        for r in all_data:
            r["opd"] = normalize_opd(r.get("opd"))

            raw_item = r.get("item")
            if raw_item is None and r.get("items") is not None:
                raw_item = r.get("items")

            normalized_item_list = _ensure_item_list(raw_item)
            r["item"] = normalized_item_list
            r["items"] = _coerce_items_to_text_list(normalized_item_list)

        return jsonify(all_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _sales_safe_float(v, default=0.0):
    try:
        if v in (None, ""):
            return default
        return float(v)
    except Exception:
        return default


def _sales_safe_int(v, default=0):
    try:
        if v in (None, ""):
            return default
        return int(float(v))
    except Exception:
        return default


def _ensure_pending_work_list(v):
    if v in (None, ""):
        return []
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except Exception:
            return []
    if not isinstance(v, list):
        return []

    out = []
    for x in v:
        if not isinstance(x, dict):
            continue
        item = (x.get("item") or x.get("name") or x.get("label") or "").strip()
        main = (x.get("main") or x.get("category") or "").strip()
        sub = (x.get("sub") or x.get("subitem") or "").strip()
        if not item:
            item = f"{main} ({sub})" if main and sub else main or sub
        qty = _sales_safe_int(x.get("qty") or x.get("quantity"), 1)
        unit = (x.get("unit") or "ครั้ง").strip() or "ครั้ง"
        note = (x.get("note") or "").strip()
        if item and qty > 0:
            out.append({"item": item, "qty": qty, "unit": unit, "note": note, "main": main, "sub": sub})
    return out


def _sync_sales_pending_summary(sale_id, rec_db, rec):
    """Keep one summary row per sales record for AR / pending work.

    This replaces the old add/pay transaction-style mirror. It stores exactly one
    row in sale_pending_summary for each sales record that has either:
      - ar_amount > 0
      - pending_work has at least one item

    No phone number is stored here. name is the short/nickname from the sales form.
    Receipt issuing is not touched by this function.
    """
    if not sale_id:
        return

    sale_id_txt = str(sale_id)

    # Always replace the summary for this sale_id so editing a queued/old record
    # cannot create duplicate pending rows.
    try:
        supabase.table("sale_pending_summary").delete().eq("sale_id", sale_id_txt).execute()
    except Exception as e:
        print(f"Warning: clear sale_pending_summary failed for sale_id={sale_id_txt}: {e}")

    opd = normalize_opd(rec_db.get("opd"))
    sale_date = safe_date_str(rec_db.get("date"))
    if not opd or not sale_date:
        return

    ar_amount = _sales_safe_float(
        rec.get("ar_amount") or rec.get("unpaid_amount") or rec_db.get("ar_amount"),
        0.0
    )
    pending = _ensure_pending_work_list(rec.get("pending_work") or rec_db.get("pending_work"))

    # Nothing pending for this sales row, so no summary row is needed.
    if not (ar_amount and ar_amount > 0) and not pending:
        return

    payload = {
        "sale_id": sale_id_txt,
        "opd": opd,
        "name": (rec_db.get("name") or rec.get("name") or "").strip(),
        "sale_date": sale_date,
        "ar_amount": float(ar_amount or 0),
        "pending_work": pending,
        "note": (rec.get("note") or rec_db.get("note") or "").strip(),
        "source": "sales_record",
    }

    supabase.table("sale_pending_summary").insert(payload).execute()

@app.route("/api/save_sales", methods=["POST"])
@login_required
def save_sales():
    data = request.get_json(force=True)
    if not isinstance(data, list):
        return jsonify({"error": "payload_must_be_list"}), 400

    inserted_count = 0
    updated_count = 0

    try:
        for rec in data:
            if not isinstance(rec, dict):
                continue

            date = safe_date_str(rec.get("date"))
            opd_4 = normalize_opd(rec.get("opd"))

            amt = rec.get("amount")
            if amt in ("", None):
                amt = None
            else:
                try:
                    amt = float(amt)
                except Exception:
                    amt = None

            # --- 1. แก้ไขจุดเสี่ยง Upsert ลูกค้า (Logic เก่าที่เสถียร) ---
            if opd_4 and rec.get("name"):
                customer_data = {
                    "opd": opd_4,
                    "name": rec.get("name", ""),
                    "phone": rec.get("phone", ""),
                }
                if rec.get("birthMonth"):
                    customer_data["birthMonth"] = rec.get("birthMonth")
                if rec.get("profile"):
                    customer_data["profile"] = rec.get("profile")
                
                try:
                    supabase.table("customers").upsert(customer_data, on_conflict=["opd"]).execute()
                except Exception as e:
                    print(f"Warning: Customer upsert failed for {opd_4}: {e}")

            items_in = rec.get("items")
            if items_in is None:
                items_in = rec.get("item")
            items = _coerce_items_to_text_list(items_in)

            ar_amount = _sales_safe_float(rec.get("ar_amount") or rec.get("unpaid_amount"), 0.0)
            pending_work = _ensure_pending_work_list(rec.get("pending_work"))

            rec_db = {
                "date": date,
                "opd": opd_4,
                "name": rec.get("name", ""),
                "phone": rec.get("phone", ""),
                "amount": amt,
                "payment": rec.get("payment"),
                "note": rec.get("note", ""),
                "item": items,
                "ar_amount": ar_amount,
                "pending_work": pending_work,
            }

            rec_id = rec.get("id")

            # --- กรณีแก้ไข (Update) ---
            if rec_id:
                existing_rows = (
                    supabase.table("sales_records")
                    .select("*")
                    .eq("id", rec_id)
                    .limit(1)
                    .execute()
                ).data or []
                existing = existing_rows[0] if existing_rows else {}

                # Old rows may not have receipt numbers yet. Give them a number once,
                # but never overwrite an existing RC/RB number during edit.
                if not _sale_row_has_receipt_no(existing):
                    rec_db.update(_receipt_fields_for_sale_record(
                        date_s=date,
                        opd_4=opd_4,
                        amount=amt or 0,
                        payment_method=rec.get("payment"),
                        items=items,
                        status=existing.get("receipt_status") or "recorded",
                    ))
                else:
                    # Keep existing status unless it is blank.
                    if not existing.get("receipt_status"):
                        rec_db["receipt_status"] = "recorded"
                    rec_db["idempotency_key"] = make_idempotency_key(
                        date=date, opd=opd_4, amount=amt or 0, payment_method=rec.get("payment"), items=items
                    )

                supabase.table("sales_records").update(rec_db).eq("id", rec_id).execute()
                _sync_sales_pending_summary(rec_id, rec_db, rec)
                updated_count += 1
                continue

            # New sale saves get receipt/bill numbers immediately, even if the user
            # never presses the receipt button.
            rec_db.update(_receipt_fields_for_sale_record(
                date_s=date,
                opd_4=opd_4,
                amount=amt or 0,
                payment_method=rec.get("payment"),
                items=items,
                status="recorded",
            ))

            # --- 2. แก้ไขจุดเสี่ยงเช็คซ้ำ (Duplicate Check) ---
            dup_q = (
                supabase.table("sales_records")
                .select("*")
                .eq("opd", rec_db["opd"])
                .eq("date", rec_db["date"])
            )
            if rec_db.get("amount") is not None:
                dup_q = dup_q.eq("amount", rec_db["amount"])
            if rec_db.get("payment") is not None:
                dup_q = dup_q.eq("payment", rec_db["payment"])
            
            if rec_db.get("note"):
                dup_q = dup_q.eq("note", rec_db["note"])

            dup = dup_q.execute().data
            if dup:
                # If the matching old row predates the receipt-number change, fill it now.
                try:
                    _ensure_sale_row_receipt_number(dup[0], status=dup[0].get("receipt_status") or "recorded")
                except Exception as e:
                    print(f"Warning: ensure receipt for duplicate failed: {e}")
                continue

            ins = supabase.table("sales_records").insert(rec_db).execute()
            inserted_rows = ins.data or []
            sale_id = inserted_rows[0].get("id") if inserted_rows else None
            _sync_sales_pending_summary(sale_id, rec_db, rec)
            inserted_count += 1

        return jsonify({"message": "บันทึกสำเร็จ", "inserted": inserted_count, "updated": updated_count})
    
    except Exception as e:
        print(f"SAVE SALES ERROR: {e}") 
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_sales_record", methods=["POST"])
@login_required
def delete_sales_record():
    try:
        payload = request.get_json(force=True) or {}
        record_id = payload.get("id")
        if not record_id:
            return jsonify({"error": "Missing ID"}), 400

        # ลบสรุปค้างชำระ/ค้างทำที่ผูกกับบิลนี้ก่อน แล้วค่อยลบบิล
        # ตารางนี้เก็บ 1 แถวต่อ 1 บิลเท่านั้น จึงไม่สร้างรายการซ้ำ
        try:
            supabase.table("sale_pending_summary").delete().eq("sale_id", str(record_id)).execute()
        except Exception as e:
            print(f"Warning: delete linked sale_pending_summary failed for sale_id={record_id}: {e}")

        # ลบได้ทุกกรณี แม้ออกใบเสร็จแล้ว
        supabase.table("sales_records").delete().eq("id", record_id).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/api/rebuild_rc_receipts", methods=["POST"])
@login_required
def rebuild_rc_receipts():
    try:
        data = request.get_json(silent=True) or {}
        year = int(data.get("year") or 0)
        if year < 2000 or year > 2100:
            return jsonify({"success": False, "error": "Invalid year"}), 400

        # (แนะนำ) จำกัดสิทธิ์เฉพาะ admin กันกดพลาด
        if (session.get("role") or "") != "admin":
            return jsonify({"success": False, "error": "forbidden"}), 403

        start_date = f"{year}-01-01"
        end_date = f"{year}-12-31"

        # ดึงรายการขายทั้งหมดในปีนั้น
        q = (
            supabase.table("sales_records")
            .select("id,date,created_at")
            .gte("date", start_date)
            .lte("date", end_date)
            .order("date", desc=False)
            .order("created_at", desc=False)
        )

        all_rows = []
        start = 0
        limit = 1000
        while True:
            resp = q.range(start, start + limit - 1).execute()
            batch = resp.data or []
            all_rows.extend(batch)
            if len(batch) < limit:
                break
            start += limit

        # PASS 1: เคลียร์ orig_no อย่างเดียวพอ (กันชน unique) — ปลอดภัยสุด (ไม่ชน NOT NULL)
        supabase.table("sales_records").update(
            {"orig_no": None}
        ).gte("date", start_date).lte("date", end_date).execute()

        # PASS 2: ใส่เลข RC ใหม่
        now_iso = _utc_now_iso()
        seq = 1

        for r in all_rows:
            rid = r.get("id")
            if not rid:
                continue

            new_no = f"RC-{year}-{str(seq).zfill(4)}"

            supabase.table("sales_records").update(
                {
                    "orig_year": year,
                    "orig_seq": seq,
                    "orig_no": new_no,
                    "orig_issued_at": now_iso,
                    "receipt_status": "issued",
                }
            ).eq("id", rid).execute()

            seq += 1

        # อัปเดต counter ให้ next_seq ต่อจากตัวล่าสุด
        supabase.table("receipt_counters_orig").upsert(
            {"year": year, "next_seq": seq},
            on_conflict="year"  # ✅ ต้องเป็น string ในหลายเวอร์ชัน
        ).execute()

        return jsonify({"success": True, "count": len(all_rows)}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/cleanup_duplicates")
@login_required
def cleanup_duplicates():
    try:
        response = supabase.table("sales_records").select("*").execute()
        all_data = response.data or []
        seen: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)

        for row in all_data:
            key = (
                row.get("opd"),
                safe_date_str(row.get("date")),
                row.get("amount"),
                row.get("payment"),
                row.get("item"),
                row.get("note"),
                row.get("orig_no") or "",
            )
            seen[key].append(row)

        deleted = 0
        for rows in seen.values():
            if len(rows) > 1:
                keep = None
                for r in rows:
                    if r.get("orig_no"):
                        keep = r
                        break
                if keep is None:
                    keep = rows[0]

                ids_to_delete = [r["id"] for r in rows if r.get("id") and r.get("id") != keep.get("id")]
                if ids_to_delete:
                    supabase.table("sales_records").delete().in_("id", ids_to_delete).execute()
                    deleted += len(ids_to_delete)

        return jsonify({"message": f"ลบรายการซ้ำทั้งหมด {deleted} รายการเรียบร้อยแล้ว"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Product Catalog
# =============================================================
@app.route("/api/products_map")
@login_required
def api_products_map():
    try:
        cats = (
            supabase.table("product_categories")
            .select("id,name,sort_order,is_active")
            .eq("is_active", True)
            .order("sort_order", desc=False)
            .order("name", desc=False)
            .execute()
        ).data or []

        cat_ids = [c["id"] for c in cats if c.get("id")]
        if not cat_ids:
            return jsonify({"map": {}, "categories": []})

        prods_q = (
            supabase.table("products")
            .select("id,name,default_price,estimated_price,estimated_unit,sort_order,category_id,is_active,deleted_at")
            .in_("category_id", cat_ids)
            .eq("is_active", True)
            .is_("deleted_at", "null")
            .order("sort_order", desc=False)
            .order("name", desc=False)
        )
        prods = (prods_q.execute().data or [])

        id_to_name = {c["id"]: c["name"] for c in cats}
        out: Dict[str, List[Dict[str, Any]]] = {c["name"]: [] for c in cats}
        for p in prods:
            cn = id_to_name.get(p.get("category_id"))
            if not cn:
                continue
            out.setdefault(cn, []).append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "default_price": p.get("default_price"),
                    "estimated_price": p.get("estimated_price"),
                    "estimated_unit": p.get("estimated_unit") or "ชิ้น",
                    "sort_order": p.get("sort_order", 0),
                }
            )

        return jsonify({"map": out, "categories": cats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/categories", methods=["GET", "POST", "PUT"])
@login_required
def api_categories():
    if request.method == "GET":
        try:
            res = (
                supabase.table("product_categories")
                .select("*")
                .order("sort_order", desc=False)
                .order("name", desc=False)
                .execute()
            )
            return jsonify(res.data or [])
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    data = request.get_json(force=True) or {}

    try:
        if request.method == "POST":
            name = (data.get("name") or "").strip()
            if not name:
                return jsonify({"error": "missing_name"}), 400
            payload = {
                "name": name,
                "sort_order": int(data.get("sort_order") or 0),
                "is_active": bool(data.get("is_active", True)),
            }
            supabase.table("product_categories").insert(payload).execute()
            return jsonify({"message": "ok"})

        if request.method == "PUT":
            cid = data.get("id")
            if not cid:
                return jsonify({"error": "missing_id"}), 400
            patch = {}
            if "name" in data:
                patch["name"] = (data.get("name") or "").strip()
            if "sort_order" in data:
                patch["sort_order"] = int(data.get("sort_order") or 0)
            if "is_active" in data:
                patch["is_active"] = bool(data.get("is_active"))
            if not patch:
                return jsonify({"error": "no_fields"}), 400
            supabase.table("product_categories").update(patch).eq("id", cid).execute()
            return jsonify({"message": "ok"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500




def _product_price_or_none(v: Any) -> Optional[float]:
    try:
        if v is None or v == "":
            return None
        n = float(v)
        if n < 0:
            n = 0.0
        return n
    except Exception:
        raise ValueError("invalid_price")


def _product_unit_clean(v: Any) -> str:
    s = str(v or "").strip()
    return s or "ชิ้น"

@app.route("/api/products", methods=["GET", "POST", "PUT", "DELETE"])
@login_required
def api_products():
    if request.method == "GET":
        try:
            res = (
                supabase.table("products")
                .select("*")
                .order("sort_order", desc=False)
                .order("name", desc=False)
                .execute()
            )
            return jsonify(res.data or [])
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    data = request.get_json(force=True) or {}

    try:
        if request.method == "POST":
            category_id = data.get("category_id")
            name = (data.get("name") or "").strip()
            if not category_id or not name:
                return jsonify({"error": "missing_category_or_name"}), 400

            dp = data.get("default_price", None)
            default_price = None
            if dp is not None and dp != "":
                try:
                    default_price = float(dp)
                except Exception:
                    return jsonify({"error": "invalid_default_price"}), 400

            try:
                estimated_price = _product_price_or_none(data.get("estimated_price"))
            except ValueError:
                return jsonify({"error": "invalid_estimated_price"}), 400

            payload = {
                "category_id": category_id,
                "name": name,
                "default_price": default_price,
                "estimated_price": estimated_price if estimated_price is not None else 0,
                "estimated_unit": _product_unit_clean(data.get("estimated_unit")),
                "sort_order": int(data.get("sort_order") or 0),
                "is_active": bool(data.get("is_active", True)),
            }
            ins = supabase.table("products").insert(payload).execute()
            row = (ins.data or [{}])[0] if getattr(ins, "data", None) else {}
            return jsonify({"message": "ok", "row": row})

        if request.method == "PUT":
            pid = data.get("id")
            if not pid:
                return jsonify({"error": "missing_id"}), 400

            patch = {}
            if "category_id" in data:
                patch["category_id"] = data.get("category_id")
            if "name" in data:
                patch["name"] = (data.get("name") or "").strip()
            if "sort_order" in data:
                patch["sort_order"] = int(data.get("sort_order") or 0)
            if "is_active" in data:
                patch["is_active"] = bool(data.get("is_active"))
            if "default_price" in data:
                dp = data.get("default_price")
                if dp is None or dp == "":
                    patch["default_price"] = None
                else:
                    try:
                        patch["default_price"] = float(dp)
                    except Exception:
                        return jsonify({"error": "invalid_default_price"}), 400

            if "estimated_price" in data:
                try:
                    ep = _product_price_or_none(data.get("estimated_price"))
                    patch["estimated_price"] = ep if ep is not None else 0
                except ValueError:
                    return jsonify({"error": "invalid_estimated_price"}), 400
            if "estimated_unit" in data:
                patch["estimated_unit"] = _product_unit_clean(data.get("estimated_unit"))

            if "deleted_at" in data:
                patch["deleted_at"] = data.get("deleted_at")

            if not patch:
                return jsonify({"error": "no_fields"}), 400

            upd = supabase.table("products").update(patch).eq("id", pid).execute()
            row = (upd.data or [{}])[0] if getattr(upd, "data", None) else {}
            return jsonify({"message": "ok", "row": row})

        if request.method == "DELETE":
            pid = data.get("id")
            if not pid:
                return jsonify({"error": "missing_id"}), 400
            supabase.table("products").update(
                {
                    "deleted_at": _utc_now_iso(),
                    "is_active": False,
                }
            ).eq("id", pid).execute()
            return jsonify({"message": "trashed"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/products_restore", methods=["POST"])
@login_required
def api_products_restore():
    data = request.get_json(force=True) or {}
    pid = data.get("id")
    if not pid:
        return jsonify({"error": "missing_id"}), 400
    try:
        supabase.table("products").update(
            {
                "deleted_at": None,
                "is_active": True,
            }
        ).eq("id", pid).execute()
        return jsonify({"message": "restored"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/products_add_from_insight", methods=["POST"])
@login_required
def api_products_add_from_insight():
    """Add/update a legacy product discovered from sales history.

    Used by customer_list Product Insight when an item exists in old sales_records
    but is not in the product settings. The default is_active=False keeps it out of
    the sales-entry product picker, while still letting analytics use its estimated
    price.
    """
    try:
        data = request.get_json(force=True) or {}
        category_name = (data.get("category") or data.get("category_name") or "").strip()
        product_name = (data.get("product_name") or data.get("name") or "").strip()
        if not category_name:
            return jsonify({"error": "missing_category"}), 400
        if not product_name:
            return jsonify({"error": "missing_product_name"}), 400

        try:
            estimated_price = _product_price_or_none(data.get("estimated_price"))
        except ValueError:
            return jsonify({"error": "invalid_estimated_price"}), 400

        estimated_price = estimated_price if estimated_price is not None else 0
        estimated_unit = _product_unit_clean(data.get("estimated_unit") or data.get("unit") or "ชิ้น")

        # Default false: use for analytics only, not for the sales-entry picker.
        open_for_sales_raw = data.get("open_for_sales", data.get("is_active", False))
        if isinstance(open_for_sales_raw, bool):
            is_active = open_for_sales_raw
        else:
            is_active = str(open_for_sales_raw or "").strip().lower() in {"1", "true", "yes", "y", "on"}

        # Find or create category by its display name.
        cat_rows = (
            supabase.table("product_categories")
            .select("*")
            .eq("name", category_name)
            .limit(1)
            .execute()
        ).data or []

        if cat_rows:
            category = cat_rows[0]
        else:
            # Put new category at the end; normally category should already exist.
            sort_order = 9999
            try:
                last_cat = (
                    supabase.table("product_categories")
                    .select("sort_order")
                    .order("sort_order", desc=True)
                    .limit(1)
                    .execute()
                ).data or []
                if last_cat:
                    sort_order = int(last_cat[0].get("sort_order") or 0) + 10
            except Exception:
                pass

            ins_cat = supabase.table("product_categories").insert({
                "name": category_name,
                "sort_order": sort_order,
                "is_active": True,
            }).execute()
            category = (ins_cat.data or [{}])[0]

        category_id = category.get("id")
        if not category_id:
            return jsonify({"error": "category_create_failed"}), 500

        # Existing product with the exact same name in this category: just update price/unit/status.
        existing = (
            supabase.table("products")
            .select("*")
            .eq("category_id", category_id)
            .eq("name", product_name)
            .limit(1)
            .execute()
        ).data or []

        patch = {
            "estimated_price": estimated_price,
            "estimated_unit": estimated_unit,
            "is_active": is_active,
            "deleted_at": None,
        }

        if existing:
            pid = existing[0].get("id")
            upd = supabase.table("products").update(patch).eq("id", pid).execute()
            row = (upd.data or [{}])[0] if getattr(upd, "data", None) else {}
            return jsonify({"message": "updated", "row": row, "category": category}), 200

        sort_order = 9999
        try:
            last_prod = (
                supabase.table("products")
                .select("sort_order")
                .eq("category_id", category_id)
                .order("sort_order", desc=True)
                .limit(1)
                .execute()
            ).data or []
            if last_prod:
                sort_order = int(last_prod[0].get("sort_order") or 0) + 10
        except Exception:
            pass

        payload = {
            "category_id": category_id,
            "name": product_name,
            "default_price": None,
            "estimated_price": estimated_price,
            "estimated_unit": estimated_unit,
            "sort_order": sort_order,
            "is_active": is_active,
            "deleted_at": None,
        }
        ins = supabase.table("products").insert(payload).execute()
        row = (ins.data or [{}])[0] if getattr(ins, "data", None) else {}
        return jsonify({"message": "inserted", "row": row, "category": category}), 200

    except Exception as e:
        app.logger.error(f"/api/products_add_from_insight error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Product Estimated Prices
# ใช้สำหรับหน้า customer_list แถบ "ตั้งค่าราคาประเมินสินค้า"
# หมายเหตุ: ราคานี้ใช้คำนวณเฉพาะ Product Insight เท่านั้น ไม่กระทบยอดจริงของ sales_records.amount
# =============================================================
def _pep_clean_text(v: Any) -> str:
    return str(v or "").strip()


def _pep_float(v: Any, default: float = 0.0) -> float:
    try:
        if v in (None, ""):
            return default
        return float(v)
    except Exception:
        return default


def _pep_int(v: Any, default: int = 0) -> int:
    try:
        if v in (None, ""):
            return default
        return int(float(v))
    except Exception:
        return default


def _pep_bool(v: Any, default: bool = True) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v or "").strip().lower()
    if s in {"false", "0", "no", "n", "off"}:
        return False
    if s in {"true", "1", "yes", "y", "on"}:
        return True
    return default


def _clean_product_estimated_price_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    category = _pep_clean_text(data.get("category"))
    product_name = _pep_clean_text(data.get("product_name") or data.get("name"))
    if not category:
        raise ValueError("missing_category")
    if not product_name:
        raise ValueError("missing_product_name")

    payload = {
        "category": category,
        "product_name": product_name,
        "unit_label": _pep_clean_text(data.get("unit_label") or data.get("unit") or "ชิ้น") or "ชิ้น",
        "estimated_price": max(0.0, _pep_float(data.get("estimated_price"), 0.0)),
        "is_active": _pep_bool(data.get("is_active"), True),
        "sort_order": _pep_int(data.get("sort_order"), 0),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    return payload


@app.route("/api/product_estimated_prices")
@login_required
def api_product_estimated_prices():
    try:
        include_inactive = str(request.args.get("include_inactive", "1")).lower() in {"1", "true", "yes"}
        q = supabase.table("product_estimated_prices").select("*")
        if not include_inactive:
            q = q.eq("is_active", True)
        rows = (
            q.order("category", desc=False)
             .order("sort_order", desc=False)
             .order("product_name", desc=False)
             .execute()
             .data
            or []
        )
        return jsonify(rows)
    except Exception as e:
        app.logger.error(f"/api/product_estimated_prices error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/save_product_estimated_price", methods=["POST"])
@login_required
def api_save_product_estimated_price():
    try:
        data = request.get_json(force=True) or {}
        row_id = _pep_clean_text(data.get("id"))
        payload = _clean_product_estimated_price_payload(data)

        if row_id:
            res = supabase.table("product_estimated_prices").update(payload).eq("id", row_id).execute()
        else:
            payload["created_at"] = datetime.now(timezone.utc).isoformat()
            res = supabase.table("product_estimated_prices").upsert(
                payload,
                on_conflict="category,product_name"
            ).execute()

        row = (res.data or [payload])[0] if isinstance(res.data, list) else payload
        return jsonify({"success": True, "row": row})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"/api/save_product_estimated_price error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/save_product_estimated_prices", methods=["POST"])
@login_required
def api_save_product_estimated_prices():
    try:
        data = request.get_json(force=True) or {}
        rows_in = data if isinstance(data, list) else data.get("rows")
        if not isinstance(rows_in, list):
            return jsonify({"error": "payload_must_be_list_or_rows"}), 400

        now_iso = datetime.now(timezone.utc).isoformat()
        payloads = []
        for row in rows_in:
            if not isinstance(row, dict):
                continue
            payload = _clean_product_estimated_price_payload(row)
            payload["created_at"] = row.get("created_at") or now_iso
            payload["updated_at"] = now_iso
            payloads.append(payload)

        if not payloads:
            return jsonify({"success": True, "count": 0, "rows": []})

        res = supabase.table("product_estimated_prices").upsert(
            payloads,
            on_conflict="category,product_name"
        ).execute()
        return jsonify({"success": True, "count": len(payloads), "rows": res.data or payloads})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"/api/save_product_estimated_prices error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Sales Pitch
# =============================================================
@app.route("/api/pitches")
@login_required
def get_pitches():
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


@app.route("/api/add_pitch", methods=["POST"])
@login_required
def add_pitch():
    data = request.get_json(force=True) or {}
    opd = normalize_opd(data.get("opd"))
    content = _clean_dash(data.get("content") or "")
    channel = data.get("channel")
    outcome = data.get("outcome")
    author = session.get("username") or data.get("author")

    if not opd or content is None:
        return jsonify({"error": "opd and content required"}), 400

    try:
        ins = {"opd": opd, "content": content, "channel": channel, "outcome": outcome, "author": author}
        if "promotion" in data:
            ins["promotion"] = _clean_dash(data.get("promotion"))
        r = supabase.table("customer_pitch_logs").insert(ins).execute()
        row = (r.data or [{}])[0]
        return jsonify({"message": "ok", "id": row.get("id"), "created_at": row.get("created_at")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/add_pitches_bulk", methods=["POST"])
@login_required
def add_pitches_bulk():
    to_insert: List[Dict[str, Any]] = []
    try:
        rows = request.get_json(force=True)
        if not isinstance(rows, list):
            return jsonify({"error": "payload_must_be_list"}), 400

        author = session.get("username", "")

        for r in rows:
            date_str = (r.get("date") or "")[:10] or datetime.utcnow().strftime("%Y-%m-%d")
            created_at_iso = f"{date_str}T12:00:00Z"

            rec: Dict[str, Any] = {
                "opd": normalize_opd(r.get("opd")),
                "content": _clean_dash(r.get("content") or ""),
                "channel": r.get("channel") or None,
                "outcome": r.get("outcome") or None,
                "author": author or None,
                "created_at": created_at_iso,
            }
            if "promotion" in r and r.get("promotion") is not None:
                rec["promotion"] = _clean_dash(r.get("promotion"))
            to_insert.append(rec)

        if not to_insert:
            return jsonify({"error": "empty"}), 400

        supabase.table("customer_pitch_logs").insert(to_insert).execute()
        return jsonify({"inserted": len(to_insert), "message": "ok"})
    except Exception as e:
        msg = str(e)
        if "promotion" in msg.lower() and to_insert:
            try:
                cleaned = [{k: v for k, v in r.items() if k != "promotion"} for r in to_insert]
                supabase.table("customer_pitch_logs").insert(cleaned).execute()
                return jsonify({"inserted": len(cleaned), "message": "ok (promotion skipped)"}), 200
            except Exception as e2:
                return jsonify({"error": str(e2)}), 500
        return jsonify({"error": msg}), 500


@app.route("/api/pitches_by_date")
@login_required
def pitches_by_date():
    try:
        q_from = (request.args.get("from") or "").strip()
        q_to = (request.args.get("to") or "").strip()
        kw = (request.args.get("q") or "").strip().lower()
        outcome = (request.args.get("outcome") or "").strip()
        channel = (request.args.get("channel") or "").strip()

        if not q_from or not q_to:
            today = datetime.utcnow().strftime("%Y-%m-%d")
            q_to = q_to or today
            q_from = q_from or today

        qry = (
            supabase.table("customer_pitch_logs")
            .select("*")
            .gte("created_at", f"{q_from}T00:00:00Z")
            .lte("created_at", f"{q_to}T23:59:59Z")
            .order("created_at", desc=True)
        )
        if outcome:
            qry = qry.eq("outcome", outcome)
        if channel:
            qry = qry.eq("channel", channel)

        resp = qry.execute()
        rows = resp.data or []

        if kw:
            tmp = []
            for r in rows:
                s = " ".join(
                    [
                        str(r.get("opd") or ""),
                        str(r.get("content") or ""),
                        str(r.get("outcome") or ""),
                        str(r.get("channel") or ""),
                        str(r.get("author") or ""),
                        str(r.get("promotion") or ""),
                    ]
                ).lower()
                if kw in s:
                    tmp.append(r)
            rows = tmp

        for r in rows:
            ts = str(r.get("created_at") or "")
            r["date"] = ts[:10] if ts else None

        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/update_pitch", methods=["PUT"])
@login_required
def update_pitch():
    data = request.get_json(force=True) or {}
    rec_id = data.get("id")
    if not rec_id:
        return jsonify({"error": "missing id"}), 400

    allowed = {"promotion", "outcome", "content", "channel"}
    payload = {k: _clean_dash(v) for k, v in data.items() if k in allowed}
    if not payload:
        return jsonify({"error": "no_fields_to_update"}), 400

    try:
        res = supabase.table("customer_pitch_logs").update(payload).eq("id", rec_id).execute()
        if not res.data:
            return jsonify({"error": "not_found"}), 404
        return jsonify({"message": "updated", "row": res.data[0]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_pitch", methods=["DELETE"])
@login_required
def delete_pitch():
    rec_id = request.args.get("id")
    if not rec_id:
        body = request.get_json(silent=True) or {}
        rec_id = body.get("id") if isinstance(body, dict) else None
    if not rec_id:
        return jsonify({"error": "missing id"}), 400

    try:
        supabase.table("customer_pitch_logs").delete().eq("id", rec_id).execute()
        return jsonify({"message": "deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cleanup_pitch_dash", methods=["POST", "GET"])
@login_required
def cleanup_pitch_dash():
    try:
        supabase.table("customer_pitch_logs").update({"content": ""}).in_("content", ["-", "–", "—"]).execute()
        supabase.table("customer_pitch_logs").update({"promotion": ""}).in_("promotion", ["-", "–", "—"]).execute()
        return jsonify({"message": "cleaned"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Reccord Sale (Extra)
# =============================================================
@app.route("/api/reccord_sale")
@login_required
def api_reccord_sale():
    try:
        name = (request.args.get("name") or "").strip()
        phone = (request.args.get("phone") or "").strip()
        opd_q = normalize_opd(request.args.get("opd")) if request.args.get("opd") else ""
        since = safe_date_str(request.args.get("since")) if request.args.get("since") else ""
        until = safe_date_str(request.args.get("until")) if request.args.get("until") else ""
        try:
            limit = max(1, min(20000, int(request.args.get("limit", "2000"))))
        except Exception:
            limit = 2000

        q = supabase.table("sales_records").select("*")
        if opd_q:
            q = q.eq("opd", opd_q)
        if name:
            q = q.ilike("name", f"%{name}%")
        if phone:
            q = q.ilike("phone", f"%{phone}%")
        if since:
            q = q.gte("date", since)
        if until:
            q = q.lte("date", until)

        q = q.order("date", desc=True)

        out: List[Dict[str, Any]] = []
        start = 0
        page_size = 1000
        while start < limit:
            resp = q.range(start, start + min(page_size, limit - start) - 1).execute()
            batch = resp.data or []
            if not batch:
                break
            for r in batch:
                raw_item = r.get("item")
                if raw_item is None and r.get("items") is not None:
                    raw_item = r.get("items")

                normalized_item_list = _ensure_item_list(raw_item)
                r["item"] = normalized_item_list
                r["items"] = _coerce_items_to_text_list(normalized_item_list)
                r["opd"] = normalize_opd(r.get("opd"))
                r["date"] = safe_date_str(r.get("date"))
            out.extend(batch)
            if len(batch) < page_size:
                break
            start += page_size

        if len(out) > limit:
            out = out[:limit]

        return jsonify(out)
    except Exception as e:
        app.logger.error(f"/api/reccord_sale error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Oldsale & Inventory
# Inventory v2: fixed item master + one count per item/date
# =============================================================
@app.route("/api/oldsaledata")
@login_required
def api_oldsaledata():
    try:
        response = supabase.table("oldsaledata").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        app.logger.error(f"ERROR loading oldsaledata: {e}")
        return jsonify({"error": str(e)}), 500


def _clean_inventory_aliases(value):
    """Return clean alias list from list/string."""
    if value is None:
        return []
    if isinstance(value, list):
        raw = value
    elif isinstance(value, str):
        raw = value.split(",")
    else:
        raw = []
    out = []
    seen = set()
    for x in raw:
        s = str(x or "").strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _num_or_zero(value):
    try:
        if value is None or value == "":
            return 0
        return float(value)
    except Exception:
        return 0


def _inventory_fetch_items(include_inactive=True):
    q = supabase.table("inventory_items").select("*")
    if not include_inactive:
        q = q.eq("is_active", True)
    res = q.execute()
    rows = res.data or []
    rows.sort(key=lambda x: (
        str(x.get("category") or ""),
        int(float(x.get("sort_order") or 0)),
        str(x.get("name") or "")
    ))
    return rows


def _inventory_match_item_id(item_name, items_cache=None):
    name = str(item_name or "").strip()
    if not name:
        return None
    key = name.lower()
    items = items_cache if items_cache is not None else _inventory_fetch_items(include_inactive=True)
    for item in items:
        if str(item.get("name") or "").strip().lower() == key:
            return item.get("id")
        aliases = item.get("aliases") or []
        if isinstance(aliases, str):
            aliases = _clean_inventory_aliases(aliases)
        for a in aliases:
            if str(a or "").strip().lower() == key:
                return item.get("id")
    return None


@app.route("/api/inventory_items")
@login_required
def api_inventory_items():
    """Fixed inventory item master. Frontend uses this instead of hardcoded item heads."""
    try:
        include_inactive = str(request.args.get("include_inactive", "0")).lower() in ("1", "true", "yes")
        rows = _inventory_fetch_items(include_inactive=include_inactive)
        return jsonify(rows)
    except Exception as e:
        app.logger.error(f"/api/inventory_items error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/save_inventory_item", methods=["POST"])
@login_required
def api_save_inventory_item():
    """Create/update item master. Deletion is intentionally soft via is_active."""
    try:
        data = request.get_json(force=True) or {}
        item_id = str(data.get("id") or "").strip()
        name = str(data.get("name") or "").strip()
        category = str(data.get("category") or "").strip()
        unit = str(data.get("unit") or "ชิ้น").strip() or "ชิ้น"
        aliases = _clean_inventory_aliases(data.get("aliases"))
        min_qty = _num_or_zero(data.get("min_qty"))
        sort_order = int(_num_or_zero(data.get("sort_order")))
        is_active = bool(data.get("is_active", True))

        if not name:
            return jsonify({"error": "กรุณากรอกชื่อรายการ"}), 400
        if not category:
            return jsonify({"error": "กรุณากรอกหมวด"}), 400

        payload = {
            "name": name,
            "category": category,
            "unit": unit,
            "min_qty": min_qty,
            "sort_order": sort_order,
            "is_active": is_active,
            "aliases": aliases,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        if item_id:
            supabase.table("inventory_items").update(payload).eq("id", item_id).execute()
            return jsonify({"success": True, "message": "updated"})

        payload["created_at"] = datetime.now(timezone.utc).isoformat()
        supabase.table("inventory_items").insert(payload).execute()
        return jsonify({"success": True, "message": "inserted"})

    except Exception as e:
        app.logger.error(f"/api/save_inventory_item error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/toggle_inventory_item", methods=["POST"])
@login_required
def api_toggle_inventory_item():
    """Soft delete / restore item master."""
    try:
        data = request.get_json(force=True) or {}
        item_id = str(data.get("id") or "").strip()
        if not item_id:
            return jsonify({"error": "missing id"}), 400
        is_active = bool(data.get("is_active", True))
        supabase.table("inventory_items").update({
            "is_active": is_active,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", item_id).execute()
        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"/api/toggle_inventory_item error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/inventory")
@login_required
def api_inventory():
    """
    Compatibility endpoint.
    New system returns flattened rows from inventory_counts joined with inventory_items:
      {item_id, item_name, category, unit, min_qty, date, quantity}
    If new tables are not available yet, it falls back to legacy inventory table.
    """
    try:
        all_data = []
        start = 0
        limit = 1000
        while True:
            res = (
                supabase.table("inventory_counts")
                .select("id,item_id,count_date,quantity,note,created_at,updated_at,inventory_items(id,name,category,unit,min_qty,sort_order,is_active)")
                .range(start, start + limit - 1)
                .execute()
            )
            batch = res.data or []
            for r in batch:
                item = r.get("inventory_items") or {}
                all_data.append({
                    "id": r.get("id"),
                    "item_id": r.get("item_id"),
                    "item_name": item.get("name") or "",
                    "category": item.get("category") or "",
                    "unit": item.get("unit") or "ชิ้น",
                    "min_qty": item.get("min_qty") or 0,
                    "sort_order": item.get("sort_order") or 0,
                    "is_active": item.get("is_active", True),
                    "date": safe_date_str(r.get("count_date")),
                    "quantity": r.get("quantity") or 0,
                    "note": r.get("note") or "",
                })
            if len(batch) < limit:
                break
            start += limit
        return jsonify(all_data)
    except Exception as e_new:
        # Legacy fallback for projects that have not run the new SQL yet.
        try:
            all_data = []
            start = 0
            limit = 1000
            while True:
                res = supabase.table("inventory").select("*").range(start, start + limit - 1).execute()
                batch = res.data or []
                all_data.extend(batch)
                if len(batch) < limit:
                    break
                start += limit
            return jsonify(all_data)
        except Exception as e_old:
            app.logger.error(f"/api/inventory error new={e_new} old={e_old}")
            return jsonify({"error": str(e_new)}), 500


@app.route("/api/save_inventory", methods=["POST"])
@login_required
def api_save_inventory():
    """
    Save inventory counts.
    New behavior: UPSERT by (item_id, count_date), so the same item/date cannot duplicate.
    Backward compatible: item_name is mapped to inventory_items by name/aliases.
    """
    data = request.get_json(force=True)
    rows = data if isinstance(data, list) else [data]
    try:
        items_cache = None
        payload = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for row in rows:
            if not isinstance(row, dict):
                continue
            item_id = str(row.get("item_id") or "").strip()
            if not item_id:
                if items_cache is None:
                    items_cache = _inventory_fetch_items(include_inactive=True)
                item_id = _inventory_match_item_id(row.get("item_name"), items_cache=items_cache) or ""
            date_str = safe_date_str(row.get("date") or row.get("count_date"))
            if not item_id:
                return jsonify({"error": f"ไม่พบรายการกลางของ {row.get('item_name') or '-'}"}), 400
            if not date_str:
                return jsonify({"error": "กรุณาระบุวันที่"}), 400
            qty = _num_or_zero(row.get("quantity"))
            if qty < 0:
                return jsonify({"error": "จำนวนต้องไม่ติดลบ"}), 400
            payload.append({
                "item_id": item_id,
                "count_date": date_str,
                "quantity": qty,
                "note": str(row.get("note") or "").strip(),
                "updated_at": now_iso,
            })

        if not payload:
            return jsonify({"message": "no data", "count": 0})

        supabase.table("inventory_counts").upsert(payload, on_conflict="item_id,count_date").execute()
        return jsonify({"message": "success", "count": len(payload)})

    except Exception as e:
        # If the new schema is not installed, fallback to old insert to avoid breaking immediately.
        try:
            legacy_payload = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                legacy_payload.append({
                    "item_name": str(row.get("item_name") or row.get("name") or "").strip(),
                    "date": safe_date_str(row.get("date") or row.get("count_date")),
                    "quantity": _num_or_zero(row.get("quantity")),
                })
            if legacy_payload:
                supabase.table("inventory").insert(legacy_payload).execute()
                return jsonify({"message": "success", "count": len(legacy_payload), "legacy": True})
        except Exception:
            pass
        app.logger.error(f"/api/save_inventory error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Tax Module
# =============================================================
def th_tax_brackets(amount: float) -> float:
    if amount is None or amount <= 0:
        return 0.0

    remain = amount
    tax = 0.0
    prev_cap = 0.0
    brackets = [
        (150000, 0.00),
        (300000, 0.05),
        (500000, 0.10),
        (750000, 0.15),
        (1000000, 0.20),
        (2000000, 0.25),
        (5000000, 0.30),
        (float("inf"), 0.35),
    ]

    for cap, rate in brackets:
        slab_width = (cap - prev_cap) if isfinite(cap) else max(0.0, remain)
        chunk = max(0.0, min(remain, slab_width))
        tax += chunk * rate
        remain -= chunk
        prev_cap = cap
        if remain <= 0:
            break
    return round(tax, 2)


def compute_tax_from_gross_sales_yearly(gross_year: float, social_sec: float = 0.0) -> dict:
    if not gross_year or gross_year <= 0:
        return {
            "gross_year": 0.0,
            "expense_lump": 0.0,
            "net_after_expense": 0.0,
            "allowance_personal": 60000.0,
            "social_security": 0.0,
            "taxable_income": 0.0,
            "tax_year": 0.0,
            "tax_month_avg": 0.0,
            "effective_rate": 0.0,
        }

    expense_lump = round(gross_year * 0.60, 2)
    net_after_expense = max(0.0, round(gross_year - expense_lump, 2))

    allowance_personal = 60000.0
    social_security = min(max(social_sec or 0.0, 0.0), 9000.0)

    taxable_income = max(0.0, round(net_after_expense - allowance_personal - social_security, 2))
    tax_year = th_tax_brackets(taxable_income)
    tax_month_avg = round(tax_year / 12.0, 2) if tax_year > 0 else 0.0
    effective_rate = round((tax_year / gross_year) * 100.0, 4) if gross_year > 0 else 0.0

    return {
        "gross_year": round(gross_year, 2),
        "expense_lump": expense_lump,
        "net_after_expense": net_after_expense,
        "allowance_personal": allowance_personal,
        "social_security": social_security,
        "taxable_income": taxable_income,
        "tax_year": tax_year,
        "tax_month_avg": tax_month_avg,
        "effective_rate": effective_rate,
    }


@app.route("/api/tax_summary")
@login_required
def api_tax_summary():
    try:
        year_str = (request.args.get("year") or "").strip()
        if not year_str.isdigit() or len(year_str) != 4:
            return jsonify({"error": "year_required_as_YYYY"}), 400
        year = int(year_str)

        try:
            sso = float(request.args.get("sso", "0") or "0")
        except Exception:
            sso = 0.0

        month_sum = {m: 0.0 for m in range(1, 13)}
        total = 0.0

        q = (
            supabase.table("sales_records")
            .select("amount,date")
            .gte("date", f"{year}-01-01")
            .lte("date", f"{year}-12-31")
            .order("date", desc=False)
        )
        start = 0
        page = 1000
        while True:
            resp = q.range(start, start + page - 1).execute()
            batch = resp.data or []
            if not batch:
                break
            for r in batch:
                amt = r.get("amount")
                d = r.get("date") or ""
                if amt is None:
                    continue
                try:
                    y, m, _ = str(d)[:10].split("-")
                    if int(y) == year:
                        m_i = int(m)
                        month_sum[m_i] = round(month_sum[m_i] + float(amt), 2)
                        total = round(total + float(amt), 2)
                except Exception:
                    continue
            if len(batch) < page:
                break
            start += page

        tax = compute_tax_from_gross_sales_yearly(total, social_sec=sso)

        months = [{"month": m, "gross": month_sum[m]} for m in range(1, 13)]
        return jsonify({"year": year, "months": months, "summary": tax})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# Simple "Ledger" APIs (AR / Voucher / Work)
# =============================================================

def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v in ("", None):
            return default
        return float(v)
    except Exception:
        return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v in ("", None):
            return default
        return int(float(v))
    except Exception:
        return default


def _page_all(q, page_size: int = 1000) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    start = 0
    while True:
        resp = q.range(start, start + page_size - 1).execute()
        batch = resp.data or []
        out.extend(batch)
        if len(batch) < page_size:
            break
        start += page_size
    return out


def _get_customer_map() -> Dict[str, Dict[str, Any]]:
    cust = (supabase.table("customers").select("opd,name,phone").execute().data) or []
    m: Dict[str, Dict[str, Any]] = {}
    for c in cust:
        opd = normalize_opd(c.get("opd"))
        m[opd] = {"name": c.get("name") or "", "phone": c.get("phone") or ""}
    return m


def _match_kw(opd: str, name: str, phone: str, kw: str) -> bool:
    if not kw:
        return True
    s = f"{opd} {name} {phone}".lower()
    return kw.lower() in s


# -----------------------------
# A) ค้างเรา (AR)
# -----------------------------
@app.route("/api/ar_summary")
@login_required
def api_ar_summary():
    try:
        kw = (request.args.get("q") or "").strip()
        opd_q = normalize_opd(request.args.get("opd")) if request.args.get("opd") else ""

        cust_map = _get_customer_map()

        q = supabase.table("ar_transactions").select("*").order("tx_date", desc=False).order("created_at", desc=False)
        if opd_q:
            q = q.eq("opd", opd_q)

        rows = _page_all(q)

        agg: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            opd = normalize_opd(r.get("opd"))
            amt = _safe_float(r.get("amount"), 0.0)
            t = (r.get("tx_type") or "").strip()

            delta = 0.0
            if t == "add":
                delta = abs(amt)
            elif t == "pay":
                delta = -abs(amt)
            elif t == "adjust":
                delta = amt
            else:
                continue

            if opd not in agg:
                agg[opd] = {
                    "opd": opd,
                    "balance": 0.0,
                    "last_tx_date": "",
                    "last_pay_date": "",
                }

            agg[opd]["balance"] = round(agg[opd]["balance"] + delta, 2)

            d = safe_date_str(r.get("tx_date"))
            if d and (agg[opd]["last_tx_date"] == "" or d >= agg[opd]["last_tx_date"]):
                agg[opd]["last_tx_date"] = d

            if t == "pay":
                if d and (agg[opd]["last_pay_date"] == "" or d >= agg[opd]["last_pay_date"]):
                    agg[opd]["last_pay_date"] = d

        out: List[Dict[str, Any]] = []
        for opd, a in agg.items():
            info = cust_map.get(opd, {"name": "", "phone": ""})
            if not _match_kw(opd, info["name"], info["phone"], kw):
                continue
            out.append(
                {
                    "opd": opd,
                    "name": info["name"],
                    "phone": info["phone"],
                    "balance": a["balance"],
                    "last_tx_date": a["last_tx_date"],
                    "last_pay_date": a["last_pay_date"],
                }
            )

        out.sort(key=lambda x: (-(x.get("balance") or 0.0), x.get("last_tx_date") or ""), reverse=False)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ar_history")
@login_required
def api_ar_history():
    try:
        opd = normalize_opd(request.args.get("opd"))
        if not opd:
            return jsonify({"error": "missing_opd"}), 400

        cust_map = _get_customer_map()
        info = cust_map.get(opd, {"name": "", "phone": ""})

        q = (
            supabase.table("ar_transactions")
            .select("*")
            .eq("opd", opd)
            .order("tx_date", desc=False)
            .order("created_at", desc=False)
        )
        rows = _page_all(q)

        bal = 0.0
        out_rows: List[Dict[str, Any]] = []
        for r in rows:
            amt = _safe_float(r.get("amount"), 0.0)
            t = (r.get("tx_type") or "").strip()

            if t == "add":
                delta = abs(amt)
                label = "เพิ่มค้าง"
            elif t == "pay":
                delta = -abs(amt)
                label = "รับชำระ"
            elif t == "adjust":
                delta = amt
                label = "ปรับยอด"
            else:
                continue

            bal = round(bal + delta, 2)
            out_rows.append(
                {
                    "id": r.get("id"),
                    "tx_date": safe_date_str(r.get("tx_date")),
                    "type": t,
                    "type_label": label,
                    "delta": round(delta, 2),
                    "balance_after": bal,
                    "note": r.get("note") or "",
                    "created_at": r.get("created_at"),
                }
            )

        return jsonify(
            {
                "opd": opd,
                "name": info["name"],
                "phone": info["phone"],
                "balance_now": bal,
                "rows": out_rows,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ar_tx", methods=["POST"])
@login_required
def api_ar_tx():
    try:
        data = request.get_json(silent=True) or {}
        opd = normalize_opd(data.get("opd"))
        tx_date = safe_date_str(data.get("tx_date") or data.get("date"))
        tx_type = (data.get("tx_type") or "").strip()
        amount = _safe_float(data.get("amount"), None)
        note = (data.get("note") or "").strip()

        if not opd:
            return jsonify({"error": "missing_opd"}), 400
        if not tx_date:
            return jsonify({"error": "missing_tx_date"}), 400
        if tx_type not in {"add", "pay", "adjust"}:
            return jsonify({"error": "invalid_tx_type"}), 400
        if amount is None:
            return jsonify({"error": "missing_amount"}), 400
        if amount == 0:
            return jsonify({"error": "amount_cannot_be_zero"}), 400

        payload = {
            "opd": opd,
            "tx_date": tx_date,
            "tx_type": tx_type,
            "amount": float(amount),
            "note": note or None,
        }

        ins = supabase.table("ar_transactions").insert(payload).execute()
        row = (ins.data or [{}])[0]
        return jsonify({"success": True, "id": row.get("id")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# B) วอยเชอร์/เงินจ่ายล่วงหน้า (Voucher / Prepaid)
# -----------------------------
@app.route("/api/voucher_summary")
@login_required
def api_voucher_summary():
    try:
        kw = (request.args.get("q") or "").strip()
        opd_q = normalize_opd(request.args.get("opd")) if request.args.get("opd") else ""

        cust_map = _get_customer_map()

        q = supabase.table("voucher_transactions").select("*").order("tx_date", desc=False).order("created_at", desc=False)
        if opd_q:
            q = q.eq("opd", opd_q)

        rows = _page_all(q)

        agg: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            opd = normalize_opd(r.get("opd"))
            amt = _safe_float(r.get("amount"), 0.0)
            t = (r.get("tx_type") or "").strip()

            if t == "topup":
                delta = abs(amt)
            elif t == "use":
                delta = -abs(amt)
            elif t == "adjust":
                delta = amt
            else:
                continue

            if opd not in agg:
                agg[opd] = {"opd": opd, "balance": 0.0, "last_tx_date": ""}
            agg[opd]["balance"] = round(agg[opd]["balance"] + delta, 2)

            d = safe_date_str(r.get("tx_date"))
            if d and (agg[opd]["last_tx_date"] == "" or d >= agg[opd]["last_tx_date"]):
                agg[opd]["last_tx_date"] = d

        out: List[Dict[str, Any]] = []
        for opd, a in agg.items():
            info = cust_map.get(opd, {"name": "", "phone": ""})
            if not _match_kw(opd, info["name"], info["phone"], kw):
                continue
            out.append(
                {
                    "opd": opd,
                    "name": info["name"],
                    "phone": info["phone"],
                    "balance": a["balance"],
                    "last_tx_date": a["last_tx_date"],
                }
            )

        out.sort(key=lambda x: (-(x.get("balance") or 0.0), x.get("last_tx_date") or ""), reverse=False)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/voucher_history")
@login_required
def api_voucher_history():
    try:
        opd = normalize_opd(request.args.get("opd"))
        if not opd:
            return jsonify({"error": "missing_opd"}), 400

        cust_map = _get_customer_map()
        info = cust_map.get(opd, {"name": "", "phone": ""})

        q = (
            supabase.table("voucher_transactions")
            .select("*")
            .eq("opd", opd)
            .order("tx_date", desc=False)
            .order("created_at", desc=False)
        )
        rows = _page_all(q)

        bal = 0.0
        out_rows: List[Dict[str, Any]] = []
        for r in rows:
            amt = _safe_float(r.get("amount"), 0.0)
            t = (r.get("tx_type") or "").strip()

            if t == "topup":
                delta = abs(amt)
                label = "เติมวอยเชอร์/จ่ายล่วงหน้า"
            elif t == "use":
                delta = -abs(amt)
                label = "ใช้วอยเชอร์/หักเครดิต"
            elif t == "adjust":
                delta = amt
                label = "ปรับยอด"
            else:
                continue

            bal = round(bal + delta, 2)
            out_rows.append(
                {
                    "id": r.get("id"),
                    "tx_date": safe_date_str(r.get("tx_date")),
                    "type": t,
                    "type_label": label,
                    "delta": round(delta, 2),
                    "balance_after": bal,
                    "note": r.get("note") or "",
                    "created_at": r.get("created_at"),
                }
            )

        return jsonify({"opd": opd, "name": info["name"], "phone": info["phone"], "balance_now": bal, "rows": out_rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/voucher_tx", methods=["POST"])
@login_required
def api_voucher_tx():
    try:
        data = request.get_json(silent=True) or {}
        opd = normalize_opd(data.get("opd"))
        tx_date = safe_date_str(data.get("tx_date") or data.get("date"))
        tx_type = (data.get("tx_type") or "").strip()
        amount = _safe_float(data.get("amount"), None)
        note = (data.get("note") or "").strip()

        if not opd:
            return jsonify({"error": "missing_opd"}), 400
        if not tx_date:
            return jsonify({"error": "missing_tx_date"}), 400
        if tx_type not in {"topup", "use", "adjust"}:
            return jsonify({"error": "invalid_tx_type"}), 400
        if amount is None:
            return jsonify({"error": "missing_amount"}), 400
        if amount == 0:
            return jsonify({"error": "amount_cannot_be_zero"}), 400

        payload = {"opd": opd, "tx_date": tx_date, "tx_type": tx_type, "amount": float(amount), "note": note or None}
        ins = supabase.table("voucher_transactions").insert(payload).execute()
        row = (ins.data or [{}])[0]
        return jsonify({"success": True, "id": row.get("id")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# C) ค้างทำสินค้า/งาน (Work)
# -----------------------------
@app.route("/api/work_summary")
@login_required
def api_work_summary():
    try:
        kw = (request.args.get("q") or "").strip()
        opd_q = normalize_opd(request.args.get("opd")) if request.args.get("opd") else ""

        cust_map = _get_customer_map()

        q = supabase.table("work_transactions").select("*").order("tx_date", desc=False).order("created_at", desc=False)
        if opd_q:
            q = q.eq("opd", opd_q)

        rows = _page_all(q)

        agg: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            opd = normalize_opd(r.get("opd"))
            item = (r.get("item") or "").strip()
            qty = _safe_int(r.get("qty"), 0)
            t = (r.get("tx_type") or "").strip()

            if not item:
                continue

            if t == "add":
                delta = abs(qty)
            elif t == "done":
                delta = -abs(qty)
            elif t == "adjust":
                delta = qty
            else:
                continue

            if opd not in agg:
                agg[opd] = {"opd": opd, "items": {}, "last_tx_date": ""}

            agg[opd]["items"].setdefault(item, 0)
            agg[opd]["items"][item] += int(delta)

            d = safe_date_str(r.get("tx_date"))
            if d and (agg[opd]["last_tx_date"] == "" or d >= agg[opd]["last_tx_date"]):
                agg[opd]["last_tx_date"] = d

        out: List[Dict[str, Any]] = []
        for opd, a in agg.items():
            info = cust_map.get(opd, {"name": "", "phone": ""})
            if not _match_kw(opd, info["name"], info["phone"], kw):
                continue

            items_pending = []
            total = 0
            for item, qtty in a["items"].items():
                if qtty != 0:
                    items_pending.append({"item": item, "qty_pending": int(qtty)})
                    total += int(qtty)

            if total == 0:
                continue

            items_pending.sort(key=lambda x: x["qty_pending"], reverse=True)

            out.append(
                {
                    "opd": opd,
                    "name": info["name"],
                    "phone": info["phone"],
                    "total_qty_pending": total,
                    "last_tx_date": a["last_tx_date"],
                    "items": items_pending,
                }
            )

        out.sort(key=lambda x: (-(x.get("total_qty_pending") or 0), x.get("last_tx_date") or ""), reverse=False)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/work_history")
@login_required
def api_work_history():
    try:
        opd = normalize_opd(request.args.get("opd"))
        if not opd:
            return jsonify({"error": "missing_opd"}), 400

        cust_map = _get_customer_map()
        info = cust_map.get(opd, {"name": "", "phone": ""})

        q = (
            supabase.table("work_transactions")
            .select("*")
            .eq("opd", opd)
            .order("tx_date", desc=False)
            .order("created_at", desc=False)
        )
        rows = _page_all(q)

        items_now: Dict[str, int] = {}
        out_rows: List[Dict[str, Any]] = []

        for r in rows:
            item = (r.get("item") or "").strip()
            qty = _safe_int(r.get("qty"), 0)
            t = (r.get("tx_type") or "").strip()

            if not item:
                continue

            if t == "add":
                delta = abs(qty); label = "เพิ่มค้างทำ"
            elif t == "done":
                delta = -abs(qty); label = "ทำแล้ว/ส่งแล้ว"
            elif t == "adjust":
                delta = qty; label = "ปรับยอด"
            else:
                continue

            items_now.setdefault(item, 0)
            items_now[item] += int(delta)

            out_rows.append(
                {
                    "id": r.get("id"),
                    "tx_date": safe_date_str(r.get("tx_date")),
                    "type": t,
                    "type_label": label,
                    "item": item,
                    "delta_qty": int(delta),
                    "note": r.get("note") or "",
                    "created_at": r.get("created_at"),
                }
            )

        items_list = [{"item": k, "qty_pending": v} for k, v in items_now.items() if v != 0]
        items_list.sort(key=lambda x: x["qty_pending"], reverse=True)

        return jsonify({"opd": opd, "name": info["name"], "phone": info["phone"], "items_now": items_list, "rows": out_rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/work_tx", methods=["POST"])
@login_required
def api_work_tx():
    try:
        data = request.get_json(silent=True) or {}
        opd = normalize_opd(data.get("opd"))
        tx_date = safe_date_str(data.get("tx_date") or data.get("date"))
        tx_type = (data.get("tx_type") or "").strip()
        item = (data.get("item") or "").strip()
        qty = _safe_int(data.get("qty"), None)
        note = (data.get("note") or "").strip()

        if not opd:
            return jsonify({"error": "missing_opd"}), 400
        if not tx_date:
            return jsonify({"error": "missing_tx_date"}), 400
        if tx_type not in {"add", "done", "adjust"}:
            return jsonify({"error": "invalid_tx_type"}), 400
        if not item:
            return jsonify({"error": "missing_item"}), 400
        if qty is None or qty == 0:
            return jsonify({"error": "qty_required"}), 400

        payload = {"opd": opd, "tx_date": tx_date, "tx_type": tx_type, "item": item, "qty": int(qty), "note": note or None}
        ins = supabase.table("work_transactions").insert(payload).execute()
        row = (ins.data or [{}])[0]
        return jsonify({"success": True, "id": row.get("id")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# Clinic Time Module 
# =============================================================
@app.route("/api/get_appointments")
@login_required
def api_get_appointments():
    try:
        appt_date = safe_date_str(request.args.get("date"))
        if not appt_date:
            return jsonify({"error": "missing_date"}), 400

        res = (
            supabase.table("appointments")
            .select("*")
            .eq("appt_date", appt_date)
            .order("start_time", desc=False)
            .execute()
        )

        rows = res.data or []
        try:
            rows.sort(key=lambda r: (str(r.get("start_time") or ""), str(r.get("column_id") or ""), str(r.get("id") or "")))
        except Exception:
            pass
        return jsonify(rows)

    except Exception as e:
        app.logger.error(f"/api/get_appointments error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/get_appointments_range")
@login_required
def api_get_appointments_range():
    """ดึงนัดหมายหลายวันในครั้งเดียว เช่น /api/get_appointments_range?start=2026-05-01&end=2026-05-31"""
    try:
        start_date = safe_date_str(request.args.get("start") or request.args.get("start_date"))
        end_date = safe_date_str(request.args.get("end") or request.args.get("end_date"))

        if not start_date or not end_date:
            return jsonify({"error": "missing_date_range"}), 400

        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
            end_dt = datetime.strptime(end_date, "%Y-%m-%d").date()
        except Exception:
            return jsonify({"error": "invalid_date_format"}), 400

        if end_dt < start_dt:
            return jsonify({"error": "invalid_date_range"}), 400

        # ไม่จำกัดจำนวนวัน: ถ้าผู้ใช้เลือกทั้งหมด/เลือกช่วงเวลา ต้องได้ข้อมูลจริงครบ
        # ความปลอดภัยเรื่องค้างแก้ด้วยการดึงข้อมูลแบบแบ่งหน้า 1000 แถวต่อรอบด้านล่าง

        base_q = (
            supabase.table("appointments")
            .select("*")
            .gte("appt_date", start_date)
            .lte("appt_date", end_date)
            .order("appt_date", desc=False)
        )
        rows = []
        page_start = 0
        page_size = 1000
        while True:
            res = base_q.range(page_start, page_start + page_size - 1).execute()
            batch = res.data or []
            rows.extend(batch)
            if len(batch) < page_size:
                break
            page_start += page_size
        try:
            rows.sort(key=lambda r: (
                str(r.get("appt_date") or ""),
                str(r.get("start_time") or ""),
                str(r.get("column_id") or ""),
                str(r.get("id") or ""),
            ))
        except Exception:
            pass

        return jsonify(rows)

    except Exception as e:
        app.logger.error(f"/api/get_appointments_range error: {e}")
        return jsonify({"error": str(e)}), 500


def _appt_norm_status_for_search(value: Any) -> str:
    s = str(value or "pending").strip().lower()
    if s in {"confirm", "confirmed"}:
        return "confirmed"
    if s in {"cancel", "canceled", "cancelled"}:
        return "cancelled"
    return "pending"


@app.route("/api/search_appointments")
@login_required
def api_search_appointments():
    """Search appointments directly from Supabase for the Queue filter.

    This endpoint fixes the old frontend-only filter problem. The previous UI only
    filtered rows that were already loaded in cache, so old cancelled appointments
    were invisible. This endpoint queries the appointments table directly and then
    applies status / column / customer type / text filters in Python for maximum
    compatibility with older schemas.
    """
    try:
        start_date = safe_date_str(request.args.get("start") or request.args.get("start_date"))
        end_date = safe_date_str(request.args.get("end") or request.args.get("end_date"))
        range_mode = (request.args.get("range") or "default").strip().lower()
        status_filter = (request.args.get("status") or "all").strip().lower()
        column_filter = (request.args.get("column") or "all").strip().lower()
        type_filter = (request.args.get("type") or "all").strip().lower()
        kw = (request.args.get("q") or "").strip().lower()

        # Validate date range when provided. range=all intentionally has no date bound. range=custom uses the provided start/end dates.
        if range_mode != "all":
            if not start_date or not end_date:
                return jsonify({"success": False, "error": "missing_date_range"}), 400
            try:
                start_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
                end_dt = datetime.strptime(end_date, "%Y-%m-%d").date()
            except Exception:
                return jsonify({"success": False, "error": "invalid_date_format"}), 400
            if end_dt < start_dt:
                return jsonify({"success": False, "error": "invalid_date_range"}), 400
            # ไม่จำกัดจำนวนวัน: เลือกช่วงเวลา/ปีเก่า ๆ ต้องค้นเจอจริง
            # backend จะดึงข้อมูลแบบแบ่งหน้าเพื่อไม่ให้ชน limit ของ Supabase

        q = supabase.table("appointments").select("*")
        if range_mode != "all" and start_date and end_date:
            q = q.gte("appt_date", start_date).lte("appt_date", end_date)
        q = q.order("appt_date", desc=False).order("start_time", desc=False)

        rows: List[Dict[str, Any]] = []
        page_start = 0
        page_size = 1000
        while True:
            resp = q.range(page_start, page_start + page_size - 1).execute()
            batch = resp.data or []
            rows.extend(batch)
            if len(batch) < page_size:
                break
            page_start += page_size

        def _norm_col(v: Any) -> str:
            try:
                return str(int(float(v)))
            except Exception:
                return str(v or "").strip()

        def _row_name(r: Dict[str, Any]) -> str:
            return str(
                r.get("customer_name") or r.get("guest_name") or r.get("display_name") or r.get("name") or ""
            ).strip()

        def _haystack(r: Dict[str, Any]) -> str:
            vals = [
                _row_name(r),
                r.get("guest_phone"), r.get("phone"),
                r.get("service"), r.get("procedure"),
                r.get("opd"), r.get("customer_id"),
                r.get("note"), r.get("status"),
            ]
            return " ".join(str(x or "") for x in vals).lower()

        def _phone_digits(s: str) -> str:
            return re.sub(r"\D", "", s or "")

        out: List[Dict[str, Any]] = []
        kw_digits = _phone_digits(kw)
        for r in rows:
            st = _appt_norm_status_for_search(r.get("status"))
            if status_filter in {"pending", "confirmed", "cancelled"} and st != status_filter:
                continue

            col = _norm_col(r.get("column_id"))
            if column_filter == "doctor":
                if col not in {"1", "2"}:
                    continue
            elif column_filter not in {"", "all"} and col != column_filter:
                continue

            ctype = str(r.get("customer_type") or "new").strip().lower()
            if ctype not in {"old", "new"}:
                ctype = "new"
            if type_filter in {"old", "new"} and ctype != type_filter:
                continue

            if kw:
                hay = _haystack(r)
                if kw not in hay and (not kw_digits or kw_digits not in _phone_digits(hay)):
                    continue

            # Normalize output fields for frontend compatibility.
            r = dict(r)
            r["status"] = st
            r["customer_type"] = ctype
            if not r.get("customer_name"):
                r["customer_name"] = _row_name(r)
            out.append(r)

        out.sort(key=lambda r: (
            str(r.get("appt_date") or ""),
            str(r.get("start_time") or ""),
            _norm_col(r.get("column_id")),
            str(r.get("id") or ""),
        ))

        return jsonify({
            "success": True,
            "rows": out,
            "count": len(out),
            "range": range_mode,
            "start_date": start_date or None,
            "end_date": end_date or None,
        })

    except Exception as e:
        app.logger.error(f"/api/search_appointments error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/save_appointment", methods=["POST"])
@login_required
def api_save_appointment():
    try:
        data = request.get_json(silent=True) or {}

        appt_id = data.get("id")
        appt_date = safe_date_str(data.get("appt_date"))
        start_time = (data.get("start_time") or "").strip()
        end_time = (data.get("end_time") or start_time or "").strip()

        try:
            column_id = int(data.get("column_id") or 0)
        except Exception:
            column_id = 0

        guest_name = (
            data.get("guest_name")
            or data.get("customer_name")
            or data.get("name")
            or ""
        ).strip()

        guest_phone = (
            data.get("guest_phone")
            or data.get("phone")
            or ""
        ).strip()

        service = (data.get("service") or data.get("procedure") or "").strip()
        note = data.get("note")

        allowed_types = {"new", "old"}
        customer_type = (data.get("customer_type") or "new").strip().lower()
        if customer_type not in allowed_types:
            customer_type = "new"

        allowed_status = {"pending", "confirmed", "cancelled"}
        status = (data.get("status") or "pending").strip().lower()
        if status not in allowed_status:
            status = "pending"

        if not guest_name:
            return jsonify({"success": False, "error": "missing_customer_name"}), 400
        if not appt_date or not start_time or not column_id or not service:
            return jsonify({"success": False, "error": "missing_required_fields"}), 400

        # สำคัญ: customer_id ใน Supabase เป็น uuid บางระบบ
        # ห้ามเอาเลข OPD เช่น 0470 ไปใส่ customer_id เด็ดขาด
        def _is_uuid_text(v):
            return bool(re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                str(v or "").strip()
            ))

        incoming_customer_id = data.get("customer_id")
        incoming_customer_id_s = str(incoming_customer_id or "").strip()
        customer_id_uuid = incoming_customer_id_s if _is_uuid_text(incoming_customer_id_s) else None

        # frontend รุ่นเก่าอาจส่ง OPD มาใน customer_id ด้วย จึงต้องดึงกลับไปไว้ที่ opd
        opd_raw = data.get("opd")
        if not opd_raw and incoming_customer_id_s and not customer_id_uuid:
            opd_raw = incoming_customer_id_s
        opd = normalize_opd(opd_raw) if opd_raw else ""

        # กันคิวซ้ำวันเดียวกัน + เวลาเดียวกัน + ช่องเดียวกัน ยกเว้นรายการที่ cancelled
        try:
            dup_res = (
                supabase.table("appointments")
                .select("id,start_time,status,guest_name")
                .eq("appt_date", appt_date)
                .eq("column_id", column_id)
                .execute()
            )
            for row in dup_res.data or []:
                if appt_id and str(row.get("id")) == str(appt_id):
                    continue
                if (row.get("status") or "pending").lower() == "cancelled":
                    continue
                row_time = str(row.get("start_time") or "")[:5]
                if row_time == start_time[:5]:
                    return jsonify({
                        "success": False,
                        "error": "slot_already_booked",
                        "message": f"เวลานี้มีคิวแล้ว: {row.get('guest_name') or '-'}",
                    }), 409
        except Exception as dup_err:
            app.logger.warning(f"Duplicate appointment check skipped: {dup_err}")

        base_payload = {
            "appt_date": appt_date,
            "start_time": start_time,
            "end_time": end_time,
            "column_id": column_id,
            "guest_name": guest_name if guest_name else None,
            "guest_phone": guest_phone if guest_phone else None,
            "service": service,
            "status": status,
            "customer_type": customer_type,
            "note": note,
        }

        # รองรับฐานข้อมูลหลายเวอร์ชัน:
        # - เวอร์ชันใหม่มี opd และ/หรือ customer_id
        # - เวอร์ชันเก่าอาจไม่มีคอลัมน์ใดคอลัมน์หนึ่ง
        # แต่ทุกกรณีจะไม่ใส่ OPD ลง customer_id อีกแล้ว
        candidate_payloads = []

        p = dict(base_payload)
        if customer_id_uuid:
            p["customer_id"] = customer_id_uuid
        if opd:
            p["opd"] = opd
        candidate_payloads.append(p)

        if opd:
            p = dict(base_payload)
            p["opd"] = opd
            candidate_payloads.append(p)

        if customer_id_uuid:
            p = dict(base_payload)
            p["customer_id"] = customer_id_uuid
            candidate_payloads.append(p)

        candidate_payloads.append(dict(base_payload))

        last_err = None
        saved_res = None
        for payload in candidate_payloads:
            try:
                if appt_id:
                    saved_res = (
                        supabase.table("appointments")
                        .update(payload)
                        .eq("id", appt_id)
                        .execute()
                    )
                else:
                    insert_payload = dict(payload)
                    insert_payload["created_at"] = datetime.now(timezone.utc).isoformat()
                    saved_res = supabase.table("appointments").insert(insert_payload).execute()
                last_err = None
                break
            except Exception as e:
                last_err = e
                msg = str(e).lower()
                # ถ้าพังเพราะคอลัมน์ไม่มี / schema cache / type uuid ให้ลอง payload ที่ตัด field เสี่ยงออก
                if (
                    "customer_id" in msg or "opd" in msg or "schema" in msg or
                    "column" in msg or "could not find" in msg or "uuid" in msg
                ):
                    continue
                raise

        if last_err is not None:
            raise last_err

        row = (saved_res.data or [{}])[0] if getattr(saved_res, "data", None) else {}
        return jsonify({"success": True, "row": row}), 200

    except Exception as e:
        app.logger.error(f"Save Appt Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/search_customer_simple")
@login_required
def api_search_customer_simple():
    try:
        q = (request.args.get("q") or "").strip()

        if not q or len(q) < 1:
            return jsonify([])

        res = (
            supabase.table("customers")
            .select("opd,name,full_name,phone")
            .or_(f"name.ilike.%{q}%,full_name.ilike.%{q}%")
            .limit(10)
            .execute()
        )

        rows = res.data or []

        for r in rows:
            display_name = (r.get("name") or "").strip()

            r["display_name"] = display_name

        return jsonify(rows)

    except Exception as e:
        app.logger.error(f"Search customer error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_appointment", methods=["POST"])
@login_required
def api_delete_appointment():
    try:
        data = request.get_json(silent=True) or {}
        appt_id = data.get("id")

        if not appt_id:
            return jsonify({"error": "missing_id"}), 400

        supabase.table("appointments").delete().eq("id", appt_id).execute()

        return jsonify({"success": True})

    except Exception as e:
        app.logger.error(f"Delete Appt Error: {e}")
        return jsonify({"error": str(e)}), 500

_ALLOWED_APPT_STATUS = {"pending", "confirmed", "cancelled"}

def _normalize_appt_status(s):
    s = (s or "").strip().lower()
    return s if s in _ALLOWED_APPT_STATUS else "pending"


@app.route("/api/set_appointment_status", methods=["POST"])
@login_required
def api_set_appointment_status():
    try:
        data = request.get_json(silent=True) or {}
        appt_id = data.get("id")
        status = _normalize_appt_status(data.get("status"))

        if not appt_id:
            return jsonify({"success": False, "error": "missing_id"}), 400

        patch = {"status": status}

        # ✅ อัปเดต (ห้าม chain .select/.single)
        upd = (
            supabase.table("appointments")
            .update(patch)
            .eq("id", appt_id)
            .execute()
        )

        # (optional) ถ้าอยากส่ง row กลับไป ก็ query อีกรอบ
        row = (
            supabase.table("appointments")
            .select("*")
            .eq("id", appt_id)
            .single()
            .execute()
        ).data

        return jsonify({"success": True, "row": row}), 200

    except Exception as e:
        app.logger.error(f"Set Appt Status Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500




# =============================================================
# STAFF MANAGEMENT API
# =============================================================
@app.route("/api/staffs", methods=["GET", "POST", "DELETE"])
@login_required
def api_staffs_mgmt():
    try:
        if request.method == "GET":
            res = supabase.table("staffs").select("*").order("id").execute()
            return jsonify(res.data or [])

        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            
            payload = {
                "name": data.get("name"),
                "role": data.get("role"),
                "color_code": data.get("color_code"),
                "is_active": True
            }

            if data.get("id"):
                staff_id = data.get("id")
                supabase.table("staffs").update(payload).eq("id", staff_id).execute()
            else:
                supabase.table("staffs").insert(payload).execute()
            
            return jsonify({"success": True})

        if request.method == "DELETE":
            staff_id = request.args.get("id")
            if not staff_id:
                data = request.get_json(silent=True) or {}
                staff_id = data.get("id")
            
            if not staff_id:
                return jsonify({"error": "Missing ID"}), 400

            supabase.table("staffs").delete().eq("id", staff_id).execute()
            return jsonify({"success": True})

    except Exception as e:
        print(f"Staff API Error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================
# ROSTER API
# =============================================================

@app.route("/api/get_roster")
@login_required
def api_get_roster():
    try:
        month = request.args.get("month") # รูปแบบ YYYY-MM
        if not month: return jsonify([])
        
        start_date = f"{month}-01"
        year, mnth = map(int, month.split('-'))
        if mnth == 12:
            next_month = f"{year+1}-01-01"
        else:
            next_month = f"{year}-{mnth+1:02d}-01"

        roster_res = (
            supabase.table("work_schedules")
            .select("*")
            .gte("date", start_date)
            .lt("date", next_month)
            .execute()
        )
        rosters = roster_res.data or []

        staff_res = supabase.table("staffs").select("id,name,role,color_code").execute()
        staff_map = {s['id']: s for s in staff_res.data or []}

        for r in rosters:
            sid = r.get('staff_id')
            if sid in staff_map:
                r['staff_name'] = staff_map[sid]['name']
                r['staff_role'] = staff_map[sid]['role']
                r['staff_color'] = staff_map[sid]['color_code']
            else:
                r['staff_name'] = 'Unknown'
                r['staff_role'] = '-'
                r['staff_color'] = '#cbd5e1'

        return jsonify(rosters)
    except Exception as e:
        print(f"Get Roster Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/save_roster", methods=["POST"])
@login_required
def api_save_roster():
    try:
        data = request.get_json(silent=True) or {}
        
        payload = {
            "staff_id": data.get("staff_id"),
            "date": data.get("date"),
            "work_type": data.get("work_type", "work"), 
            "start_time": data.get("start_time"),
            "end_time": data.get("end_time"),
            "note": data.get("note", ""),
            
        }

        if payload["work_type"] == "leave":
            payload["start_time"] = None
            payload["end_time"] = None
        else:
            if not payload["start_time"]: payload["start_time"] = "11:00"
            if not payload["end_time"]: payload["end_time"] = "20:00"

        if data.get("id"):
            roster_id = data.get("id")
            supabase.table("work_schedules").update(payload).eq("id", roster_id).execute()
        else:
            supabase.table("work_schedules").insert(payload).execute()

        return jsonify({"success": True})

    except Exception as e:
        print(f"Save Roster Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_roster", methods=["POST"])
@login_required
def api_delete_roster():
    try:
        data = request.get_json(silent=True) or {}
        rid = data.get("id")
        
        if not rid:
            return jsonify({"error": "Missing ID"}), 400

        supabase.table("work_schedules").delete().eq("id", rid).execute()
        
        return jsonify({"success": True})

    except Exception as e:
        print(f"Delete Error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================
# Customer Image / Gallery / OCR System (Unified)
# =============================================================
# แนวคิดใหม่:
# - รูปทุกชนิดเข้า customer_gallery ได้ทางเดียว
# - รูปโปรไฟล์ใช้ URL จาก gallery เดียวกัน แล้ว update customers.profile_pic_url
# - OCR อ่านจากไฟล์ก่อน แล้วค่อยบันทึกรูปบัตรเมื่ออ่านสำเร็จ เพื่อลดรูปซ้ำ/รูปค้าง
# - รองรับ schema เดิมของ customer_gallery ที่มีแค่ opd,image_url และ schema ใหม่ที่มี image_type/cloudinary_public_id/is_profile

CUSTOMER_ALLOWED_PATCH_FIELDS = {
    "name", "full_name", "phone", "birthMonth", "birth_th_ddmmyyyy",
    "facebook_name", "national_id", "vip", "address", "profile", "note", "profile_pic_url"
}

IMAGE_TYPE_ALLOWED = {"gallery", "profile", "id_card", "before", "after", "document"}


def _truthy(v: Any) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _clean_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _normalize_birth_month(v: Any) -> Optional[str]:
    s = str(v or "").strip()
    if not s:
        return None
    s = re.sub(r"\D", "", s)
    if not s:
        return None
    try:
        n = int(s)
        if 1 <= n <= 12:
            return str(n).zfill(2)
    except Exception:
        return None
    return None


def _normalize_image_type(v: Any) -> str:
    s = str(v or "gallery").strip().lower()
    return s if s in IMAGE_TYPE_ALLOWED else "gallery"


def _is_allowed_image_file(file_obj: Any) -> bool:
    filename = (getattr(file_obj, "filename", "") or "").lower()
    mimetype = (getattr(file_obj, "mimetype", "") or "").lower()
    allowed_ext = filename.endswith((".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif"))
    allowed_mime = mimetype.startswith("image/")
    return bool(allowed_ext or allowed_mime)


def _gallery_folder(opd: str, image_type: str) -> str:
    image_type = _normalize_image_type(image_type)
    if image_type == "profile":
        return f"clinic_gallery/{opd}/profile"
    if image_type == "id_card":
        return f"clinic_gallery/{opd}/id_card"
    return f"clinic_gallery/{opd}/{image_type}"


def _upload_image_to_cloudinary(file_obj: Any, opd: str, image_type: str = "gallery") -> Dict[str, Any]:
    if hasattr(file_obj, "seek"):
        try:
            file_obj.seek(0)
        except Exception:
            pass

    image_type = _normalize_image_type(image_type)
    result = cloudinary.uploader.upload(
        file_obj,
        folder=_gallery_folder(opd, image_type),
        resource_type="image",
    )
    return {
        "image_url": result.get("secure_url") or result.get("url"),
        "cloudinary_public_id": result.get("public_id"),
        "image_type": image_type,
    }


def _insert_gallery_row(opd: str, image_url: str, image_type: str = "gallery", public_id: Optional[str] = None, is_profile: bool = False) -> Optional[Dict[str, Any]]:
    """Insert gallery row. Supports both old and new table schemas."""
    if not opd or not image_url:
        return None

    image_type = _normalize_image_type(image_type)
    new_row = {
        "opd": opd,
        "image_url": image_url,
        "image_type": image_type,
        "cloudinary_public_id": public_id,
        "is_profile": bool(is_profile),
    }

    try:
        res = supabase.table("customer_gallery").insert(new_row).execute()
        return (res.data or [new_row])[0] if isinstance(res.data, list) else new_row
    except Exception as e:
        # Fallback สำหรับฐานข้อมูลเดิมที่ยังไม่มี image_type/cloudinary_public_id/is_profile
        app.logger.warning(f"Gallery insert fallback to legacy schema: {e}")
        legacy_row = {"opd": opd, "image_url": image_url}
        try:
            res = supabase.table("customer_gallery").insert(legacy_row).execute()
            return (res.data or [legacy_row])[0] if isinstance(res.data, list) else legacy_row
        except Exception as e2:
            app.logger.error(f"Gallery insert failed: {e2}")
            raise


def _set_customer_profile_url(opd: str, image_url: Optional[str]) -> None:
    if not opd:
        return
    supabase.table("customers").update({"profile_pic_url": image_url}).eq("opd", opd).execute()


def _clean_customer_payload_from_form(form: Any) -> Dict[str, Any]:
    payload = {
        "opd": normalize_opd(form.get("opd")),
        "birthMonth": _normalize_birth_month(form.get("birthMonth")),
        "birth_th_ddmmyyyy": _clean_str(form.get("birth_th_ddmmyyyy")),
        "name": _clean_str(form.get("name")),
        "full_name": _clean_str(form.get("full_name")),
        "phone": _clean_str(form.get("phone")),
        "facebook_name": _clean_str(form.get("facebook_name")),
        "national_id": _clean_str(form.get("national_id")),
        "vip": _clean_str(form.get("vip")),
        "address": _clean_str(form.get("address")),
        "profile": _clean_str(form.get("profile")),
        "note": _clean_str(form.get("note")),
    }
    return {k: v for k, v in payload.items() if v is not None and v != ""}


def _try_get_gallery_row(img_id: Any) -> Optional[Dict[str, Any]]:
    try:
        res = supabase.table("customer_gallery").select("*").eq("id", img_id).maybe_single().execute()
        return res.data or None
    except Exception:
        try:
            res = supabase.table("customer_gallery").select("*").eq("id", img_id).execute()
            rows = res.data or []
            return rows[0] if rows else None
        except Exception:
            return None


def _parse_cloudinary_public_id_from_url(url: str) -> Optional[str]:
    """Best-effort public_id extraction for old rows that don't store cloudinary_public_id."""
    if not url or "cloudinary" not in url:
        return None
    try:
        # Example: .../upload/v123456/clinic_gallery/0001/gallery/abc.jpg
        marker = "/upload/"
        after = url.split(marker, 1)[1]
        parts = after.split("/")
        if parts and re.match(r"^v\d+$", parts[0]):
            parts = parts[1:]
        public_with_ext = "/".join(parts)
        return re.sub(r"\.[a-zA-Z0-9]+$", "", public_with_ext)
    except Exception:
        return None


def _destroy_cloudinary_public_id(public_id: Optional[str]) -> bool:
    if not public_id:
        return False
    try:
        cloudinary.uploader.destroy(public_id, resource_type="image")
        return True
    except Exception as e:
        app.logger.warning(f"Cloudinary destroy failed for {public_id}: {e}")
        return False


@app.route('/api/get_gallery')
@login_required
def get_gallery():
    opd = normalize_opd(request.args.get('opd'))
    image_type = request.args.get('image_type')
    if not opd:
        return jsonify([])
    try:
        q = supabase.table("customer_gallery").select("*").eq("opd", opd)
        if image_type:
            q = q.eq("image_type", _normalize_image_type(image_type))
        try:
            res = q.order("created_at", desc=True).execute()
        except Exception:
            res = q.execute()
        rows = res.data or []
        return jsonify(rows)
    except Exception as e:
        app.logger.error(f"get_gallery error: {e}")
        return jsonify([])


@app.route('/api/upload_gallery', methods=['POST'])
@login_required
def upload_gallery():
    try:
        opd = normalize_opd(request.form.get('opd'))
        image_type = _normalize_image_type(request.form.get('image_type'))
        set_profile = _truthy(request.form.get('set_profile')) or image_type == "profile"

        if not opd or len(opd) != 4:
            return jsonify({"error": "invalid_opd"}), 400

        images = request.files.getlist('images') or request.files.getlist('image') or request.files.getlist('profile_pic')
        if not images:
            return jsonify({"error": "no_images"}), 400

        saved_rows = []
        uploaded_urls = []

        for img in images:
            if not img or not _is_allowed_image_file(img):
                continue
            uploaded = _upload_image_to_cloudinary(img, opd, image_type)
            url = uploaded.get("image_url")
            if not url:
                continue

            row = _insert_gallery_row(
                opd=opd,
                image_url=url,
                image_type=image_type,
                public_id=uploaded.get("cloudinary_public_id"),
                is_profile=set_profile,
            )
            saved_rows.append(row or {"opd": opd, "image_url": url})
            uploaded_urls.append(url)

        if not uploaded_urls:
            return jsonify({"error": "no_valid_images"}), 400

        if set_profile:
            _set_customer_profile_url(opd, uploaded_urls[-1])

        return jsonify({"status": "success", "count": len(uploaded_urls), "urls": uploaded_urls, "rows": saved_rows})

    except Exception as e:
        app.logger.error(f"Gallery upload error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/set_profile_image', methods=['POST'])
@login_required
def set_profile_image():
    try:
        data = request.get_json(silent=True) or {}
        opd = normalize_opd(data.get('opd'))
        image_url = _clean_str(data.get('image_url'))
        image_id = data.get('id')

        if image_id and not image_url:
            row = _try_get_gallery_row(image_id)
            if row:
                image_url = row.get('image_url')
                opd = opd or normalize_opd(row.get('opd'))

        if not opd or not image_url:
            return jsonify({"error": "missing_opd_or_image"}), 400

        _set_customer_profile_url(opd, image_url)
        try:
            supabase.table("customer_gallery").update({"is_profile": False}).eq("opd", opd).execute()
            if image_id:
                supabase.table("customer_gallery").update({"is_profile": True, "image_type": "profile"}).eq("id", image_id).execute()
        except Exception:
            pass

        return jsonify({"status": "success", "profile_pic_url": image_url})
    except Exception as e:
        app.logger.error(f"set_profile_image error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/delete_gallery_image', methods=['POST'])
@login_required
def delete_gallery_image():
    try:
        data = request.get_json(silent=True) or {}
        img_id = data.get('id')
        if not img_id:
            return jsonify({"error": "missing_id"}), 400

        row = _try_get_gallery_row(img_id)
        image_url = (row or {}).get('image_url')
        opd = normalize_opd((row or {}).get('opd'))
        public_id = (row or {}).get('cloudinary_public_id') or _parse_cloudinary_public_id_from_url(image_url or "")

        # ลบ DB ก่อนเพื่อให้ UI ไม่เห็นแล้ว แม้ cloud delete จะ fail ก็ไม่ block ผู้ใช้
        supabase.table("customer_gallery").delete().eq("id", img_id).execute()
        _destroy_cloudinary_public_id(public_id)

        if opd and image_url:
            try:
                # ถ้ารูปนี้เป็น profile อยู่ ให้เคลียร์ออก เพื่อไม่ชี้ URL ที่ลบแล้ว
                supabase.table("customers").update({"profile_pic_url": None}).eq("opd", opd).eq("profile_pic_url", image_url).execute()
            except Exception:
                pass

        return jsonify({"status": "deleted"})
    except Exception as e:
        app.logger.error(f"delete_gallery_image error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/update_customer_with_image', methods=['POST'])
@login_required
def update_customer_with_image():
    try:
        form = request.form
        opd = normalize_opd(form.get("opd"))
        if not opd:
            return jsonify({"error": "missing_opd"}), 400

        patch = _clean_customer_payload_from_form(form)
        patch.pop("opd", None)

        profile_file = request.files.get('profile_pic')
        existing_url = _clean_str(form.get("existing_profile_url"))

        if profile_file and _is_allowed_image_file(profile_file):
            uploaded = _upload_image_to_cloudinary(profile_file, opd, "profile")
            profile_url = uploaded.get("image_url")
            if profile_url:
                _insert_gallery_row(
                    opd=opd,
                    image_url=profile_url,
                    image_type="profile",
                    public_id=uploaded.get("cloudinary_public_id"),
                    is_profile=True,
                )
                patch["profile_pic_url"] = profile_url
        elif existing_url:
            patch["profile_pic_url"] = existing_url

        if patch:
            supabase.table("customers").update(patch).eq("opd", opd).execute()

        return jsonify({"status": "success", "profile_pic_url": patch.get("profile_pic_url")})

    except Exception as e:
        app.logger.error(f"Update Image Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/add_customer_v2', methods=['POST'])
@login_required
def add_customer_v2():
    try:
        form = request.form
        opd = normalize_opd(form.get('opd'))
        if not opd or len(opd) != 4:
            return jsonify({"error": "invalid_opd"}), 400

        existing = supabase.table("customers").select("opd").eq("opd", opd).execute()
        if existing.data:
            return jsonify({"error": "duplicate_opd", "message": "มีเลข OPD นี้ในระบบแล้ว"}), 400

        customer_data = _clean_customer_payload_from_form(form)
        customer_data["opd"] = opd

        profile_file = request.files.get('profile_pic')
        existing_profile_url = _clean_str(form.get("existing_profile_url"))

        uploaded_profile = None
        if profile_file and _is_allowed_image_file(profile_file):
            uploaded_profile = _upload_image_to_cloudinary(profile_file, opd, "profile")
            if uploaded_profile.get("image_url"):
                customer_data["profile_pic_url"] = uploaded_profile["image_url"]
        elif existing_profile_url:
            customer_data["profile_pic_url"] = existing_profile_url

        supabase.table('customers').insert(customer_data).execute()

        if uploaded_profile and uploaded_profile.get("image_url"):
            _insert_gallery_row(
                opd=opd,
                image_url=uploaded_profile["image_url"],
                image_type="profile",
                public_id=uploaded_profile.get("cloudinary_public_id"),
                is_profile=True,
            )

        return jsonify({"status": "success", "profile_pic_url": customer_data.get("profile_pic_url")})

    except Exception as e:
        app.logger.error(f"Error adding customer v2: {e}")
        return jsonify({"error": str(e)}), 500


def _parse_gemini_json(text_response: str) -> Dict[str, Any]:
    text_response = (text_response or "").strip()
    if text_response.startswith("```"):
        text_response = text_response.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(text_response)
    except Exception:
        # Best-effort: extract {...}
        m = re.search(r"\{.*\}", text_response, flags=re.S)
        if m:
            return json.loads(m.group(0))
        raise


def _extract_idcard_from_pil_image(img: Image.Image) -> Dict[str, Any]:
    prompt = """
Task: Extract Thai National ID Card data into JSON.
Output MUST be pure JSON only. No markdown formatting.

Fields:
- id_number (string, 13 digits only)
- title_th (string, e.g., นาย, นาง, นางสาว)
- first_name_th (string)
- last_name_th (string)
- birth_date (string, format: dd/mm/yyyy in Thai Year BE 25xx)
- address (string, full address in Thai)

If a field is unclear or missing, use null.
"""
    model_names = [
        os.getenv("GEMINI_MODEL", "").strip(),
        "models/gemini-2.0-flash",
        "gemini-2.0-flash",
        "models/gemini-1.5-flash",
        "gemini-1.5-flash",
    ]
    last_err = None
    for model_name in [m for m in model_names if m]:
        try:
            model = genai.GenerativeModel(model_name)
            result = model.generate_content([prompt, img])
            return _parse_gemini_json(result.text)
        except Exception as e:
            last_err = e
            app.logger.warning(f"Gemini OCR failed with {model_name}: {e}")
            continue
    raise last_err or RuntimeError("gemini_ocr_failed")


@app.route('/api/idcard_extract_upload', methods=['POST'])
@login_required
def api_idcard_extract_upload():
    """OCR จากไฟล์โดยตรง: อ่านสำเร็จแล้วค่อยเก็บรูปเป็น image_type=id_card"""
    try:
        opd = normalize_opd(request.form.get('opd'))
        save_image = _truthy(request.form.get('save_image') or 'true')
        file_obj = request.files.get('file') or request.files.get('image') or request.files.get('id_card')

        if not file_obj:
            return jsonify({"error": "no_file"}), 400
        if not _is_allowed_image_file(file_obj):
            return jsonify({"error": "invalid_image_type"}), 400

        img = Image.open(file_obj.stream)
        extracted = _extract_idcard_from_pil_image(img)

        # ถ้า OCR ไม่ได้ข้อมูลอะไรเลย ไม่บันทึกรูป เพื่อลดรูปค้างในระบบ
        meaningful = any(extracted.get(k) for k in ["id_number", "first_name_th", "last_name_th", "birth_date", "address"])
        if not meaningful:
            return jsonify({"error": "no_data_extracted", "data": extracted}), 422

        image_url = None
        if save_image and opd and len(opd) == 4:
            uploaded = _upload_image_to_cloudinary(file_obj, opd, "id_card")
            image_url = uploaded.get("image_url")
            if image_url:
                _insert_gallery_row(
                    opd=opd,
                    image_url=image_url,
                    image_type="id_card",
                    public_id=uploaded.get("cloudinary_public_id"),
                    is_profile=False,
                )

        extracted["image_url"] = image_url
        return jsonify(extracted)

    except Exception as e:
        app.logger.error(f"idcard_extract_upload error: {e}")
        return jsonify({"error": str(e)}), 500

# =============================================================
# Gemini AI - ID Card Extract
# =============================================================
@app.route('/api/idcard_extract', methods=['POST'])
@login_required
def api_idcard_extract():
    import json

    try:
        data = request.get_json(silent=True) or {}
        image_url = data.get('image_url')

        if not image_url:
            return jsonify({"error": "No image URL provided."}), 400

        print(f"🤖 Gemini reading form: {image_url}")
        response = requests.get(image_url)
        img_bytes = BytesIO(response.content)
        img = Image.open(img_bytes)

        # ใช้โมเดลล่าสุด
        model = genai.GenerativeModel('models/gemini-2.0-flash') 
        
        prompt = """
        Task: Extract Thai National ID Card data into JSON.
        Output MUST be pure JSON only. No markdown formatting.
        
        Fields:
        - id_number (string, 13 digits only)
        - title_th (string, e.g., นาย, นาง, นางสาว)
        - first_name_th (string)
        - last_name_th (string)
        - birth_date (string, format: dd/mm/yyyy in Thai Year BE 25xx)
        - address (string, full address in Thai)
        
        If a field is unclear or missing, use null.
        """

        result = model.generate_content([prompt, img])
        
        text_response = result.text.strip()
        if text_response.startswith("```"):
            text_response = text_response.replace("```json", "").replace("```", "").strip()
        
        print("Gemini Output:", text_response)
        
        return jsonify(json.loads(text_response))

    except Exception as e:
        print(f"Gemini Error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)

    # =============================================================
# TAX DISPLAY ADDITIONS (เพิ่มใน app.py)
# สำหรับคอลัมน์ sales_records.tax_display = 'show' / 'noshow'
# อ้างอิงจาก app.py เดิมที่มี /api/sales ใช้งาน select('*') อยู่แล้ว
# ดังนั้น /api/sales จะส่ง tax_display กลับมาให้อัตโนมัติหลังเพิ่มคอลัมน์ใน Supabase
# =============================================================

# -----------------------------
# Helper: normalize tax_display
# วางไว้แถว Helpers อื่น ๆ ใน app.py
# -----------------------------
def _normalize_tax_display(v: Any) -> str:
    s = str(v or "").strip().lower()
    return s if s in {"show", "noshow"} else "show"


# -----------------------------
# API: save tax_display แบบหลายบิลพร้อมกัน
# ใช้ตอนหน้าเว็บกดปุ่ม "บันทึก"
# รับ payload แบบ:
# {
#   "updates": [
#     {"id": 1, "tax_display": "show"},
#     {"id": 2, "tax_display": "noshow"}
#   ]
# }
# -----------------------------
@app.route("/api/save_tax_display", methods=["POST"])
@login_required
def api_save_tax_display():
    try:
        data = request.get_json(silent=True) or {}
        updates = data.get("updates") or []

        if not isinstance(updates, list) or not updates:
            return jsonify({"error": "updates_required"}), 400

        updated_count = 0
        errors = []

        for idx, row in enumerate(updates):
            if not isinstance(row, dict):
                errors.append({"index": idx, "error": "invalid_row"})
                continue

            record_id = row.get("id")
            if not record_id:
                errors.append({"index": idx, "error": "missing_id"})
                continue

            tax_display = _normalize_tax_display(row.get("tax_display"))

            try:
                res = (
                    supabase.table("sales_records")
                    .update({"tax_display": tax_display})
                    .eq("id", record_id)
                    .execute()
                )
                if res.data:
                    updated_count += 1
                else:
                    errors.append({"index": idx, "id": record_id, "error": "not_found_or_not_updated"})
            except Exception as inner_e:
                errors.append({"index": idx, "id": record_id, "error": str(inner_e)})

        return jsonify({
            "success": True,
            "updated": updated_count,
            "errors": errors,
        }), 200

    except Exception as e:
        app.logger.error(f"/api/save_tax_display error: {e}")
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: เลือกทั้งหมด / ยกเลิกทั้งหมด ตามช่วงวันที่หรือเดือน
# ใช้กับปุ่ม "เลือกทั้งหมด" หรือ "ยกเลิกทั้งหมด"
# รับ payload ได้ 2 แบบ
# แบบเดือนเดียว:
# {
#   "month": "2026-04",
#   "tax_display": "show"
# }
#
# แบบช่วงวันที่:
# {
#   "start_date": "2026-04-01",
#   "end_date": "2026-04-30",
#   "tax_display": "noshow"
# }
#
# optional: ใส่ opd หรือ date เพิ่มได้ ถ้าจะกรองเฉพาะบางกลุ่ม
# -----------------------------
@app.route("/api/set_all_tax_display", methods=["POST"])
@login_required
def api_set_all_tax_display():
    try:
        data = request.get_json(silent=True) or {}
        tax_display = _normalize_tax_display(data.get("tax_display"))

        month = (data.get("month") or "").strip()
        date = safe_date_str(data.get("date")) if data.get("date") else ""
        start_date = safe_date_str(data.get("start_date")) if data.get("start_date") else ""
        end_date = safe_date_str(data.get("end_date")) if data.get("end_date") else ""
        opd = normalize_opd(data.get("opd")) if data.get("opd") else ""

        # ถ้าส่ง month มา แต่ไม่ได้ส่ง start/end ให้แปลงเป็นช่วงวันของเดือนนั้น
        if month and not start_date and not end_date:
            m = re.match(r"^(\d{4})-(\d{2})$", month)
            if not m:
                return jsonify({"error": "invalid_month_format_use_YYYY_MM"}), 400

            y = int(m.group(1))
            mo = int(m.group(2))
            if mo < 1 or mo > 12:
                return jsonify({"error": "invalid_month_value"}), 400

            start_date = f"{y}-{str(mo).zfill(2)}-01"
            if mo == 12:
                next_month = datetime(y + 1, 1, 1)
            else:
                next_month = datetime(y, mo + 1, 1)
            end_date = (next_month - timedelta(days=1)).strftime("%Y-%m-%d")

        q = supabase.table("sales_records").update({"tax_display": tax_display})

        has_filter = False
        if opd:
            q = q.eq("opd", opd)
            has_filter = True
        if date:
            q = q.eq("date", date)
            has_filter = True
        if start_date:
            q = q.gte("date", start_date)
            has_filter = True
        if end_date:
            q = q.lte("date", end_date)
            has_filter = True

        if not has_filter:
            return jsonify({"error": "at_least_one_filter_required"}), 400

        res = q.execute()
        affected = len(res.data or [])

        return jsonify({
            "success": True,
            "tax_display": tax_display,
            "affected": affected,
            "month": month or None,
            "date": date or None,
            "start_date": start_date or None,
            "end_date": end_date or None,
            "opd": opd or None,
        }), 200

    except Exception as e:
        app.logger.error(f"/api/set_all_tax_display error: {e}")
        return jsonify({"error": str(e)}), 500



# =============================================================
# API — Full AI Chatbot Export (single ZIP file)
# =============================================================
def _ai_json_default(obj):
    try:
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
    except Exception:
        pass
    return str(obj)


def _ai_to_jsonl(rows: List[Dict[str, Any]]) -> str:
    return "\n".join(json.dumps(r, ensure_ascii=False, default=_ai_json_default) for r in (rows or [])) + ("\n" if rows else "")


def _ai_fetch_table_all(table_name: str, select_expr: str = "*") -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Fetch every row from a Supabase table with pagination.

    Missing legacy tables are reported in metadata but do not break the export.
    """
    rows: List[Dict[str, Any]] = []
    start = 0
    limit = 1000
    try:
        while True:
            res = supabase.table(table_name).select(select_expr).range(start, start + limit - 1).execute()
            batch = res.data or []
            if not isinstance(batch, list):
                batch = []
            rows.extend(batch)
            if len(batch) < limit:
                break
            start += limit
        return rows, None
    except Exception as e:
        return [], str(e)


def _ai_num(v: Any, default: float = 0.0) -> float:
    try:
        if v in (None, ""):
            return default
        return float(v)
    except Exception:
        return default


def _ai_int(v: Any, default: int = 0) -> int:
    try:
        if v in (None, ""):
            return default
        return int(float(v))
    except Exception:
        return default


def _ai_parse_sale_item(item: Any) -> Dict[str, Any]:
    """Normalize sale item for chatbot usage while keeping original label.

    Supports old string format and newer object format.
    """
    out = {
        "label": "",
        "category": "",
        "name": "",
        "qty": 1,
        "price": None,
        "raw": item,
    }

    if isinstance(item, dict):
        category = str(item.get("category") or item.get("main") or item.get("group") or "").strip()
        name = str(item.get("name") or item.get("subitem") or item.get("sub") or item.get("label") or item.get("product") or "").strip()
        label = str(item.get("label") or "").strip()
        qty = _ai_int(item.get("qty") or item.get("quantity") or item.get("count"), 1)
        price_raw = item.get("price") if item.get("price") is not None else item.get("unit_price")
        price = None if price_raw in (None, "") else _ai_num(price_raw, 0)

        # Handle name like "งานผิว (Rejuran)" when category is missing.
        if not category and name:
            m = re.match(r"^(.*?)\s*\((.*?)\)\s*$", name)
            if m:
                category = (m.group(1) or "").strip()
                name = (m.group(2) or "").strip()

        if not label:
            if category and name:
                label = f"{category} ({name})"
            else:
                label = name or category

        out.update({"label": label, "category": category, "name": name or label, "qty": max(1, qty), "price": price})
        return out

    text = str(item or "").strip()
    out["label"] = text
    if not text:
        return out

    base = text
    qty = 1
    price = None
    m = re.match(r"^(.*?)\s*-\s*(\d+(?:\.\d+)?)\s*ชิ้น\s*x\s*(\d+(?:\.\d+)?)\s*บาท?", text)
    if m:
        base = (m.group(1) or "").strip()
        qty = _ai_int(m.group(2), 1)
        price = _ai_num(m.group(3), 0)
    else:
        m2 = re.match(r"^(.*?)\s*-\s*(\d+(?:\.\d+)?)\s*ชิ้น", text)
        if m2:
            base = (m2.group(1) or "").strip()
            qty = _ai_int(m2.group(2), 1)

    category = ""
    name = base
    m3 = re.match(r"^(.*?)\s*\((.*?)\)\s*$", base)
    if m3:
        category = (m3.group(1) or "").strip()
        name = (m3.group(2) or "").strip()

    out.update({"category": category, "name": name or base, "qty": max(1, qty), "price": price})
    return out


def _ai_normalize_sale_items(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = row.get("item")
    if raw is None:
        raw = row.get("items")
    items = _ensure_item_list(raw)
    return [_ai_parse_sale_item(x) for x in items if x not in (None, "")]


def _ai_build_sales_full(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in rows or []:
        rr = dict(r)
        rr["opd"] = normalize_opd(rr.get("opd"))
        rr["date"] = safe_date_str(rr.get("date"))
        rr["amount"] = _ai_num(rr.get("amount"), 0)
        rr["items_normalized"] = _ai_normalize_sale_items(rr)
        rr["items_text"] = _coerce_items_to_text_list(rr.get("item") if rr.get("item") is not None else rr.get("items"))
        out.append(rr)
    return out


def _ai_build_daily_summary(sales_rows: List[Dict[str, Any]], pending_rows: List[Dict[str, Any]], appt_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_day: Dict[str, Dict[str, Any]] = {}

    def day_obj(d: str) -> Dict[str, Any]:
        if d not in by_day:
            by_day[d] = {
                "date": d,
                "total_sales": 0,
                "bill_count": 0,
                "unique_customers": 0,
                "customer_opds": set(),
                "payment_methods": defaultdict(int),
                "top_items_counter": defaultdict(int),
                "ar_total": 0,
                "pending_work_count": 0,
                "appointment_count": 0,
                "appointment_statuses": defaultdict(int),
                "doctor_case_count": 0,
                "iv_case_count": 0,
            }
        return by_day[d]

    for r in sales_rows or []:
        d = safe_date_str(r.get("date"))
        if not d:
            continue
        o = day_obj(d)
        o["bill_count"] += 1
        o["total_sales"] += _ai_num(r.get("amount"), 0)
        opd = normalize_opd(r.get("opd"))
        if opd:
            o["customer_opds"].add(opd)
        pm_raw = r.get("payment") if r.get("payment") not in (None, "") else r.get("payment_method")
        pm = str(pm_raw or "").strip() or "ไม่ระบุ"
        o["payment_methods"][pm] += 1
        for it in _ai_normalize_sale_items(r):
            name = it.get("name") or it.get("label") or "ไม่ระบุ"
            o["top_items_counter"][name] += _ai_int(it.get("qty"), 1)

    for p in pending_rows or []:
        d = safe_date_str(p.get("sale_date") or p.get("date"))
        if not d:
            continue
        o = day_obj(d)
        o["ar_total"] += _ai_num(p.get("ar_amount"), 0)
        pending = _ensure_pending_work_list(p.get("pending_work"))
        o["pending_work_count"] += sum(_ai_int(x.get("qty"), 1) for x in pending)

    for a in appt_rows or []:
        d = safe_date_str(a.get("appt_date") or a.get("date"))
        if not d:
            continue
        o = day_obj(d)
        o["appointment_count"] += 1
        st = str(a.get("status") or "ไม่ระบุ").strip() or "ไม่ระบุ"
        o["appointment_statuses"][st] += 1
        typ_raw = a.get("case_type") or a.get("type") or a.get("column_id") or a.get("note") or ""
        typ = str(typ_raw or "").lower()
        if "iv" in typ or "ดริป" in typ:
            o["iv_case_count"] += 1
        elif "doctor" in typ or "แพทย" in typ or "หมอ" in typ:
            o["doctor_case_count"] += 1

    out = []
    for d in sorted(by_day.keys()):
        o = by_day[d]
        top_items = sorted(o["top_items_counter"].items(), key=lambda x: x[1], reverse=True)[:15]
        out.append({
            "date": d,
            "total_sales": round(o["total_sales"], 2),
            "bill_count": o["bill_count"],
            "unique_customers": len(o["customer_opds"]),
            "payment_methods": dict(o["payment_methods"]),
            "top_items": [{"name": k, "qty": v} for k, v in top_items],
            "ar_total": round(o["ar_total"], 2),
            "pending_work_count": o["pending_work_count"],
            "appointment_count": o["appointment_count"],
            "appointment_statuses": dict(o["appointment_statuses"]),
            "doctor_case_count": o["doctor_case_count"],
            "iv_case_count": o["iv_case_count"],
        })
    return out


def _ai_data_dictionary() -> Dict[str, Any]:
    return {
        "purpose": "ข้อมูลจริงทั้งหมดจากระบบคลินิก สำหรับให้ backend/AI Chatbot ใช้ค้นหาและสรุปคำตอบ",
        "warning": "ไฟล์นี้มีข้อมูลลูกค้าจริง เช่น ชื่อ เบอร์ ประวัติซื้อ นัดหมาย และข้อมูลค้างชำระ ใช้เฉพาะภายในคลินิกเท่านั้น",
        "recommended_usage": "ให้ระบบ chatbot ดึงเฉพาะข้อมูลที่เกี่ยวข้องกับคำถามจากไฟล์หรือฐานข้อมูล แล้วส่งให้ AI สรุป ไม่ควรส่งทั้งฐานข้อมูลให้ AI ทุกครั้ง",
        "files": {
            "raw/*.jsonl": "ข้อมูลดิบจาก Supabase ทีละตาราง ไม่ตัดข้อมูล",
            "curated/customers_full.jsonl": "ข้อมูลลูกค้าจริงทั้งหมด",
            "curated/sales_full.jsonl": "ยอดขายจริงทั้งหมด พร้อม items_normalized สำหรับ AI อ่านง่าย",
            "curated/appointments_full.jsonl": "นัดหมายทั้งหมด",
            "curated/pending_summary.jsonl": "ค้างชำระ/ค้างทำแบบ 1 บิลต่อ 1 แถว",
            "curated/inventory_counts_full.jsonl": "ข้อมูลนับสต๊อกพร้อมรายละเอียด item",
            "curated/daily_summary.jsonl": "สรุปรายวันจากยอดขาย นัดหมาย และรายการค้าง",
        },
        "important_fields": {
            "opd": "รหัสลูกค้าในคลินิก",
            "amount": "ยอดขายสุทธิของบิล",
            "items_normalized": "รายการสินค้า/บริการในบิลแบบแยก category, name, qty, price",
            "ar_amount": "ยอดค้างชำระของบิล",
            "pending_work": "รายการที่ลูกค้าซื้อแล้วแต่ยังไม่ได้ทำ",
            "receipt_status": "สถานะใบเสร็จ เช่น recorded/issued",
            "orig_no": "เลขใบเสร็จต้นฉบับ RC",
            "disp_no": "เลขแสดงผล RB",
        },
    }


@app.route("/api/export_ai_chatbot_zip")
@login_required
def export_ai_chatbot_zip():
    """Download a single ZIP containing real full data for AI Chatbot usage."""
    try:
        exported_at = datetime.now(timezone(timedelta(hours=7))).replace(microsecond=0).isoformat()
        stamp = datetime.now(timezone(timedelta(hours=7))).strftime("%Y%m%d_%H%M%S")
        filename = f"palmy_ai_chatbot_full_{stamp}.zip"

        table_names = [
            "customers",
            "customer_gallery",
            "sales_records",
            "sale_pending_summary",
            "appointments",
            "product_categories",
            "products",
            "customer_pitch_logs",
            "inventory_items",
            "inventory_counts",
            "receipt_counters_orig",
            "staffs",
            "work_schedules",
            "oldsaledata",
            "inventory",  # legacy backup table if still exists
            "ar_transactions",  # legacy, may be deleted
            "voucher_transactions",
            "work_transactions",  # legacy, may be deleted
        ]

        raw: Dict[str, List[Dict[str, Any]]] = {}
        errors: Dict[str, str] = {}
        for t in table_names:
            rows, err = _ai_fetch_table_all(t)
            raw[t] = rows
            if err:
                errors[t] = err

        sales_full = _ai_build_sales_full(raw.get("sales_records") or [])
        daily_summary = _ai_build_daily_summary(
            raw.get("sales_records") or [],
            raw.get("sale_pending_summary") or [],
            raw.get("appointments") or [],
        )

        inventory_counts_full: List[Dict[str, Any]] = []
        items_by_id = {str(x.get("id")): x for x in (raw.get("inventory_items") or []) if x.get("id") is not None}
        for c in raw.get("inventory_counts") or []:
            row = dict(c)
            item = items_by_id.get(str(c.get("item_id"))) or {}
            row["item_name"] = item.get("name") or row.get("item_name")
            row["category"] = item.get("category")
            row["unit"] = item.get("unit")
            row["min_qty"] = item.get("min_qty")
            inventory_counts_full.append(row)

        metadata = {
            "export_type": "palmy_clinic_ai_chatbot_full_dataset",
            "exported_at": exported_at,
            "version": "1.0",
            "contains_real_personal_data": True,
            "warning": "ไฟล์นี้มีข้อมูลจริงของคลินิกและลูกค้า ใช้เฉพาะภายในเท่านั้น ห้ามส่งต่อสาธารณะ",
            "source_tables": table_names,
            "record_counts": {k: len(v or []) for k, v in raw.items()},
            "curated_counts": {
                "customers_full": len(raw.get("customers") or []),
                "sales_full": len(sales_full),
                "appointments_full": len(raw.get("appointments") or []),
                "pending_summary": len(raw.get("sale_pending_summary") or []),
                "inventory_counts_full": len(inventory_counts_full),
                "daily_summary": len(daily_summary),
            },
            "table_errors": errors,
        }

        bio = BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2, default=_ai_json_default))
            z.writestr("data_dictionary.json", json.dumps(_ai_data_dictionary(), ensure_ascii=False, indent=2, default=_ai_json_default))
            z.writestr("README.txt", "ไฟล์นี้เป็นข้อมูลจริงทั้งหมดสำหรับ AI Chatbot ภายในคลินิก\nห้ามส่งต่อสาธารณะหรืออัปโหลดไปยังระบบที่ไม่ควบคุมสิทธิ์\nใช้สำหรับให้ backend/AI ดึงข้อมูลที่เกี่ยวข้องกับคำถามแล้วสรุปคำตอบเท่านั้น\n")

            for table_name, rows in raw.items():
                z.writestr(f"raw/{table_name}.jsonl", _ai_to_jsonl(rows or []))

            z.writestr("curated/customers_full.jsonl", _ai_to_jsonl(raw.get("customers") or []))
            z.writestr("curated/sales_full.jsonl", _ai_to_jsonl(sales_full))
            z.writestr("curated/appointments_full.jsonl", _ai_to_jsonl(raw.get("appointments") or []))
            z.writestr("curated/pending_summary.jsonl", _ai_to_jsonl(raw.get("sale_pending_summary") or []))
            z.writestr("curated/inventory_items.jsonl", _ai_to_jsonl(raw.get("inventory_items") or []))
            z.writestr("curated/inventory_counts_full.jsonl", _ai_to_jsonl(inventory_counts_full))
            z.writestr("curated/products.jsonl", _ai_to_jsonl(raw.get("products") or []))
            z.writestr("curated/product_categories.jsonl", _ai_to_jsonl(raw.get("product_categories") or []))
            z.writestr("curated/customer_pitch_logs.jsonl", _ai_to_jsonl(raw.get("customer_pitch_logs") or []))
            z.writestr("curated/customer_gallery.jsonl", _ai_to_jsonl(raw.get("customer_gallery") or []))
            z.writestr("curated/staffs.jsonl", _ai_to_jsonl(raw.get("staffs") or []))
            z.writestr("curated/work_schedules.jsonl", _ai_to_jsonl(raw.get("work_schedules") or []))
            z.writestr("curated/daily_summary.jsonl", _ai_to_jsonl(daily_summary))

        bio.seek(0)
        return send_file(
            bio,
            mimetype="application/zip",
            as_attachment=True,
            download_name=filename,
            max_age=0,
        )
    except Exception as e:
        app.logger.error(f"/api/export_ai_chatbot_zip error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500



# =============================================================
# API — NotebookLM Export (single plain TXT source)
# =============================================================
# NOTE:
# NotebookLM/Gemini reads natural text more reliably than huge JSON-in-Markdown.
# This export intentionally creates a UTF-8 plain .txt file with clear sections,
# one readable record at a time, while still keeping the real fields.

_NB_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _nb_clean_scalar(v: Any) -> str:
    """Convert any scalar to safe plain text for NotebookLM."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (datetime,)):
        return v.isoformat()
    s = str(v)
    s = s.replace("\ufeff", "")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = _NB_CONTROL_RE.sub(" ", s)
    # Keep new lines in notes, but prevent massive whitespace blobs.
    s = "\n".join(re.sub(r"[ \t]+", " ", line).strip() for line in s.split("\n"))
    return s.strip()


def _nb_inline_value(v: Any) -> str:
    """Compact value for one-line nested fields."""
    if isinstance(v, dict):
        parts = []
        for k in sorted(v.keys(), key=lambda x: str(x)):
            val = _nb_inline_value(v.get(k))
            if val != "":
                parts.append(f"{_nb_clean_scalar(k)}={val}")
        return "; ".join(parts)
    if isinstance(v, (list, tuple)):
        return " | ".join(_nb_inline_value(x) for x in v if _nb_inline_value(x) != "")
    return _nb_clean_scalar(v)


def _nb_format_value(v: Any, indent: str = "") -> str:
    """Readable multi-line formatting for scalars/lists/dicts."""
    if isinstance(v, dict):
        if not v:
            return ""
        lines = []
        for k in sorted(v.keys(), key=lambda x: str(x)):
            val = v.get(k)
            if isinstance(val, (dict, list, tuple)):
                rendered = _nb_format_value(val, indent + "  ")
                if rendered:
                    lines.append(f"{indent}{_nb_clean_scalar(k)}:")
                    lines.append(rendered)
            else:
                rendered = _nb_clean_scalar(val)
                if rendered != "":
                    lines.append(f"{indent}{_nb_clean_scalar(k)}: {rendered}")
        return "\n".join(lines)
    if isinstance(v, (list, tuple)):
        if not v:
            return ""
        lines = []
        for item in v:
            if isinstance(item, dict):
                inline = _nb_inline_value(item)
                if inline:
                    lines.append(f"{indent}- {inline}")
            elif isinstance(item, (list, tuple)):
                inline = _nb_inline_value(item)
                if inline:
                    lines.append(f"{indent}- {inline}")
            else:
                rendered = _nb_clean_scalar(item)
                if rendered:
                    lines.append(f"{indent}- {rendered}")
        return "\n".join(lines)
    return _nb_clean_scalar(v)


def _nb_ordered_keys(row: Dict[str, Any], preferred: Optional[List[str]] = None) -> List[str]:
    preferred = preferred or []
    keys = []
    seen = set()
    for k in preferred:
        if k in row and k not in seen:
            keys.append(k)
            seen.add(k)
    for k in sorted(row.keys(), key=lambda x: str(x)):
        if k not in seen:
            keys.append(k)
            seen.add(k)
    return keys


def _nb_format_record(row: Dict[str, Any], preferred: Optional[List[str]] = None) -> str:
    lines: List[str] = []
    for k in _nb_ordered_keys(row or {}, preferred):
        val = (row or {}).get(k)
        rendered = _nb_format_value(val, "  ") if isinstance(val, (dict, list, tuple)) else _nb_clean_scalar(val)
        if rendered == "":
            continue
        key = _nb_clean_scalar(k)
        if isinstance(val, (dict, list, tuple)):
            lines.append(f"{key}:")
            lines.append(rendered)
        else:
            lines.append(f"{key}: {rendered}")
    return "\n".join(lines) if lines else "(empty record)"


def _nb_section(
    title: str,
    rows: List[Dict[str, Any]],
    description: str = "",
    preferred_keys: Optional[List[str]] = None,
) -> str:
    safe_title = _nb_clean_scalar(title)
    section_code = re.sub(r"[^A-Za-z0-9ก-๙]+", "_", safe_title).strip("_") or "SECTION"
    parts: List[str] = []
    parts.append("\n\n============================================================\n")
    parts.append(f"SECTION: {safe_title}\n")
    parts.append("============================================================\n")
    if description:
        parts.append(_nb_clean_scalar(description) + "\n")
    parts.append(f"จำนวนรายการทั้งหมดในส่วนนี้: {len(rows or [])}\n")
    if not rows:
        parts.append("ไม่มีข้อมูล\n")
        return "".join(parts)

    for idx, row in enumerate(rows or [], 1):
        parts.append("\n------------------------------------------------------------\n")
        parts.append(f"{section_code} RECORD {idx} / {len(rows or [])}\n")
        parts.append("------------------------------------------------------------\n")
        parts.append(_nb_format_record(row or {}, preferred_keys))
        parts.append("\n")
    return "".join(parts)


def _nb_collect_dataset() -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    """Collect the same real dataset as AI ZIP export, optimized for one NotebookLM plain-text file."""
    table_names = [
        "customers",
        "customer_gallery",
        "sales_records",
        "sale_pending_summary",
        "appointments",
        "product_categories",
        "products",
        "customer_pitch_logs",
        "inventory_items",
        "inventory_counts",
        "receipt_counters_orig",
        "staffs",
        "work_schedules",
        "oldsaledata",
        "inventory",  # legacy backup table if still exists
        "ar_transactions",  # legacy, may be deleted
        "voucher_transactions",
        "work_transactions",  # legacy, may be deleted
    ]

    raw: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    for t in table_names:
        rows, err = _ai_fetch_table_all(t)
        raw[t] = rows
        if err:
            errors[t] = err

    sales_full = _ai_build_sales_full(raw.get("sales_records") or [])
    daily_summary = _ai_build_daily_summary(
        raw.get("sales_records") or [],
        raw.get("sale_pending_summary") or [],
        raw.get("appointments") or [],
    )

    inventory_counts_full: List[Dict[str, Any]] = []
    items_by_id = {str(x.get("id")): x for x in (raw.get("inventory_items") or []) if x.get("id") is not None}
    for c in raw.get("inventory_counts") or []:
        row = dict(c)
        item = items_by_id.get(str(c.get("item_id"))) or {}
        row["item_name"] = item.get("name") or row.get("item_name")
        row["category"] = item.get("category")
        row["unit"] = item.get("unit")
        row["min_qty"] = item.get("min_qty")
        inventory_counts_full.append(row)

    curated: Dict[str, List[Dict[str, Any]]] = {
        "customers_full": raw.get("customers") or [],
        "sales_full": sales_full,
        "appointments_full": raw.get("appointments") or [],
        "pending_summary": raw.get("sale_pending_summary") or [],
        "inventory_items": raw.get("inventory_items") or [],
        "inventory_counts_full": inventory_counts_full,
        "products": raw.get("products") or [],
        "product_categories": raw.get("product_categories") or [],
        "customer_pitch_logs": raw.get("customer_pitch_logs") or [],
        "customer_gallery": raw.get("customer_gallery") or [],
        "staffs": raw.get("staffs") or [],
        "work_schedules": raw.get("work_schedules") or [],
        "daily_summary": daily_summary,
    }

    metadata = {
        "export_type": "palmy_clinic_notebooklm_plain_text_source",
        "exported_at": datetime.now(timezone(timedelta(hours=7))).replace(microsecond=0).isoformat(),
        "version": "1.1",
        "contains_real_personal_data": True,
        "warning": "ไฟล์นี้มีข้อมูลจริงของคลินิกและลูกค้า ใช้เฉพาะภายในเท่านั้น ห้ามส่งต่อสาธารณะ",
        "source_tables": table_names,
        "raw_record_counts": {k: len(v or []) for k, v in raw.items()},
        "curated_record_counts": {k: len(v or []) for k, v in curated.items()},
        "table_errors": errors,
    }
    return metadata, curated, errors


def _nb_customer_lookup_index(customers: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    parts.append("\n\n============================================================\n")
    parts.append("CUSTOMER LOOKUP INDEX / ดัชนีค้นหาลูกค้า\n")
    parts.append("============================================================\n")
    parts.append("ใช้ส่วนนี้เพื่อค้นหาจาก OPD, ชื่อ, ชื่อเต็ม หรือเบอร์โทรได้เร็วขึ้น\n")
    if not customers:
        parts.append("ไม่มีข้อมูลลูกค้า\n")
        return "".join(parts)
    for c in customers:
        opd = _nb_clean_scalar(c.get("opd") or c.get("OPD") or "")
        name = _nb_clean_scalar(c.get("name") or c.get("nickname") or "")
        full_name = _nb_clean_scalar(c.get("full_name") or c.get("fullname") or "")
        phone = _nb_clean_scalar(c.get("phone") or c.get("tel") or "")
        vip = _nb_clean_scalar(c.get("vip") or c.get("vip_level") or "")
        parts.append(f"- OPD: {opd or '-'} | ชื่อ: {name or '-'} | ชื่อเต็ม: {full_name or '-'} | เบอร์: {phone or '-'} | VIP: {vip or '-'}\n")
    return "".join(parts)


def _nb_plain_text_dataset() -> str:
    metadata, curated, errors = _nb_collect_dataset()
    dictionary = _ai_data_dictionary()

    parts: List[str] = []
    parts.append("PALMY CLINIC — NOTEBOOKLM / GEMINI KNOWLEDGE BASE\n")
    parts.append("============================================================\n\n")
    parts.append("ไฟล์นี้เป็นไฟล์ข้อความธรรมดา UTF-8 สำหรับอัปโหลดเข้า NotebookLM / Gemini\n")
    parts.append("ออกแบบให้ AI อ่านง่ายกว่า Markdown ที่มี JSON ยาว ๆ โดยแบ่งข้อมูลเป็นหัวข้อและ record ชัดเจน\n\n")
    parts.append("คำเตือน: ไฟล์นี้มีข้อมูลจริง เช่น ชื่อ เบอร์ ประวัติซื้อ นัดหมาย ค้างชำระ ค้างทำ และสต๊อก ใช้เฉพาะภายในคลินิกเท่านั้น\n\n")

    parts.append("วิธีถามตัวอย่าง\n")
    examples = [
        "OPD 0114 เคยซื้ออะไรบ้างและยอดรวมเท่าไหร่",
        "ลูกค้าชื่อออยมีประวัติซื้ออะไรบ้าง",
        "วันนี้ยอดขายรวมเท่าไหร่ มีกี่บิล",
        "ใครค้างชำระบ้าง",
        "ใครมีค้างทำและค้างทำรายการอะไร",
        "สต๊อกอะไรใกล้หมด",
        "ลูกค้าคนนี้นัดครั้งล่าสุดเมื่อไหร่",
        "เดือนนี้สินค้า/บริการอะไรขายดีที่สุด",
    ]
    for ex in examples:
        parts.append(f"- {ex}\n")

    parts.append("\n============================================================\n")
    parts.append("METADATA\n")
    parts.append("============================================================\n")
    parts.append(_nb_format_record(metadata) + "\n")

    parts.append("\n============================================================\n")
    parts.append("DATA DICTIONARY / ความหมายของข้อมูล\n")
    parts.append("============================================================\n")
    parts.append(_nb_format_record(dictionary) + "\n")

    if errors:
        parts.append("\n============================================================\n")
        parts.append("TABLE ERRORS / ตารางที่ไม่มีหรือดึงไม่ได้\n")
        parts.append("============================================================\n")
        parts.append(_nb_format_record(errors) + "\n")

    parts.append(_nb_customer_lookup_index(curated.get("customers_full") or []))

    section_order = [
        (
            "Daily Summary / สรุปรายวัน",
            "daily_summary",
            "สรุปรายวันจากยอดขาย นัดหมาย และรายการค้าง",
            ["date", "total_sales", "bill_count", "unique_customers", "ar_total", "pending_work_count", "top_items"],
        ),
        (
            "Customers Full / ข้อมูลลูกค้าเต็ม",
            "customers_full",
            "ข้อมูลลูกค้าจริงทั้งหมดจากตาราง customers",
            ["opd", "name", "full_name", "phone", "birth_date", "birth_month", "vip", "vip_level", "profile", "note", "created_at", "updated_at"],
        ),
        (
            "Sales Full / ประวัติขายเต็ม",
            "sales_full",
            "ยอดขายจริงทั้งหมด พร้อม items_normalized ที่แยกรายการให้ AI อ่านง่าย",
            ["id", "sale_id", "date", "opd", "name", "customer_name", "amount", "payment_method", "orig_no", "disp_no", "receipt_status", "items_normalized", "items", "note", "ar_amount", "pending_work"],
        ),
        (
            "Pending Summary / ค้างชำระและค้างทำ",
            "pending_summary",
            "ค้างชำระ/ค้างทำแบบ 1 บิลต่อ 1 แถว",
            ["sale_id", "sale_date", "date", "opd", "name", "ar_amount", "pending_work", "note", "created_at", "updated_at"],
        ),
        (
            "Appointments Full / นัดหมายเต็ม",
            "appointments_full",
            "ข้อมูลนัดหมายทั้งหมด",
            ["date", "time", "opd", "name", "status", "column_id", "note", "created_at", "updated_at"],
        ),
        (
            "Inventory Counts Full / ประวัตินับสต๊อก",
            "inventory_counts_full",
            "ข้อมูลนับสต๊อกพร้อมชื่อ item, หมวด, หน่วย และ min_qty",
            ["count_date", "date", "item_name", "category", "quantity", "unit", "min_qty", "note"],
        ),
        (
            "Inventory Items / รายการสต๊อกกลาง",
            "inventory_items",
            "ทะเบียนรายการสต๊อกกลาง",
            ["name", "category", "unit", "min_qty", "sort_order", "is_active", "aliases"],
        ),
        (
            "Customer Pitch Logs / ประวัติ CRM Pitch",
            "customer_pitch_logs",
            "ประวัติการ pitch / CRM",
            ["created_at", "opd", "name", "promotion", "outcome", "content", "channel", "author", "note"],
        ),
        (
            "Products / สินค้าและบริการ",
            "products",
            "ข้อมูลสินค้า/บริการ",
            ["name", "category", "price", "unit", "is_active", "sort_order"],
        ),
        (
            "Product Categories / หมวดสินค้าและบริการ",
            "product_categories",
            "หมวดสินค้า/บริการ",
            ["name", "sort_order", "is_active"],
        ),
        (
            "Customer Gallery / คลังรูปลูกค้า",
            "customer_gallery",
            "ข้อมูลคลังรูปลูกค้า/URL รูป ถ้ามี",
            ["opd", "image_type", "is_profile", "image_url", "cloudinary_public_id", "created_at"],
        ),
        (
            "Staffs / พนักงาน",
            "staffs",
            "ข้อมูลพนักงาน",
            ["name", "role", "phone", "is_active", "created_at", "updated_at"],
        ),
        (
            "Work Schedules / ตารางงาน",
            "work_schedules",
            "ข้อมูลตารางงาน/เวร",
            ["date", "staff_name", "role", "start_time", "end_time", "note"],
        ),
    ]
    for title, key, desc, preferred in section_order:
        parts.append(_nb_section(title, curated.get(key) or [], desc, preferred))

    parts.append("\n\nEND OF PALMY CLINIC NOTEBOOKLM KNOWLEDGE BASE\n")
    return "".join(parts)



_NB_SPLIT_SECTIONS = [
    ("Daily Summary / สรุปรายวัน", "daily_summary", "สรุปรายวันจากยอดขาย นัดหมาย และรายการค้าง", ["date", "total_sales", "bill_count", "unique_customers", "ar_total", "pending_work_count", "top_items"], 600),
    ("Customers Full / ข้อมูลลูกค้าเต็ม", "customers_full", "ข้อมูลลูกค้าจริงทั้งหมดจากตาราง customers", ["opd", "name", "full_name", "phone", "birth_date", "birth_month", "vip", "vip_level", "profile", "note", "created_at", "updated_at"], 350),
    ("Sales Full / ประวัติขายเต็ม", "sales_full", "ยอดขายจริงทั้งหมด พร้อม items_normalized ที่แยกรายการให้ AI อ่านง่าย", ["id", "sale_id", "date", "opd", "name", "customer_name", "amount", "payment_method", "orig_no", "disp_no", "receipt_status", "items_normalized", "items", "note", "ar_amount", "pending_work"], 250),
    ("Pending Summary / ค้างชำระและค้างทำ", "pending_summary", "ค้างชำระ/ค้างทำแบบ 1 บิลต่อ 1 แถว", ["sale_id", "sale_date", "date", "opd", "name", "ar_amount", "pending_work", "note", "created_at", "updated_at"], 400),
    ("Appointments Full / นัดหมายเต็ม", "appointments_full", "ข้อมูลนัดหมายทั้งหมด", ["date", "time", "opd", "name", "status", "column_id", "note", "created_at", "updated_at"], 350),
    ("Inventory Counts Full / ประวัตินับสต๊อก", "inventory_counts_full", "ข้อมูลนับสต๊อกพร้อมชื่อ item, หมวด, หน่วย และ min_qty", ["count_date", "date", "item_name", "category", "quantity", "unit", "min_qty", "note"], 450),
    ("Inventory Items / รายการสต๊อกกลาง", "inventory_items", "ทะเบียนรายการสต๊อกกลาง", ["name", "category", "unit", "min_qty", "sort_order", "is_active", "aliases"], 600),
    ("Customer Pitch Logs / ประวัติ CRM Pitch", "customer_pitch_logs", "ประวัติการ pitch / CRM", ["created_at", "opd", "name", "promotion", "outcome", "content", "channel", "author", "note"], 300),
    ("Products / สินค้าและบริการ", "products", "ข้อมูลสินค้า/บริการ", ["name", "category", "price", "unit", "is_active", "sort_order"], 600),
    ("Product Categories / หมวดสินค้าและบริการ", "product_categories", "หมวดสินค้า/บริการ", ["name", "sort_order", "is_active"], 800),
    ("Customer Gallery / คลังรูปลูกค้า", "customer_gallery", "ข้อมูลคลังรูปลูกค้า/URL รูป ถ้ามี", ["opd", "image_type", "is_profile", "image_url", "cloudinary_public_id", "created_at"], 300),
    ("Staffs / พนักงาน", "staffs", "ข้อมูลพนักงาน", ["name", "role", "phone", "is_active", "created_at", "updated_at"], 800),
    ("Work Schedules / ตารางงาน", "work_schedules", "ข้อมูลตารางงาน/เวร", ["date", "staff_name", "role", "start_time", "end_time", "note"], 800),
]


def _nb_ascii_file_stem(index: int, key: str, part: Optional[int] = None) -> str:
    safe_key = re.sub(r"[^A-Za-z0-9_\-]+", "_", str(key or "section")).strip("_").lower() or "section"
    if part is None:
        return f"{index:02d}_{safe_key}.txt"
    return f"{index:02d}_{safe_key}_part{part:03d}.txt"


def _nb_section_chunk(
    title: str,
    rows: List[Dict[str, Any]],
    description: str = "",
    preferred_keys: Optional[List[str]] = None,
    start_number: int = 1,
    total_count: Optional[int] = None,
    part_number: Optional[int] = None,
    total_parts: Optional[int] = None,
) -> str:
    safe_title = _nb_clean_scalar(title)
    total_count = total_count if total_count is not None else len(rows or [])
    parts: List[str] = []
    parts.append(f"{safe_title}\n")
    parts.append("=" * 70 + "\n\n")
    if description:
        parts.append(_nb_clean_scalar(description) + "\n")
    if part_number and total_parts:
        parts.append(f"ไฟล์ย่อย: {part_number}/{total_parts}\n")
    parts.append(f"จำนวน record ในไฟล์นี้: {len(rows or [])}\n")
    parts.append(f"จำนวน record ทั้งหมดของหมวดนี้: {total_count}\n")
    parts.append("\n")

    if not rows:
        parts.append("ไม่มีข้อมูล\n")
        return "".join(parts)

    for offset, row in enumerate(rows or [], 0):
        record_no = start_number + offset
        parts.append("-" * 70 + "\n")
        parts.append(f"RECORD {record_no} / {total_count}\n")
        parts.append("-" * 70 + "\n")
        parts.append(_nb_format_record(row or {}, preferred_keys))
        parts.append("\n\n")
    return "".join(parts)


def _nb_zip_readme(metadata: Dict[str, Any]) -> str:
    examples = [
        "OPD 0114 เคยซื้ออะไรบ้างและยอดรวมเท่าไหร่",
        "ลูกค้าชื่อออยมีประวัติซื้ออะไรบ้าง",
        "วันนี้ยอดขายรวมเท่าไหร่ มีกี่บิล",
        "ใครค้างชำระบ้าง",
        "ใครมีค้างทำและค้างทำรายการอะไร",
        "สต๊อกอะไรใกล้หมด",
        "ลูกค้าคนนี้นัดครั้งล่าสุดเมื่อไหร่",
        "เดือนนี้สินค้า/บริการอะไรขายดีที่สุด",
    ]
    lines: List[str] = []
    lines.append("PALMY CLINIC — NOTEBOOKLM / GEMINI FILE PACK\n")
    lines.append("=" * 70 + "\n\n")
    lines.append("ไฟล์ ZIP นี้แยกข้อมูลออกเป็นหลายไฟล์ .txt เพื่อไม่ให้ NotebookLM/Gemini ค้างจากไฟล์ก้อนเดียวใหญ่เกินไป\n")
    lines.append("วิธีใช้ที่แนะนำ: แตก ZIP ก่อน แล้วเลือกอัปโหลดไฟล์ .txt ที่ต้องการเข้า NotebookLM/Gemini\n")
    lines.append("ถ้าต้องถามภาพรวมลูกค้าและยอดขาย ให้เริ่มจากไฟล์ 00_README, 01_METADATA, 02_CUSTOMER_LOOKUP_INDEX, customers_full, sales_full และ pending_summary\n\n")
    lines.append("คำเตือน: ชุดไฟล์นี้มีข้อมูลจริงของคลินิก เช่น ชื่อ เบอร์ ประวัติซื้อ นัดหมาย ค้างชำระ ค้างทำ และสต๊อก ใช้เฉพาะภายในคลินิกเท่านั้น\n\n")
    lines.append("ตัวอย่างคำถาม\n")
    for ex in examples:
        lines.append(f"- {ex}\n")
    lines.append("\nข้อมูล export\n")
    lines.append(_nb_format_record(metadata))
    lines.append("\n")
    return "".join(lines)


def _nb_write_split_section_files(
    z: zipfile.ZipFile,
    file_index: int,
    title: str,
    key: str,
    description: str,
    preferred_keys: List[str],
    rows: List[Dict[str, Any]],
    chunk_size: int,
) -> int:
    rows = rows or []
    chunk_size = max(50, int(chunk_size or 300))
    total = len(rows)
    if total == 0:
        name = _nb_ascii_file_stem(file_index, key)
        z.writestr(name, _nb_section_chunk(title, [], description, preferred_keys).encode("utf-8"))
        return 1

    total_parts = (total + chunk_size - 1) // chunk_size
    written = 0
    for part_idx, start in enumerate(range(0, total, chunk_size), 1):
        chunk = rows[start:start + chunk_size]
        filename = _nb_ascii_file_stem(file_index, key, part_idx if total_parts > 1 else None)
        content = _nb_section_chunk(
            title,
            chunk,
            description,
            preferred_keys,
            start_number=start + 1,
            total_count=total,
            part_number=part_idx if total_parts > 1 else None,
            total_parts=total_parts if total_parts > 1 else None,
        )
        z.writestr(filename, content.encode("utf-8"))
        written += 1
    return written


# =============================================================
# API — Excel Report Data Export
# =============================================================
def _excel_json_safe_value(v: Any) -> Any:
    """Make exported report data safe for jsonify without losing nested data."""
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, datetime):
        return v.isoformat()
    try:
        if hasattr(v, "isoformat"):
            return v.isoformat()
    except Exception:
        pass
    if isinstance(v, dict):
        return {str(k): _excel_json_safe_value(val) for k, val in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_excel_json_safe_value(x) for x in v]
    return str(v)


@app.route("/api/export_excel_report_data")
@login_required
def export_excel_report_data():
    """Return real full data for a polished multi-sheet Excel report.

    The browser uses SheetJS to build the workbook so we do not need an extra
    Python xlsx dependency on the server. The dataset is shared with the AI /
    NotebookLM export collector to keep information complete and consistent.
    """
    try:
        metadata, curated, errors = _nb_collect_dataset()
        metadata = dict(metadata or {})
        metadata["export_type"] = "palmy_clinic_excel_report_data"
        metadata["format"] = "json_for_browser_xlsx"
        metadata["note"] = "ข้อมูลจริงครบสำหรับสร้าง Excel รายงานหลาย sheet: สรุป, รายบิล, รายสินค้า, ลูกค้า, ค้าง, นัดหมาย, สต๊อก และ raw data"
        payload = {
            "success": True,
            "metadata": metadata,
            "curated": curated,
            "errors": errors or {},
        }
        return jsonify(_excel_json_safe_value(payload))
    except Exception as e:
        app.logger.error(f"/api/export_excel_report_data error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/export_notebooklm_markdown")
@login_required
def export_notebooklm_markdown():
    """Download a ZIP pack of many plain TXT files for NotebookLM/Gemini.

    Route name is kept for front-end compatibility with the previous Markdown/TXT button.
    The output is now split into multiple files to avoid NotebookLM/Gemini freezing on one huge source.
    """
    try:
        stamp = datetime.now(timezone(timedelta(hours=7))).strftime("%Y%m%d_%H%M%S")
        filename = f"palmy_notebooklm_split_pack_{stamp}.zip"

        metadata, curated, errors = _nb_collect_dataset()
        metadata = dict(metadata or {})
        metadata["export_type"] = "palmy_clinic_notebooklm_split_text_pack"
        metadata["format"] = "zip_with_multiple_utf8_txt_files"
        metadata["usage"] = "แตก ZIP แล้วอัปโหลดไฟล์ .txt ที่ต้องการเข้า NotebookLM/Gemini"
        metadata["generated_files_note"] = "ข้อมูลขนาดใหญ่ เช่น sales/customers/pitch/gallery อาจถูกแบ่งเป็น part001, part002 เพื่อกันค้าง"

        bio = BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("00_README_วิธีใช้.txt", _nb_zip_readme(metadata).encode("utf-8"))
            z.writestr("01_METADATA.txt", _nb_section_chunk("METADATA", [metadata], "รายละเอียดชุดข้อมูลและจำนวน record", None).encode("utf-8"))
            z.writestr("02_DATA_DICTIONARY.txt", _nb_section_chunk("DATA DICTIONARY / ความหมายของข้อมูล", [_ai_data_dictionary()], "ความหมายของ field สำคัญ", None).encode("utf-8"))
            if errors:
                z.writestr("03_TABLE_ERRORS.txt", _nb_section_chunk("TABLE ERRORS / ตารางที่ไม่มีหรือดึงไม่ได้", [errors], "ตารางบางตัวอาจไม่มีในระบบ ถือว่าไม่เป็นปัญหาถ้าไม่ได้ใช้งาน", None).encode("utf-8"))
            z.writestr("04_CUSTOMER_LOOKUP_INDEX.txt", _nb_customer_lookup_index(curated.get("customers_full") or []).encode("utf-8"))

            file_index = 5
            for title, key, desc, preferred, chunk_size in _NB_SPLIT_SECTIONS:
                _nb_write_split_section_files(
                    z,
                    file_index,
                    title,
                    key,
                    desc,
                    preferred,
                    curated.get(key) or [],
                    chunk_size,
                )
                file_index += 1

        bio.seek(0)
        return send_file(
            bio,
            mimetype="application/zip",
            as_attachment=True,
            download_name=filename,
            max_age=0,
        )
    except Exception as e:
        app.logger.error(f"/api/export_notebooklm_markdown split zip error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# -----------------------------
# OPTIONAL (แนะนำ): ถ้าอยากให้ของเก่าที่เป็น NULL ถูกอ่านเป็น show ชัด ๆ
# แก้ใน /api/sales ตอน loop for r in all_data:
# -----------------------------
# เพิ่มบรรทัดนี้ใน for r in all_data:
#     r["tax_display"] = _normalize_tax_display(r.get("tax_display"))
#
# ตัวอย่างบริเวณใน /api/sales:
#
#        for r in all_data:
#            r["opd"] = normalize_opd(r.get("opd"))
#            r["tax_display"] = _normalize_tax_display(r.get("tax_display"))
#
#            raw_item = r.get("item")
#            if raw_item is None and r.get("items") is not None:
#                raw_item = r.get("items")
#
#            normalized_item_list = _ensure_item_list(raw_item)
#            r["item"] = normalized_item_list
#            r["items"] = _coerce_items_to_text_list(normalized_item_list)
#
# แบบนี้ frontend จะได้ค่า show/noshow แน่นอนเสมอ
# -----------------------------

