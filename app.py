from __future__ import annotations

import os
import json
import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from math import isfinite
from typing import Any, Dict, List

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
from supabase import create_client, Client
from functools import wraps

# =============================================================
# Environment & App Setup
# =============================================================
load_dotenv()

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


# ✅ Settings page (ล็อกอินเหมือนเดิม)
@app.route("/appsettings")
@login_required
def appsettings():
    return render_template(
        "appsettings.html",
        username=session.get("username"),
        role=session.get("role", ""),
    )


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
            # ✅ FIX: วงเล็บให้ถูก
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


@app.route("/api/delete_customer", methods=["POST"])
@login_required
def delete_customer_legacy():
    data = request.get_json(force=True)
    opd = normalize_opd(data.get("opd"))
    try:
        supabase.table("sales_records").delete().eq("opd", opd).execute()
        return jsonify({"message": "ลบสำเร็จ (เฉพาะยอดขาย)"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_customer_and_sales", methods=["POST"])
@login_required
def delete_customer_and_sales():
    data = request.get_json(force=True)
    opd = normalize_opd(data.get("opd"))
    try:
        supabase.table("sales_records").delete().eq("opd", opd).execute()
        supabase.table("customers").delete().eq("opd", opd).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Sales
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
            if "item" in r:
                try:
                    r["items"] = json.loads(r["item"])
                except Exception:
                    r["items"] = []

        return jsonify(all_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

            # ✅ FIX: sanitize amount ให้เป็น float หรือ None (กัน "" ชน numeric)
            amt = rec.get("amount")
            if amt in ("", None):
                amt = None
            else:
                try:
                    amt = float(amt)
                except Exception:
                    amt = None

            if opd_4 and rec.get("name"):
                customer_data = {
                    "opd": opd_4,
                    "name": rec.get("name", ""),
                    "phone": rec.get("phone", ""),
                    "birthMonth": rec.get("birthMonth", ""),
                    "profile": rec.get("profile", ""),
                }
                supabase.table("customers").upsert(customer_data, on_conflict=["opd"]).execute()

            items = rec.get("items") or []
            rec_db = {
                "date": date,
                "opd": opd_4,
                "name": rec.get("name", ""),
                "phone": rec.get("phone", ""),
                "amount": amt,  # ✅ ใช้ค่าที่ sanitize แล้ว
                "payment": rec.get("payment"),
                "note": rec.get("note", ""),
                "item": json.dumps(items, ensure_ascii=False),
            }

            rec_id = rec.get("id")
            if rec_id:
                supabase.table("sales_records").update(rec_db).eq("id", rec_id).execute()
                updated_count += 1
                continue

            dup_q = (
                supabase.table("sales_records")
                .select("id")
                .eq("opd", rec_db["opd"])
                .eq("date", rec_db["date"])
                .eq("item", rec_db["item"])
            )
            if rec_db.get("amount") is not None:
                dup_q = dup_q.eq("amount", rec_db["amount"])
            if rec_db.get("payment") is not None:
                dup_q = dup_q.eq("payment", rec_db["payment"])
            if rec_db.get("note"):
                dup_q = dup_q.eq("note", rec_db["note"])

            dup = dup_q.execute().data
            if dup:
                continue

            supabase.table("sales_records").insert(rec_db).execute()
            inserted_count += 1

        return jsonify({"message": "บันทึกสำเร็จ", "inserted": inserted_count, "updated": updated_count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_sales_record", methods=["POST"])
@login_required
def delete_sales_record():
    try:
        payload = request.get_json(force=True) or {}
        record_id = payload.get("id")
        if not record_id:
            return jsonify({"error": "Missing ID"}), 400
        supabase.table("sales_records").delete().eq("id", record_id).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
            )
            seen[key].append(row)

        deleted = 0
        for rows in seen.values():
            if len(rows) > 1:
                ids_to_delete = [r["id"] for r in rows[1:] if "id" in r]
                if ids_to_delete:
                    supabase.table("sales_records").delete().in_("id", ids_to_delete).execute()
                    deleted += len(ids_to_delete)

        return jsonify({"message": f"ลบรายการซ้ำทั้งหมด {deleted} รายการเรียบร้อยแล้ว"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# ✅ Product Catalog APIs (ใช้กับ record_sales + appsettings)
# =============================================================
@app.route("/api/products_map")
@login_required
def api_products_map():
    """
    return แบบเดิมที่หน้า record_sales ใช้ง่าย:
    {
      "map": { "หมวด": [{"name": "...", "default_price": 0, "id": "..."}] },
      "categories": [{"id":..,"name":..}],
    }
    เฉพาะที่ยังใช้งาน: categories.is_active=true และ products.is_active=true และ products.deleted_at is null
    """
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
            .select("id,name,default_price,sort_order,category_id,is_active,deleted_at")
            .in_("category_id", cat_ids)
            .eq("is_active", True)
            .is_("deleted_at", "null")
            .order("sort_order", desc=False)
            .order("name", desc=False)
        )
        prods = (prods_q.execute().data or [])

        # group
        id_to_name = {c["id"]: c["name"] for c in cats}
        out: Dict[str, List[Dict[str, Any]]] = {c["name"]: [] for c in cats}
        for p in prods:
            cn = id_to_name.get(p.get("category_id"))
            if not cn:
                continue
            out.setdefault(cn, []).append({
                "id": p.get("id"),
                "name": p.get("name"),
                "default_price": p.get("default_price"),
                "sort_order": p.get("sort_order", 0),
            })

        return jsonify({"map": out, "categories": cats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/categories", methods=["GET", "POST", "PUT"])
@login_required
def api_categories():
    # NOTE: หมวด “ไม่ทำ soft delete” ในรอบนี้ (กันพังตอนสินค้าอ้างอิง)
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


@app.route("/api/products", methods=["GET", "POST", "PUT", "DELETE"])
@login_required
def api_products():
    """
    ✅ DELETE = soft delete -> set deleted_at + is_active=false
    """
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

            payload = {
                "category_id": category_id,
                "name": name,
                "default_price": default_price,
                "sort_order": int(data.get("sort_order") or 0),
                "is_active": bool(data.get("is_active", True)),
            }
            supabase.table("products").insert(payload).execute()
            return jsonify({"message": "ok"})

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

            if "deleted_at" in data:
                # allow UI to restore by sending deleted_at=null
                patch["deleted_at"] = data.get("deleted_at")

            if not patch:
                return jsonify({"error": "no_fields"}), 400

            supabase.table("products").update(patch).eq("id", pid).execute()
            return jsonify({"message": "ok"})

        if request.method == "DELETE":
            pid = data.get("id")
            if not pid:
                return jsonify({"error": "missing_id"}), 400
            supabase.table("products").update({
                "deleted_at": _utc_now_iso(),
                "is_active": False,
            }).eq("id", pid).execute()
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
        supabase.table("products").update({
            "deleted_at": None,
            "is_active": True,
        }).eq("id", pid).execute()
        return jsonify({"message": "restored"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
# API — Sales Pitch (เดิมของคุณ)
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
                s = " ".join([
                    str(r.get("opd") or ""),
                    str(r.get("content") or ""),
                    str(r.get("outcome") or ""),
                    str(r.get("channel") or ""),
                    str(r.get("author") or ""),
                    str(r.get("promotion") or ""),
                ]).lower()
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
                try:
                    r["items"] = json.loads(r.get("item") or "[]")
                except Exception:
                    r["items"] = []
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
# API — Oldsale & Inventory (compat)
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


@app.route("/api/inventory")
@login_required
def api_inventory():
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
# API — Tax Module (เดิมของคุณ)
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
# Main
# =============================================================
if __name__ == "__main__":
    app.run(debug=True)
