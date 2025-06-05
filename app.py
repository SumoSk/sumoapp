from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from supabase import create_client, Client
from werkzeug.security import check_password_hash
import json
import os
from dotenv import load_dotenv
from collections import defaultdict

# ✅ โหลดค่าจาก .env
load_dotenv()

# ✅ Flask config
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Supabase config
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(url, key)

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        try:
            result = supabase.table("users").select("*").eq("username", username).single().execute()
            print("📦 Result:", result)
            user = result.data
            print("📦 User data:", user)

            if user:
                if user['password_hash'] == password:
                    session['username'] = username
                    session['role'] = user.get('role', '')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
            else:
                error = 'ชื่อผู้ใช้ไม่พบในระบบ'

        except Exception as e:
            print("❌ ERROR login:", e)
            error = 'เกิดข้อผิดพลาดในการเชื่อมต่อกับระบบ'

    return render_template('login.html', error=error)


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session.get('role', ''))
    return redirect(url_for('login'))

@app.route('/record_sales')
def record_sales():
    if 'username' in session:
        return render_template('record_sales.html')
    return redirect(url_for('login'))

@app.route('/sale_summary')
def sale_summary():
    if 'username' in session:
        return render_template('sale-summary.html')
    return redirect(url_for('login'))

@app.route('/record_customer')
def record_customer():
    if 'username' in session:
        return render_template('record_customer.html')
    return redirect(url_for('login'))

@app.route('/customer_list')
def customer_list():
    if 'username' in session:
        return render_template('customer_list.html')
    return redirect(url_for('login'))


@app.route('/api/sales')
def api_sales():
    try:
        all_data = []
        start = 0
        limit = 1000

        while True:
            response = supabase.table("sales_records").select("*").range(start, start + limit - 1).execute()
            batch = response.data
            if not batch:
                break
            all_data.extend(batch)
            if len(batch) < limit:
                break
            start += limit

        # ✅ แปลง 'item' เป็น array 'items'
        for r in all_data:
            if 'item' in r:
                try:
                    r['items'] = json.loads(r['item'])
                except:
                    r['items'] = []
        return jsonify(all_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/save_sales', methods=['POST'])
def save_sales():
    data = request.get_json()
    print("📥 ได้รับข้อมูลจาก frontend:", data)

    inserted_count = 0
    try:
        # 🔄 ถ้ามี delete ก่อน (กรณีแก้ไข)
        if data and data[0].get('delete_before'):
            delete_opd = data[0].get('opd')
            delete_date = data[0].get('date')
            print(f"🧽 ลบข้อมูลเดิม opd={delete_opd}, date={delete_date}")
            supabase.table("sales_records").delete().match({
                "opd": delete_opd,
                "date": delete_date
            }).execute()
            data = data[1:]

        for i, rec in enumerate(data):
            print(f"🔍 กำลังบันทึกรายการที่ {i+1}: {rec}")

            # ✳️ เตรียม opd 4 หลัก
            opd_4digit = rec.get('opd', '').zfill(4)

            # 🟡 อัปเดตหรือเพิ่มใน customers
            if opd_4digit and rec.get('name'):
                customer_data = {
                    "opd": opd_4digit,
                    "name": rec.get('name', ''),
                    "phone": rec.get('phone', ''),
                    "birthMonth": rec.get('birthMonth', ''),
                    "vip": rec.get('vip', ''),
                    "note": rec.get('note', '')
                }
                supabase.table("customers").upsert(customer_data, on_conflict=["opd"]).execute()

            # 🔵 บันทึกใน sales_records
            rec['item'] = json.dumps(rec.get('items', []))
            rec.pop('items', None)
            rec.pop('id', None)
            rec['opd'] = opd_4digit  # บังคับให้ใช้ opd 4 หลัก

            response = supabase.table("sales_records").insert(rec).execute()
            print("✅ บันทึกสำเร็จ:", response)
            inserted_count += 1

        return jsonify({"message": "บันทึกสำเร็จ", "inserted": inserted_count})

    except Exception as e:
        print("❌ ERROR เกิดขึ้นขณะบันทึก:", e)
        return jsonify({"error": str(e)}), 500

    
@app.route('/api/customers')
def api_customers():
    try:
        response = supabase.table("customers").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/update_customer', methods=['POST'])
def update_customer():
    data = request.json
    opd = str(data.get('opd')).strip()
    field = data.get('field')
    value = data.get('value')

    print(f"🧾 กำลังอัปเดต opd = '{opd}' field = '{field}' value = '{value}'")

    try:
        # ✅ แก้ตรงนี้ให้ใช้ customers
        res = supabase.table("customers").update({field: value}).eq("opd", opd).execute()
        print("🔍 UPDATE RESULT:", res)
        return jsonify({
            "message": "อัปเดตสำเร็จ",
            "debug": res.data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500





@app.route('/api/delete_customer', methods=['POST'])
def delete_customer():
    data = request.json
    opd = data.get('opd')
    try:
        supabase.table("sales_records").delete().eq("opd", opd).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/add_customer', methods=['POST'])
def add_customer():
    data = request.json
    opd = str(data.get("opd", "")).zfill(4)

    try:
        check = supabase.table("customers").select("*").eq("opd", opd).execute()
        if check.data:
            return jsonify({"error": "มี OPD นี้อยู่แล้ว"}), 400

        supabase.table("customers").insert(data).execute()
        return jsonify({"message": "เพิ่มลูกค้าสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/api/test')
def test_route():
    return jsonify({"status": "ok"})

@app.route('/api/delete_sales_record', methods=['POST'])
def delete_sales_record():
    try:
        record_id = request.json.get('id')
        if not record_id:
            return jsonify({"error": "Missing ID"}), 400
        supabase.table("sales_records").delete().eq("id", record_id).execute()
        return jsonify({"message": "ลบสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cleanup_duplicates')
def cleanup_duplicates():
    try:
        response = supabase.table("sales_records").select("*").execute()
        all_data = response.data
        seen = defaultdict(list)
        for row in all_data:
            key = (row.get('opd'), row.get('date'), row.get('amount'))
            seen[key].append(row)
        deleted = 0
        for rows in seen.values():
            if len(rows) > 1:
                ids_to_delete = [r['id'] for r in rows[1:] if 'id' in r]
                if ids_to_delete:
                    supabase.table("sales_records").delete().in_("id", ids_to_delete).execute()
                    deleted += len(ids_to_delete)
        return jsonify({"message": f"ลบรายการซ้ำทั้งหมด {deleted} รายการเรียบร้อยแล้ว"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)


@app.route('/api/oldsaledata')
def api_oldsaledata():
    try:
        response = supabase.table("oldsaledata").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        print("❌ ERROR loading oldsaledata:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/oldsaledata')
def oldsaledata():
    if 'username' in session:
        return render_template('oldsaledata.html')
    return redirect(url_for('login'))

@app.route('/inventory')
def inventory():
    if 'username' in session:
        return render_template('inventory.html')
    return redirect(url_for('login'))

@app.route("/api/inventory")
def api_inventory():
    try:
        res = supabase.table("inventory").select("*").execute()
        return jsonify(res.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/save_inventory", methods=["POST"])
def api_save_inventory():
    data = request.json
    try:
        # optional: ตรวจสอบว่าไม่มีรายการซ้ำก่อน insert
        supabase.table("inventory").insert(data).execute()
        return jsonify({"message": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
