from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from supabase import create_client, Client
import json
import os

app = Flask(__name__)
app.secret_key = 'superscretkey'

# Supabase config
url = "https://wggtpayglmqvneyrxons.supabase.co"
key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndnZ3RwYXlnbG1xdm5leXJ4b25zIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYyODExNzcsImV4cCI6MjA2MTg1NzE3N30.IcdBWo9Hpj6_dbF9ScsrqMYiEdf1_cmdavMaHJDU-JM"
supabase: Client = create_client(url, key)

# จำลองผู้ใช้งาน
users = {
    'admin': '1234',
    'test': 'abcd'
}

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
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
        response = supabase.table("sales_records").select("*").execute()
        data = response.data

        for r in data:
            if 'item' in r:
                try:
                    r['items'] = json.loads(r['item'])
                except:
                    r['items'] = []
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/save_sales', methods=['POST'])
def save_sales():
    data = request.get_json()
    print("📥 ได้รับข้อมูลจาก frontend:", data)

    inserted_count = 0
    try:
        for rec in data:
            opd = rec.get('opd')
            date = rec.get('date')
            amount = rec.get('amount')

            # ตรวจสอบความซ้ำ: มี opd + date + amount ซ้ำหรือไม่
            existing = supabase.table("sales_records").select("id").match({
                "opd": opd,
                "date": date,
                "amount": amount
            }).execute()

            if not existing.data:
                # เตรียมข้อมูลเพื่อบันทึก
                rec['item'] = json.dumps(rec.get('items', []))
                rec.pop('items', None)
                rec.pop('id', None)

                # บันทึก
                response = supabase.table("sales_records").insert(rec).execute()
                print("✅ บันทึก:", response)
                inserted_count += 1
            else:
                print(f"⏩ ข้ามรายการซ้ำ: opd={opd}, date={date}, amount={amount}")

        return jsonify({"message": "บันทึกสำเร็จ", "inserted": inserted_count})
    except Exception as e:
        print("❌ ERROR:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/api/update_customer', methods=['POST'])
def update_customer():
    data = request.json
    opd = data.get('opd')
    field = data.get('field')
    value = data.get('value')
    try:
        supabase.table("sales_records").update({field: value}).eq("opd", opd).execute()
        return jsonify({"message": "อัปเดตสำเร็จ"})
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
    try:
        supabase.table("customers").insert(data).execute()
        return jsonify({"message": "เพิ่มลูกค้าสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
