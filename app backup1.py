from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from supabase import create_client, Client
import json

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
    response = supabase.table("sales_records").select("*").execute()
    return jsonify(response.data)

@app.route('/api/save_sales', methods=['POST'])
def save_sales():
    data = request.get_json()
    try:
        for rec in data:
            rec['item'] = json.dumps(rec.get('items', []))  # เก็บ items เป็น string
            rec.pop('items', None)
            supabase.table("sales_records").insert(rec).execute()
        return jsonify({"message": "บันทึกสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
