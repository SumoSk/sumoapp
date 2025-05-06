from supabase import create_client, Client

url = "https://wggtpayglmqvneyrxons.supabase.co"
key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndnZ3RwYXlnbG1xdm5leXJ4b25zIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYyODExNzcsImV4cCI6MjA2MTg1NzE3N30.IcdBWo9Hpj6_dbF9ScsrqMYiEdf1_cmdavMaHJDU-JM"
supabase: Client = create_client(url, key)

# ตัวอย่าง: ดึงข้อมูลจากตาราง sales_records
response = supabase.table("sales_records").select("*").execute()
print(response.data)
