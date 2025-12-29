from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, make_response
from supabase import create_client
from flask_bcrypt import Bcrypt
import os, secrets, datetime, requests, json, hashlib
from dateutil import parser
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

app = Flask(__name__)
bcrypt = Bcrypt(app)

# ======================
# SUPABASE & CRYPTO SETUP
# ======================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret_key")

# The secret key we extracted from the APK
DECRYPTION_PASSWORD = "b7Q!eF9rL2#Z8xV6wT1@pC4dJ5hM0nR3"

# ======================
# HELPER FUNCTIONS
# ======================
def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def decrypt_payload(encrypted_str):
    """Decrypts the AES-CBC payload returned by the cricket API."""
    try:
        # 1. Derive the 32-byte key using SHA-256
        key = hashlib.sha256(DECRYPTION_PASSWORD.encode('utf-8')).digest()
        
        # 2. Decode Base64
        raw_bytes = base64.b64decode(encrypted_str)
        
        # 3. Extract IV (first 16 bytes) and Ciphertext
        iv = raw_bytes[:16]
        ciphertext = raw_bytes[16:]
        
        # 4. Decrypt using AES-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_raw = cipher.decrypt(ciphertext)
        
        # 5. Remove Padding and return as List/Dict
        decrypted_data = unpad(decrypted_raw, AES.block_size)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return []

def parse_json_response(response):
    """Parses the outer JSON, then decrypts the 'payload' field."""
    try:
        outer_data = response.json()
        encrypted_payload = outer_data.get("payload")
        
        if encrypted_payload:
            return decrypt_payload(encrypted_payload)
        
        # Fallback if the API returns a direct list (unlikely now)
        return outer_data if isinstance(outer_data, list) else []
    except Exception as e:
        print(f"⚠️ Response Error: {e}")
        return []

# ======================
# LOGIN PAGE
# ======================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        res = supabase.table("user_sessions").select("*").eq("email", email).execute()
        if not res.data:
            return "Invalid email or password!", 401
        
        user = res.data[0]
        if password != user["password"]:
            return "Invalid email or password!", 401

        token = secrets.token_hex(32)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        supabase.table("user_sessions").update({
            "is_active": True,
            "token": token,
            "expires_at": expires_at.isoformat()
        }).eq("email", email).execute()

        resp = make_response(redirect("/"))
        resp.set_cookie("auth_token", token, max_age=24*3600, httponly=True, samesite="Strict")
        return resp

    return render_template("login.html")

# ======================
# LOGIN REQUIRED DECORATOR
# ======================
def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token:
            return redirect("/login")
        
        res = supabase.table("user_sessions").select("*").eq("token", token).execute()
        if not res.data:
            return redirect("/login")

        user = res.data[0]
        if not user.get("expires_at"):
            return redirect("/login")
        
        expires_at = parser.isoparse(user["expires_at"])
        now = datetime.datetime.now(datetime.timezone.utc)
        if expires_at < now:
            return redirect("/login")

        return func(*args, **kwargs)
    return wrapper

# ======================
# MAIN PAGE — DECRYPTS API DATA
# ======================
@app.route("/")
@require_login
def show_load():
    page = request.args.get('page', default=1, type=int)
    limit = 10
    url = f"http://cricketprofile.in/cricvoxencdec/2026V1/index.php/User_app/getallmatch?page={page}&limit={limit}"
    
    headers = {
        'User-Agent': "okhttp/4.9.3",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Auth': "MIIDaDCCAlCgAwIBAgIFAMARsOYwDQYJKoZIhvcNAQEBQAwTjEqMCgGCSqGSIb3"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        # This will now return the decrypted list of matches
        data = parse_json_response(response)
    except Exception as e:
        print("API error:", e)
        data = []

    # Calculate betting percentages safely
    for match in data:
        team1_bet = safe_int(match.get("noteam1", 0))
        team2_bet = safe_int(match.get("noteam2", 0))
        total_match_bet = team1_bet + team2_bet
        match["team1_match_pct"] = round(team1_bet / total_match_bet * 100, 2) if total_match_bet else 0
        match["team2_match_pct"] = round(team2_bet / total_match_bet * 100, 2) if total_match_bet else 0

        toss1_bet = safe_int(match.get("toss1", 0))
        toss2_bet = safe_int(match.get("toss2", 0))
        total_toss_bet = toss1_bet + toss2_bet
        match["team1_toss_pct"] = round(toss1_bet / total_toss_bet * 100, 2) if total_toss_bet else 0
        match["team2_toss_pct"] = round(toss2_bet / total_toss_bet * 100, 2) if total_toss_bet else 0

    return render_template("matches.html", matches=data, page=page)

# ======================
# LOGOUT
# ======================
@app.route("/logout")
def logout():
    token = request.cookies.get("auth_token")
    if token:
        supabase.table("user_sessions").update({
            "is_active": False,
            "token": None,
            "expires_at": None
        }).eq("token", token).execute()
    resp = make_response(redirect("/login"))
    resp.delete_cookie("auth_token")
    return resp

if __name__ == "__main__":
    app.run(debug=True)