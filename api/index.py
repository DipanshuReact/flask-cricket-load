from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, make_response
from supabase import create_client
from flask_bcrypt import Bcrypt
import os, secrets, datetime, requests
from dateutil import parser

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Supabase client setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app.secret_key = os.getenv("SECRET_KEY", "fallback_secret_key")

def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

# LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        res = supabase.table("user_sessions").select("*").eq("email", email).execute()
        if not res.data:
            return "Banned by CricVox voilating rules!", 401
        
        user = res.data[0]
        if password != user["password"]:
            return "Banned by CricVox voilating rules!", 401

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

def require_login(func):
    def wrapper(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token:
            return redirect("/login")
        
        res = supabase.table("user_sessions").select("*").eq("token", token).execute()
        if not res.data:
            return redirect("/login")

        user = res.data[0]
        if not user["expires_at"]:
            return redirect("/login")
        
        expires_at = parser.isoparse(user["expires_at"])
        now = datetime.datetime.now(datetime.timezone.utc)
        if expires_at < now:
            return redirect("/login")

        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route("/")
@require_login
def show_load():
    page = request.args.get('page', default=1, type=int)
    limit = 10
    url = f"http://cricketprofile.in/opgopalbhati/Jdieodapi_cricketprofile/index.php/User_app/getallmatch?page={page}&limit={limit}"
    headers = {
        'User-Agent': "okhttp/3.4.1",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Auth': "MIIDaDCCAlCgAwIBAgIFAMARsOYwDQYJKoZIhvcNAQEBQAwTjEqMCgGCSqGSIb3"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print("API error:", e)
        data = []

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


