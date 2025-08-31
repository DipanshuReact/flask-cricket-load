from flask import Flask, render_template, request
import requests
import json

app = Flask(__name__)

@app.route('/')
def show_load():
    # Get current page from query string (default 1)
    page = request.args.get('page', default=1, type=int)
    limit = 10  # still show 10 matches per page

    url = f"http://cricketprofile.in/opgopalbhati/Jdieodapi_cricketprofile/index.php/User_app/getallmatch?page={page}&limit={limit}"
    
    headers = {
        'User-Agent': "okhttp/3.4.1",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Auth': "MIIDaDCCAlCgAwIBAgIFAMARsOYwDQYJKoZIhvcNAQEBQAwTjEqMCgGCSqGSIb3"
    }

    response = requests.get(url, headers=headers)
    data = response.json()  # direct JSON parsing

    # --- calculate percentages as before ---
    for match in data:
        # Match bets
        team1_bet = int(match.get("noteam1", 0) or 0)
        team2_bet = int(match.get("noteam2", 0) or 0)
        total_match_bet = team1_bet + team2_bet
        match["team1_match_pct"] = round(team1_bet / total_match_bet * 100, 2) if total_match_bet else 0
        match["team2_match_pct"] = round(team2_bet / total_match_bet * 100, 2) if total_match_bet else 0

        # Toss bets
        toss1_bet = int(match.get("toss1", 0) or 0)
        toss2_bet = int(match.get("toss2", 0) or 0)
        total_toss_bet = toss1_bet + toss2_bet
        match["team1_toss_pct"] = round(toss1_bet / total_toss_bet * 100, 2) if total_toss_bet else 0
        match["team2_toss_pct"] = round(toss2_bet / total_toss_bet * 100, 2) if total_toss_bet else 0

    # Pass matches and current page to template
    return render_template('matches.html', matches=data, page=page)

# Do NOT use app.run() here!
# Vercel automatically serves app when you deploy
