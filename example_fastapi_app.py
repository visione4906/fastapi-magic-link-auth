"""Minimal FastAPI demo showing magic-link login + signed session cookies.

Run:
    pip install fastapi uvicorn
    export AUTH_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
    python example_fastapi_app.py

Visit http://localhost:8000/login to start.

In production you would:
  1. Send the magic link by email (Resend, SES, Postmark, etc.) instead of
     printing it to the console.
  2. Replace the in-memory _USERS dict with a real database.
  3. Add CSRF protection on the login POST.
  4. Set secure=True on cookies and serve over HTTPS.
"""
import os
from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from auth import (
    issue_magic_link_token,
    consume_magic_link_token,
    issue_session_token,
    resolve_session,
)

app = FastAPI()

# Pretend "user database"
_USERS = {
    "alice@example.com": {"id": "user_alice", "name": "Alice"},
    "bob@example.com": {"id": "user_bob", "name": "Bob"},
}

SESSION_COOKIE = "demo_session"


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user_id = resolve_session(request.cookies.get(SESSION_COOKIE))
    if not user_id:
        return HTMLResponse(
            '<h1>Welcome</h1><p><a href="/login">Sign in with a magic link</a></p>'
        )
    user = next((u for u in _USERS.values() if u["id"] == user_id), None)
    name = user["name"] if user else "(unknown)"
    return HTMLResponse(
        f'<h1>Welcome back, {name}</h1>'
        f'<p>Your session token is valid. <a href="/logout">Sign out</a></p>'
    )


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return HTMLResponse(
        '<h1>Sign in</h1>'
        '<form method="post" action="/login">'
        '<label>Email: <input type="email" name="email" required></label>'
        '<button type="submit">Send magic link</button>'
        '</form>'
        '<p><small>Try alice@example.com or bob@example.com</small></p>'
    )


@app.post("/login", response_class=HTMLResponse)
def login_submit(email: str = Form(...)):
    email = email.lower().strip()
    # Always respond identically whether the email is known or not, to avoid
    # leaking which addresses are registered.
    if email in _USERS:
        token = issue_magic_link_token(email)
        link = f"http://localhost:8000/auth?token={token}"
        # In production: send `link` via email.
        # In demo: print to console.
        print(f"\n=== Magic link for {email} ===\n{link}\n")
    return HTMLResponse(
        "<h1>Check your inbox</h1>"
        "<p>If that email is registered, a sign-in link is on its way. "
        "(In this demo, look in the server console.)</p>"
    )


@app.get("/auth")
def auth_callback(token: str):
    email = consume_magic_link_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired link")
    user = _USERS.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="No user for that email")
    session_token = issue_session_token(user["id"])
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        httponly=True,
        secure=False,  # set True in production
        samesite="lax",
        max_age=30 * 24 * 3600,
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


if __name__ == "__main__":
    if not os.environ.get("AUTH_SECRET"):
        print(
            "ERROR: AUTH_SECRET not set. Set it before running:\n"
            "  export AUTH_SECRET=$(python -c \"import secrets; print(secrets.token_urlsafe(32))\")\n"
        )
        raise SystemExit(1)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
