"""AUTH-1: authentication blueprint — register / email-verify / login / 2FA /
password-reset. Owns all session state; main.py decorates routes with the
login_required helper exported from here.
"""
import hashlib
import logging
import os
import re
import secrets
import smtplib
import uuid as _uuid
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from functools import wraps

import db

logger = logging.getLogger(__name__)
from flask import (Blueprint, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# Stable namespace for deterministic user IDs (email-based, pattern)
_USER_NS = _uuid.UUID("b3e7d1a2-c4f5-4e6b-9a0c-1d2e3f4a5b6c")

# Password rules: ≥15 chars, lower + upper + digit + symbol
_PW_RULES = [re.compile(p) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^a-zA-Z0-9]")]


def _valid_password(pw: str) -> bool:
    return len(pw) >= 15 and all(r.search(pw) for r in _PW_RULES)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _send_email(to: str, subject: str, body: str) -> None:
    """Send via SMTP env vars; fall back to console when unconfigured (dev mode)."""
    host = os.getenv("SMTP_HOST")
    if not host:
        logger.info("AUTH EMAIL (no SMTP configured) — To: %s Subject: %s\n%s", to, subject, body)
        return
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
        user = os.getenv("SMTP_USER", "")
        pw   = os.getenv("SMTP_PASS", "")
        frm  = os.getenv("SMTP_FROM", user)
        msg  = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = frm
        msg["To"]      = to
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            if user:
                s.login(user, pw)
            s.sendmail(frm, [to], msg.as_string())
    except Exception as exc:
        logger.error("AUTH EMAIL send failed to %s: %s", to, exc)


def login_required(f):
    """Decorator: allow the request only when the session maps to a real user.

    Best-practice "user loader" pattern (the contract Flask-Login enforces): the
    signed cookie is only an *identifier*, never proof the account still exists.
    We resolve session["user_id"] against the database on every request; if the
    row is gone (DB reset/wipe, user deleted, restored-from-old-backup cookie),
    we drop the stale session and bounce to login instead of letting a "ghost
    session" through to handlers that would then FK-reference a missing user.
    The loaded row is stashed on flask.g so handlers can reuse it cheaply.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("auth.login"))
        user = db.get_user_by_id(user_id)
        if user is None:
            session.clear()
            return redirect(url_for("auth.login"))
        g.user = user
        return f(*args, **kwargs)
    return decorated


# ── Register ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        pw       = request.form.get("password", "")
        pw2      = request.form.get("password2", "")

        if not username or not email or not pw:
            flash("All fields are required.", "error")
        elif pw != pw2:
            flash("Passwords do not match.", "error")
        elif not _valid_password(pw):
            flash("Password must be ≥15 characters with uppercase, lowercase, digit, and symbol.",
                  "error")
        elif db.get_user_by_email(email):
            flash("Email already registered.", "error")
        else:
            user_id = str(_uuid.uuid5(_USER_NS, email))
            logger.info("auth register new user %s (id=%s)", email, user_id)
            db.create_user(user_id, username, email, generate_password_hash(pw))
            token   = secrets.token_urlsafe(32)
            expires = (_now_utc() + timedelta(hours=24)).isoformat()
            db.create_auth_code(user_id, _hash(token), "email_verify", expires)
            link = url_for("auth.verify_email", token=token, _external=True)
            _send_email(email, "Verify your smashedburger account",
                        f"Click to verify your email:\n\n{link}\n\nExpires in 24 hours.")
            flash("Account created — check your email to verify.", "ok")
            return redirect(url_for("auth.login"))

    return render_template("register.html")


# ── Email verification ────────────────────────────────────────────────────────

@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    row = db.get_auth_code(_hash(token), "email_verify")
    if not row:
        flash("Verification link is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))
    db.set_user_verified(row["user_id"])
    db.mark_code_used(row["id"])
    flash("Email verified — you can now log in.", "ok")
    return redirect(url_for("auth.login"))


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw    = request.form.get("password", "")
        user  = db.get_user_by_email(email)

        if not user or not check_password_hash(user["password_hash"], pw):
            logger.warning("auth login failed for %s (user=%s)", email, "unknown" if not user else "bad_pw")
            flash("Invalid email or password.", "error")
        elif not user["verified"]:
            flash("Please verify your email before logging in.", "error")
        else:
            db.invalidate_user_codes(user["id"], "2fa")
            code    = f"{secrets.randbelow(1_000_000):06d}"
            expires = (_now_utc() + timedelta(minutes=5)).isoformat()
            db.create_auth_code(user["id"], _hash(code), "2fa", expires)
            _send_email(email, "Your smashedburger login code",
                        f"Your 2FA code:\n\n  {code}\n\nExpires in 5 minutes.")
            session["pending_user_id"] = user["id"]
            return redirect(url_for("auth.verify_2fa"))

    return render_template("login.html")


# ── 2FA verification ──────────────────────────────────────────────────────────

@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if session.get("user_id"):
        return redirect(url_for("index"))
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        # Fix 4: rate-limit 2FA attempts to prevent brute-forcing the 6-digit OTP.
        # The attempt counter lives in the session (server-signed cookie) so it can't
        # be reset by the client. After 5 wrong attempts we kill the pending session
        # and force a fresh login — attacker must re-authenticate to get a new OTP.
        attempts = session.get("2fa_attempts", 0)
        if attempts >= 5:
            logger.warning("auth 2FA rate-limit hit for user_id=%s — session cleared", user_id)
            session.clear()
            flash("Too many failed attempts — please log in again.", "error")
            return redirect(url_for("auth.login"))

        code = request.form.get("code", "").strip()
        row  = db.get_auth_code(_hash(code), "2fa", user_id=user_id)
        if not row:
            session["2fa_attempts"] = attempts + 1
            remaining = 5 - session["2fa_attempts"]
            flash(f"Invalid or expired code. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", "error")
        else:
            db.mark_code_used(row["id"])
            # Fix 2: session fixation defence — clear the old session (which held
            # pending_user_id) before writing the new authenticated user_id.
            # Without this, any session ID an attacker planted before login is
            # silently promoted to an authenticated session after 2FA succeeds.
            logger.info("auth 2FA success for user_id=%s — new session issued", user_id)
            session.clear()
            session["user_id"] = user_id
            session.permanent = True   # Fix 1: honour PERMANENT_SESSION_LIFETIME
            # CSRF token: generated once per session, stored server-side in the
            # signed session cookie AND exposed as a readable JS cookie so the
            # frontend can attach it as X-CSRF-Token on state-changing requests.
            # The browser's same-origin policy prevents a cross-origin attacker
            # from reading this cookie — that's what makes the defence work.
            session["csrf_token"] = secrets.token_hex(32)
            resp = redirect(url_for("index"))
            resp.set_cookie(
                "csrf_token",
                session["csrf_token"],
                httponly=False,  # intentionally JS-readable
                samesite="Lax",
            )
            return resp
    return render_template("verify_2fa.html")


# ── Forgot password ───────────────────────────────────────────────────────────

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user  = db.get_user_by_email(email)
        # Always show success — don't reveal whether the email is registered
        if user and user["verified"]:
            db.invalidate_user_codes(user["id"], "password_reset")
            token   = secrets.token_urlsafe(32)
            expires = (_now_utc() + timedelta(minutes=15)).isoformat()
            db.create_auth_code(user["id"], _hash(token), "password_reset", expires)
            link = url_for("auth.reset_password", token=token, _external=True)
            _send_email(email, "Reset your smashedburger password",
                        f"Click to reset your password:\n\n{link}\n\nExpires in 15 minutes.")
        flash("If that email is registered you'll receive a reset link shortly.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html")


# ── Reset password ────────────────────────────────────────────────────────────

@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    row = db.get_auth_code(_hash(token), "password_reset")
    if not row:
        flash("Reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.forgot_password"))
    if request.method == "POST":
        pw  = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        if pw != pw2:
            flash("Passwords do not match.", "error")
        elif not _valid_password(pw):
            flash("Password must be ≥15 characters with uppercase, lowercase, digit, and symbol.",
                  "error")
        else:
            db.update_user_password(row["user_id"], generate_password_hash(pw))
            db.mark_code_used(row["id"])
            flash("Password updated — please log in.", "ok")
            return redirect(url_for("auth.login"))
    return render_template("reset_password.html", token=token)


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
