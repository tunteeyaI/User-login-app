import secrets
import sqlite3
from datetime import datetime, timedelta

from flask import Flask, redirect, flash, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from config import DATABASE, SECRET_KEY


# Create Flask app
app = Flask(__name__)

# Secret key for sessions
app.config["SECRET_KEY"] = SECRET_KEY


# Connect to database
def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# Create users table
def init_db():
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                verification_token TEXT,
                reset_token TEXT,
                reset_expires TEXT
            )
            """
        )


def get_logged_in_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    with get_db() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


# Login page
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        with get_db() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                if not user["verified"]:
                    flash("Please verify your email.")
                    return redirect(url_for("verify_email", email=email))

                session["user_id"] = user["id"]
                return redirect(url_for("dashboard"))

        flash("Email or Password is incorrect.")

    return render_template("index.html")


# Signup page
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not name or not email or not password:
            flash("All fields are required.")
        elif password != confirm_password:
            flash("Passwords do not match.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            verification_token = secrets.token_urlsafe(20)

            try:
                with get_db() as connection:
                    connection.execute(
                        """
                        INSERT INTO users
                        (name, email, password_hash, verification_token)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            name,
                            email,
                            generate_password_hash(password),
                            verification_token,
                        ),
                    )

                flash("Account created. Verify your email.")
                return redirect(
                    url_for("verify_email", email=email, token=verification_token)
                )
            except sqlite3.IntegrityError:
                flash("This email is already registered.")

    return render_template("signup.html")


# Email verification
@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    email = request.args.get("email", request.form.get("email", "")).strip().lower()
    token = request.args.get("token", request.form.get("token", ""))

    if request.method == "POST":
        with get_db() as connection:
            updated = connection.execute(
                """
                UPDATE users
                SET verified = 1,
                    verification_token = NULL
                WHERE email = ?
                AND verification_token = ?
                """,
                (email, token),
            ).rowcount

        if updated:
            flash("Email verified. You can now log in.")
            return redirect(url_for("login"))

        flash("That verification link is invalid.")

    return render_template("verifyemail.html", email=email, token=token)


# Forgot password route
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        reset_token = secrets.token_urlsafe(20)
        expires = datetime.utcnow() + timedelta(minutes=30)

        with get_db() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,),
            ).fetchone()

            if user:
                connection.execute(
                    """
                    UPDATE users
                    SET reset_token = ?, reset_expires = ?
                    WHERE id = ?
                    """,
                    (reset_token, expires.isoformat(), user["id"]),
                )

        flash("If the email exists, a reset link is ready.")
        return redirect(url_for("reset_password", email=email, token=reset_token))

    return render_template("forgotpassword.html")


# Reset password route
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = request.args.get("email", request.form.get("email", "")).strip().lower()
    token = request.args.get("token", request.form.get("token", ""))

    if request.method == "POST":
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        email = request.form.get("email", email).strip().lower()
        token = request.form.get("token", token)

        if len(password) < 8:
            flash("Password must be 8 characters and above.")
        elif password != confirm_password:
            flash("Passwords must match.")
        else:
            with get_db() as connection:
                user = connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE email = ?
                    AND reset_token = ?
                    AND reset_expires > ?
                    """,
                    (email, token, datetime.utcnow().isoformat()),
                ).fetchone()

                if user:
                    connection.execute(
                        """
                        UPDATE users
                        SET password_hash = ?, reset_token = NULL, reset_expires = NULL
                        WHERE id = ?
                        """,
                        (generate_password_hash(password), user["id"]),
                    )
                    flash("Password updated. You can now log in.")
                    return redirect(url_for("login"))

            flash("Invalid or expired reset token.")

    return render_template("resetpassword.html", email=email, token=token)


@app.route("/dashboard")
def dashboard():
    user = get_logged_in_user()
    if not user:
        flash("Please log in first.")
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))


init_db()


if __name__ == "__main__":
    app.run(debug=True)
