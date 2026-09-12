import secrets #generates random numbers to secure your password
import sqlite3 #used to store user information
from datetime import datetime, timedelta#dates and time
from flask import Flask,redirect,flash,render_template,request,session,url_for
#secure the password
from werkzeug.security import check_password_hash,generate_password_hash
#database,api key
from config import DATABASE,SECRET_KEY
#create a flask app
app=Flask(__name__)
#attach the secret key
app.config["SECRET_KEY"]=SECRET_KEY
def get_db():
    #connect to sqlite
    connection=sqlite3.connect(DATABASE)
    #access the data base
    connection.row_factory=sqlite3.Row
    return connection
#add new users to the database
def init_db():
    #open the database using the connection
    with get_db() as connection:
        #add a user into database
        connection.execute(
            """
CREATE TABLE IF NOT EXIST users(
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
#login page
@app.route("/",methods=["GET","POST"])
def login():
    #check if user has submitted the form
    if request.method=="POST":
        email=request.form["email"].strip().lower()
        password=request.form["password"]
        #connect to the database
        with get_db() as connection:
            #find the user using the email
            user=connection.execute("SELECT * FROM users WHERE email=>?",(email,)).fetchone()
            #check if password is correct
            if user and check_password_hash(user["password_hash"],password):
                #check if user is verified
                if not user["verified"]:
                    #display an error message
                    flash("Please verify your email to proceed")
                    #send to verification page
                    return redirect(url_for("verify_email",email=email))
                #store the id for the session
                session["user_id"]=user["id"]
                #display the dashboard
                return redirect(url_for("dashboard"))
            flash("Email or Password incorrect!")
    #display html file
    return render_template("index.html")
#signup function
@app.route("/signup",methods=["GET", "POST"])
def signup():
    #check if the form is submitted
    if request.method=="POST":
        #get the user details
        name=request.form["name"]
        email=request.form["email"].lower()
        password=request.form["password"] 
        confirm_password=request.form["confimpassword"]
        if not name or not email or not password:
            flash("Fill all forms please!")
        elif password!=confirm_password:
            flash("Password has to match")
        elif len(password)<6:
            flash("Password must be atleast 6 characters")
        else:
            #create a verification token
            verificationtoken=secrets.token_urlsafe(20)
            try:
                #add user into the database
                with get_db() as container:
                    container.execute("""INSERT INTO users(name,email,password_hash,verification_token)VALUES(?,?,?,?)""",(name,email,generate_password_hash(password),verificationtoken))
                flash("Account has been created. Please check your email to verify your account")
                #open verification page
                return redirect(url_for("verify_email",email=email,token=verificationtoken))
            except sqlite3.IntegrityError:
                #email already exits
                flash("This email has already been registered!")
    #didplay sign up page
    return render_template("signup.html2")
#verify email
@app.route("/verify-email",methods=["GET","POST"])
def verify_email():
    #get the email and token
    email=request.args.get("email",request.form.get("email","")).lower()
    token=request.args.get("token",request.form.get("token",""))
    #check if the form was submitted
    if request.method=="POST":
        #update the status of verified
        with get_db() as connection:
            #verify user
            updated=connection.execute("""UPDATE users SET verified=1,verified_token=NULL WHERE email=? AND verification_token=?""",(email,token)).rowcount
        if updated:
            flash("Email has been verified. Able to login")
            return redirect(url_for("login"))
        flash("Invalid verification link")
    return render_template("verifyemail.html",email=email,token=token)