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