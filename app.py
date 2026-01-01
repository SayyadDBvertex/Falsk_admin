from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import get_jwt

from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
import os

app = Flask(__name__)

# ---------------- CONFIG ----------------
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db_flask.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['JWT_SECRET_KEY'] = os.environ.get(
    "JWT_SECRET_KEY", "super_jwt_secret"
)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ---------------- MODEL ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    role = db.Column(db.String(20), default="admin")
    # values: admin | user | editor (future)



# ---------------- ROOT ----------------
@app.route("/")
def root():
    return redirect(url_for("signup"))


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("auth/signup.html")

    data = request.get_json(silent=True) or request.form

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # 🔒 VALIDATION
    if not name or not email or not password:
        return jsonify({
            "success": False,
            "message": "name, email and password are required"
        }), 400

    if User.query.filter_by(email=email).first():
        return jsonify({
            "success": False,
            "message": "Email already exists"
        }), 400

    user = User(
        name=name,
        email=email,
        password=generate_password_hash(password),
        role="admin"
    )

    db.session.add(user)
    db.session.commit()

    # 🔑 JWT TOKEN (signup ke baad direct login)
    access_token = create_access_token(
            identity=str(user.id),   # ✅ ONLY ID
    additional_claims={
        "email": user.email,
        "role": user.role,
        "name": user.name
    }
    )

    # ✅ FINAL RESPONSE
    return jsonify({
        "success": True,
        "message": "Signup successful",
        "token": access_token,
        "data": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }), 201




# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    # ✅ GET → show login page
    if request.method == "GET":
        return render_template("auth/login.html")

    # ✅ POST → API login
    data = request.get_json(silent=True) or request.form

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required"
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({
            "success": False,
            "message": "Invalid email or password"
        }), 401

    access_token = create_access_token(
       identity=str(user.id),   # ✅ ONLY ID
    additional_claims={
        "email": user.email,
         "role": user.role,
        "name": user.name
    }
    )

    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": access_token,
        "data": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }), 200



# ---------------- ADMIN ONLY ----------------

# ---------------- DASHBOARD API (JWT PROTECTED) ----------------
@app.route("/dashboard")
@jwt_required()
def dashboard_api():
    user_id = get_jwt_identity()        # 👈 string ID
    claims = get_jwt()

    return jsonify({
        "success": True,
        "message": "Welcome to admin dashboard",
         "user": {
            "id": user_id,
            "name": claims.get("name"),
            "email": claims.get("email"),
            "role": claims.get("role")
        }
    })
# ---------------- PROTECTED DASHBOARD ----------------
@app.route("/dashboard-page")
def dashboard_page():
    return render_template("admin/dashboard.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    # JWT stateless hota hai → server kuch clear nahi karta
    # bas user ko login page par bhej dete hain
    return redirect(url_for("login"))



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
