from flask import Flask, jsonify, request
import dbconfig
import os
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
import bcrypt
import requests


# Use appropriate database helper
if dbconfig.test:
    from mockdbhelper import MockDBHelper as DBHelper
else:
    from dbhelper import DBHelper

app = Flask(__name__)
CORS(
    app,
    resources={r"/api/*": {"origins": "http://localhost:3000"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE"],
)
DB = DBHelper()

# Secret key for JWT
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "jwt-secret")
jwt = JWTManager(app)


@app.before_request
def ensure_json():
    """Ensure all POST/PUT requests have a valid JSON body."""
    if request.method in ["POST", "PUT"] and not request.is_json:
        return jsonify({"error": "Invalid JSON format"}), 400


# ✅ User Registration
@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")
        role = data.get("role", "user")  # Default role is "user"

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )

        if not hasattr(DB, "create_user"):
            return jsonify({"error": "DBHelper missing `create_user` method"}), 500

        if DB.create_user(username, hashed_pw, role):
            return jsonify({"success": "User registered successfully"}), 201
        else:
            return jsonify({"error": "Username already exists"}), 400

    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


# ✅ User Login (Fixed JWT Token)
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        user = DB.get_user(username)
        if not user:
            return jsonify({"error": "User not found"}), 404

        stored_password = user["password"]
        if not isinstance(stored_password, str):
            return jsonify({"error": "Invalid password format"}), 500

        if not bcrypt.checkpw(
            password.encode("utf-8"), stored_password.encode("utf-8")
        ):
            return jsonify({"error": "Invalid credentials"}), 401

        # ✅ Fix: Store only username in `identity`, move `role` to `additional_claims`
        role = user.get("role", "user")  # Ensure role exists
        access_token = create_access_token(
            identity=username, additional_claims={"role": role}
        )

        return jsonify({"token": access_token, "role": role}), 200

    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


# ✅ Submit Crime Report (Fixed JWT Handling)
@app.route("/api/submitcrime", methods=["POST"])
@jwt_required()
def submitcrime():
    try:
        username = get_jwt_identity()  # Correctly retrieving username
        role = get_jwt().get("role", "user")  # Ensure role is retrieved safely

        if not username:
            return jsonify({"error": "Invalid JWT token"}), 403

        # Retrieve form data
        data = request.json  # Expecting JSON input
        category = data.get("category")
        date = data.get("date")
        latitude = data.get("latitude")
        longitude = data.get("longitude")
        description = data.get("description")
        anonymous = data.get("anonymous", False)

        if not (category and date and latitude and longitude):
            return jsonify({"error": "Missing required fields"}), 400

        try:
            latitude = float(latitude)
            longitude = float(longitude)
        except ValueError:
            return jsonify({"error": "Invalid latitude/longitude"}), 400

        DB.add_crime(
            category,
            date,
            latitude,
            longitude,
            description,
            username if not anonymous else "Anonymous",
        )

        return jsonify({"success": "Crime reported successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ✅ Get Users (Admin Only)
@app.route("/api/users", methods=["GET"])
@jwt_required()
def get_users():
    role = get_jwt().get("role", None)

    if role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    users = DB.get_all_users()
    return jsonify(users), 200


# ✅ Get Crime Reports (Admin Only)
@app.route("/api/admin/crime-reports", methods=["GET"])
@jwt_required()
def admin_crime_reports():
    role = get_jwt().get("role", None)

    if role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    crimes = DB.get_all_crimes()
    return jsonify(crimes), 200


# ✅ Get User Reports
@app.route("/api/user/reports", methods=["GET"])
@jwt_required()
def get_user_reports():
    try:
        username = get_jwt_identity()
        user_reports = DB.get_reports_by_user(username)

        return jsonify(user_reports or []), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ✅ Get Heatmap Data
@app.route("/api/heatmap-data", methods=["GET"])
def get_heatmap_data():
    try:
        crime_records = DB.get_all_crimes()

        if not crime_records:
            return jsonify({"error": "No crimes found"}), 404

        heatmap_matrix = {}
        locations = ["Nairobi", "Mombasa", "Kisumu", "Nakuru", "Eldoret"]
        crime_types = ["Homicide", "Theft", "Assault", "Vandalism"]

        for loc in locations:
            heatmap_matrix[loc] = {crime: 0 for crime in crime_types}

        for crime in crime_records:
            location = crime.get("location", "Unknown")
            category = crime.get("category", "Unknown")
            if location in heatmap_matrix and category in heatmap_matrix[location]:
                heatmap_matrix[location][category] += 1

        return jsonify(heatmap_matrix), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def reverse_geocode(lat, lon):
    """Convert latitude and longitude to a readable address using OpenStreetMap's Nominatim API."""
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}"
        headers = {"User-Agent": "CrimeMappingApp"}
        response = requests.get(url, headers=headers)
        data = response.json()
        return data.get(
            "display_name", f"{lat}, {lon}"
        )  # Return address or fallback to coordinates
    except Exception as e:
        print(f"Reverse Geocoding Error: {e}")
        return f"{lat}, {lon}"  # Fallback in case of error


@app.route("/api/latestcrimes", methods=["GET"])
def latest_crimes():
    try:
        crimes = DB.get_latest_crimes(limit=5)  # Fetch the latest 5 crimes
        crime_list = [
            {
                "category": crime["category"],
                "location": reverse_geocode(crime["latitude"], crime["longitude"]),
                "timestamp": crime["date"],
            }
            for crime in crimes
        ]
        return jsonify({"crimes": crime_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5000, debug=True)
