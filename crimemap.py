import logging
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
import json
from datetime import datetime
import pytz
from typing import Dict, Any, Optional

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database helper selection
if dbconfig.test:
    from mockdbhelper import MockDBHelper as DBHelper
else:
    from dbhelper import DBHelper

# Initialize Flask app
app = Flask(__name__)
DB = DBHelper()

# Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "jwt-secret")

# Initialize extensions
CORS(
    app,
    resources={r"/api/*": {"origins": "http://localhost:3000"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE"],
)
jwt = JWTManager(app)

# Constants
KENYA_TZ = pytz.timezone("Africa/Nairobi")
DEFAULT_ROLE = "user"
ADMIN_ROLE = "admin"


# Helper functions
def validate_required_fields(
    data: Dict[str, Any], required_fields: list
) -> Optional[str]:
    """Validate that required fields are present in the request data."""
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return f"Missing required fields: {', '.join(missing_fields)}"
    return None


def reverse_geocode(lat: float, lon: float) -> str:
    """Convert coordinates to a readable address using OpenStreetMap's Nominatim API."""
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}"
        response = requests.get(url, headers={"User-Agent": "CrimeMappingApp"})
        return response.json().get("display_name", f"{lat}, {lon}")
    except Exception as e:
        logger.error(f"Reverse geocoding failed: {str(e)}")
        return f"{lat}, {lon}"


# Middleware
@app.before_request
def ensure_json():
    """Ensure all POST/PUT requests have a valid JSON body."""
    if request.method in ["POST", "PUT"] and not request.is_json:
        logger.warning("Invalid JSON request received")
        return jsonify({"error": "Invalid JSON format"}), 400


# Authentication routes
@app.route("/api/register", methods=["POST"])
def register():
    """Register a new user."""
    try:
        data = request.json
        if error := validate_required_fields(data, ["username", "password"]):
            logger.warning(f"Registration failed - {error}")
            return jsonify({"error": error}), 400

        username = data["username"]
        password = data["password"]
        role = data.get("role", DEFAULT_ROLE)

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )

        if not hasattr(DB, "create_user"):
            logger.error("Database helper missing create_user method")
            return jsonify({"error": "Database configuration error"}), 500

        if DB.create_user(username, hashed_pw, role):
            logger.info(f"User {username} registered successfully")
            return jsonify({"success": "User registered successfully"}), 201

        logger.warning(f"Username {username} already exists")
        return jsonify({"error": "Username already exists"}), 400

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Registration failed", "details": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():
    """Authenticate user and return JWT token."""
    try:
        # Validate request format
        if not request.is_json:
            logger.warning("Login attempt with non-JSON payload")
            return jsonify({"error": "Request must be JSON"}), 400

        data = request.get_json()

        # Validate required fields
        if error := validate_required_fields(data, ["username", "password"]):
            logger.warning(f"Login validation failed - {error}")
            return jsonify({"error": error}), 400

        username = data["username"].strip()
        password = data["password"]

        # Rate limiting check would go here in production

        # Fetch user from database
        user = DB.get_user(username)
        if not user:
            # Use same error message to prevent username enumeration
            logger.warning(f"Failed login attempt for username: {username}")
            return jsonify({"error": "Invalid credentials"}), 401

        # Verify password
        if not bcrypt.checkpw(
            password.encode("utf-8"), user["password"].encode("utf-8")
        ):
            logger.warning(f"Invalid password attempt for user: {username}")
            return jsonify({"error": "Invalid credentials"}), 401

        # Generate token with expiration and fresh status
        access_token = create_access_token(
            identity=username,
            additional_claims={
                "role": user.get("role", DEFAULT_ROLE),
                "fresh": True,  # Marks this as a fresh login token
            },
            # Optional: Set token expiration (e.g., 15 minutes)
            # expires_delta=timedelta(minutes=15)
        )

        # Security logging
        logger.info(
            f"Successful login for user: {username}",
            extra={"ip": request.remote_addr, "user_agent": request.user_agent.string},
        )

        # Secure response
        response = jsonify(
            {
                "token": access_token,
                "role": user.get("role", DEFAULT_ROLE),
                "message": "Login successful",
            }
        )

        # Set secure cookies if using cookies
        # response.set_cookie('token', access_token, httponly=True, secure=True, samesite='Strict')

        return response, 200

    except Exception as e:
        logger.exception("Critical login error")  # Logs full traceback
        return (
            jsonify(
                {
                    "error": "Authentication service unavailable",
                    "details": str(e) if app.debug else None,
                }
            ),
            500,
        )


# @app.route("/api/refresh", methods=["POST"])
# @jwt_required(refresh=True)
# def refresh():
#     current_user = get_jwt_identity()
#     new_token = create_access_token(identity=current_user)
#     return jsonify({"token": new_token}), 200


# Crime reporting routes
@app.route("/api/submitcrime", methods=["POST"])
@jwt_required()
def submit_crime():
    """Submit a new crime report."""
    try:
        username = get_jwt_identity()
        data = request.json
        required_fields = ["category", "latitude", "longitude"]

        if error := validate_required_fields(data, required_fields):
            logger.warning(f"Crime submission failed - {error}")
            return jsonify({"error": error}), 400

        try:
            latitude = float(data["latitude"])
            longitude = float(data["longitude"])
        except ValueError:
            logger.warning("Invalid coordinates received")
            return jsonify({"error": "Invalid coordinates"}), 400

        DB.add_crime(
            category=data["category"],
            date=datetime.now(KENYA_TZ).strftime("%Y-%m-%d %H:%M:%S"),
            latitude=latitude,
            longitude=longitude,
            description=data.get("description", ""),
            reporter=username if not data.get("anonymous", False) else "Anonymous",
        )
        logger.info(f"Crime reported by {username}")
        return jsonify({"success": "Crime reported successfully"}), 200

    except Exception as e:
        logger.error(f"Crime submission error: {str(e)}")
        return jsonify({"error": "Failed to submit crime", "details": str(e)}), 500


# Admin routes
@app.route("/api/users", methods=["GET"])
@jwt_required()
def get_users():
    """Get all users (admin only)."""
    try:
        if get_jwt().get("role") != ADMIN_ROLE:
            logger.warning("Unauthorized access attempt to users endpoint")
            return jsonify({"error": "Unauthorized"}), 403

        users = DB.get_all_users()
        logger.info("Users list retrieved by admin")
        return jsonify(users), 200
    except Exception as e:
        logger.error(f"Users retrieval error: {str(e)}")
        return jsonify({"error": "Failed to fetch users", "details": str(e)}), 500


@app.route("/api/admin/crime-reports", methods=["GET"])
@jwt_required()
def admin_crime_reports():
    """Get all crime reports (admin only)."""
    try:
        if get_jwt().get("role") != ADMIN_ROLE:
            logger.warning("Unauthorized access attempt to crime reports")
            return jsonify({"error": "Unauthorized"}), 403

        crimes = DB.get_all_crimes()
        logger.info("Crime reports retrieved by admin")
        return jsonify(crimes), 200
    except Exception as e:
        logger.error(f"Crime reports retrieval error: {str(e)}")
        return (
            jsonify({"error": "Failed to fetch crime reports", "details": str(e)}),
            500,
        )


# User data routes
@app.route("/api/alerts", methods=["GET"])
@jwt_required()
def get_alerts():
    """Get alerts for the current user."""
    try:
        username = get_jwt_identity()
        alerts = DB.get_alerts_for_user(username)
        logger.info(f"Alerts retrieved for user {username}")
        return jsonify({"alerts": alerts}), 200
    except Exception as e:
        logger.error(f"Alerts retrieval error for {username}: {str(e)}")
        return jsonify({"error": "Failed to fetch alerts", "details": str(e)}), 500


@app.route("/api/user/reports", methods=["GET"])
@jwt_required()
def get_user_reports():
    """Get crime reports submitted by the current user."""
    try:
        # Get authenticated user's identity
        username = get_jwt_identity()

        # Validate username exists
        if not username:
            logger.error("No username found in JWT token")
            return jsonify({"error": "User not authenticated"}), 401

        # Fetch reports from database
        reports = DB.get_reports_by_user(username)
        logger.debug(f"🔍 Reports retrieved from DB for {username}: {reports}")

        # Log successful retrieval
        logger.info(
            f"Successfully retrieved {len(reports)} reports for user {username}"
        )

        # Return reports (empty array if none found)
        return jsonify(reports or []), 200

    except Exception as e:
        # Log the full error with stack trace
        logger.exception(f"Failed to fetch reports for user {username or 'unknown'}")

        # Return sanitized error message to client
        error_details = str(e) if app.debug else "Internal server error"
        return (
            jsonify(
                {"error": "Failed to fetch user reports", "details": error_details}
            ),
            500,
        )


# Public data routes
@app.route("/api/heatmap-data", methods=["GET"])
def get_heatmap_data():
    """Get crime heatmap data."""
    try:
        with open("static/data/heatmap_data.json", "r") as json_file:
            logger.info("Heatmap data retrieved successfully")
            return jsonify(json.load(json_file)), 200
    except FileNotFoundError:
        logger.error("Heatmap data file not found")
        return jsonify({"error": "Heatmap data not found"}), 404
    except json.JSONDecodeError:
        logger.error("Invalid heatmap data format")
        return jsonify({"error": "Invalid heatmap data format"}), 500
    except Exception as e:
        logger.error(f"Heatmap data retrieval error: {str(e)}")
        return jsonify({"error": "Failed to load heatmap data", "details": str(e)}), 500


@app.route("/api/latestcrimes", methods=["GET"])
def latest_crimes():
    """Get the latest crime reports."""
    try:
        crimes = []
        for crime in DB.get_latest_crimes(limit=5):
            crimes.append(
                {
                    "category": crime["category"],
                    "location": reverse_geocode(crime["latitude"], crime["longitude"]),
                    "timestamp": crime["date"].strftime("%Y-%m-%d %I:%M %p"),
                }
            )
        logger.info("Latest crimes retrieved successfully")
        return jsonify({"crimes": crimes}), 200
    except Exception as e:
        logger.error(f"Latest crimes retrieval error: {str(e)}")
        return (
            jsonify({"error": "Failed to fetch latest crimes", "details": str(e)}),
            500,
        )


if __name__ == "__main__":
    logger.info("Starting Crime Reporting API")
    app.run(port=5000, debug=True)
