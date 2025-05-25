from collections import defaultdict
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
    create_refresh_token,
)
from werkzeug.exceptions import Forbidden
import bcrypt
import requests
import json
from datetime import datetime
import pytz
from typing import Dict, Any, Optional
from functools import wraps

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
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60 * 60 * 24 * 7  # 7 days
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 60 * 60 * 24 * 30  # 30 days

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


logger = logging.getLogger(__name__)

# Simplified role permissions
ROLES = {
    "admin": ["manage_users", "manage_alerts", "view_reports"],
    "user": ["submit_reports", "view_own_reports"],
}


@app.route("/api/login", methods=["POST"])
def login():
    """Authenticate user and return JWT token with role."""
    try:
        if not request.is_json:
            return jsonify({"error": "JSON payload required"}), 400

        data = request.get_json()
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        user = DB.get_user(username)
        if not user or not bcrypt.checkpw(
            password.encode(), user.get("password", "").encode()
        ):
            # Generic error to prevent user enumeration
            return jsonify({"error": "Invalid credentials"}), 401

        # Determine user role (default to 'user' if not specified)
        role = user.get("role", "user")
        if role not in ROLES:  # Only allow defined roles
            role = "user"

        # Create token with role and permissions
        additional_claims = {
            "role": role,
            "permissions": ROLES[role],
        }

        # Only add user_id if it exists in the user object
        if "id" in user:
            additional_claims["user_id"] = user["id"]

        # Create access token
        access_token = create_access_token(
            identity=username,
            additional_claims=additional_claims,
        )
        
        # Create refresh token
        refresh_token = create_refresh_token(identity=username)

        response_data = {
            "token": access_token,
            "refreshToken": refresh_token,
            "user": {
                "username": username,
                "role": role,
                "permissions": ROLES[role],
            },
            "redirect_to": "/admin/dashboard" if role == "admin" else None,
        }

        # Add user_id to response if available
        if "id" in user:
            response_data["user"]["id"] = user["id"]
            
        # Update last login time
        DB.update_last_login(username)

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({"error": "Login failed"}), 500


@app.route("/api/verify-token", methods=["GET"])
@jwt_required()
def verify_token():
    current_user = get_jwt_identity()
    user = DB.get_user(current_user)
    
    # Construct user data object similar to login response
    user_data = {
        "username": user["username"],
        "role": user.get("role", "user"),
        "permissions": ROLES[user.get("role", "user")],
    }
    
    if "id" in user:
        user_data["id"] = user["id"]
        
    return jsonify({"user": user_data, "isValid": True}), 200


def role_required(required_role="user", required_permission=None):
    """Decorator to restrict access by role and optional permission."""

    def decorator(f):
        @wraps(f)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            current_role = claims.get("role", "user")

            # Role check
            if current_role != required_role:
                logger.warning(
                    f"Role violation: {current_role} tried to access {required_role} endpoint"
                )
                raise Forbidden("Insufficient privileges")

            # Optional permission check
            if required_permission and required_permission not in claims.get(
                "permissions", []
            ):
                logger.warning(
                    f"Permission violation: User lacks {required_permission}"
                )
                raise Forbidden("Missing required permission")

            return f(*args, **kwargs)

        return wrapper

    return decorator


@app.route("/api/refresh-token", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Refresh the access token using a valid refresh token."""
    try:
        # Get user identity from refresh token
        current_user = get_jwt_identity()
        
        # Get user data
        user = DB.get_user(current_user)
        if not user:
            logger.warning(f"Refresh token used for non-existent user: {current_user}")
            return jsonify({"error": "Invalid refresh token"}), 401
            
        # Create new access token with the same claims
        role = user.get("role", "user")
        if role not in ROLES:
            role = "user"
            
        additional_claims = {
            "role": role,
            "permissions": ROLES[role],
        }
        
        if "id" in user:
            additional_claims["user_id"] = user["id"]
            
        new_token = create_access_token(
            identity=current_user,
            additional_claims=additional_claims,
        )
        
        logger.info(f"Refreshed token for user {current_user}")
        return jsonify({"token": new_token}), 200
        
    except Exception as e:
        logger.exception(f"Token refresh error: {str(e)}")
        return jsonify({"error": "Failed to refresh token"}), 500


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

        reporter_name = (
            "Anonymous" if data.get("anonymous", False) else get_jwt_identity()
        )
        DB.add_crime(
            category=data["category"],
            date=datetime.now(KENYA_TZ).strftime("%Y-%m-%d %H:%M:%S"),
            latitude=data["latitude"],
            longitude=data["longitude"],
            description=data.get("description", ""),
            username=reporter_name,
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


@app.route("/api/users", methods=["POST"])
@jwt_required()
def create_user():
    """Create a new user (admin only)."""
    try:
        # Verify admin role
        if get_jwt().get("role") != ADMIN_ROLE:
            logger.warning("Unauthorized access attempt to create user")
            return jsonify({"error": "Unauthorized"}), 403
            
        # Get request data
        data = request.json
        if not data:
            logger.warning("No data provided in user creation request")
            return jsonify({"error": "No data provided"}), 400
        
        # Log the received data for debugging (without password)
        safe_data = {k: v for k, v in data.items() if k != "password"}
        logger.info(f"User creation request with data: {safe_data}")
            
        # Validate required fields more flexibly
        username = data.get("username", "").strip()
        password = data.get("password", "")
        
        if not username:
            return jsonify({"error": "Username is required"}), 400
            
        if not password:
            return jsonify({"error": "Password is required"}), 400
            
        # Get role with a safe default
        role = data.get("role", DEFAULT_ROLE)
        
        # More permissive role validation - default to user role if invalid
        if role not in ROLES:
            logger.warning(f"Invalid role '{role}' provided, defaulting to '{DEFAULT_ROLE}'")
            role = DEFAULT_ROLE
            
        # Hash the password
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        
        # Create the user
        creation_result = DB.create_user(username, hashed_pw, role)
        if creation_result:
            logger.info(f"New user '{username}' with role '{role}' created successfully")
            
            # Get the newly created user
            user = DB.get_user(username)
            if not user:
                logger.error(f"User '{username}' was created but could not be retrieved")
                return jsonify({"success": True, "message": "User created but could not fetch details"}), 201
                
            user_data = {
                "username": user.get("username", username),
                "role": user.get("role", role)
            }
            
            if "id" in user:
                user_data["id"] = user["id"]
            
            return jsonify({
                "success": True, 
                "message": "User created successfully", 
                "user": user_data
            }), 201
        else:
            logger.warning(f"Failed to create user '{username}', may already exist")
            return jsonify({"error": "Username already exists or could not create user"}), 400
            
    except Exception as e:
        logger.exception(f"Error creating user: {str(e)}")
        return jsonify({"error": "Failed to create user", "details": str(e)}), 500


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    """Delete a user (admin only)."""
    try:
        if get_jwt().get("role") != ADMIN_ROLE:
            logger.warning("Unauthorized access attempt to delete user")
            return jsonify({"error": "Unauthorized"}), 403

        # Get the admin's username for logging
        admin_username = get_jwt_identity()
        
        # Can't delete yourself
        if DB.is_same_user(user_id, admin_username):
            logger.warning(f"Admin {admin_username} attempted to delete their own account")
            return jsonify({"error": "Cannot delete your own account"}), 400
        
        # Delete the user
        if DB.delete_user(user_id):
            logger.info(f"User ID {user_id} deleted by admin {admin_username}")
            return jsonify({"success": True, "message": "User deleted successfully"}), 200
        else:
            logger.error(f"Failed to delete user {user_id}")
            return jsonify({"error": "Failed to delete user"}), 500
            
    except Exception as e:
        logger.exception(f"Error deleting user {user_id}: {str(e)}")
        error_details = str(e) if app.debug else "Internal server error"
        return jsonify({"error": "Failed to delete user", "details": error_details}), 500


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    """Update a user (admin only)."""
    try:
        if get_jwt().get("role") != ADMIN_ROLE:
            logger.warning("Unauthorized access attempt to update user")
            return jsonify({"error": "Unauthorized"}), 403

        # Get the admin's username for logging
        admin_username = get_jwt_identity()
        
        # Get request data
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Validate data
        allowed_fields = ["username", "role"]
        update_data = {k: v for k, v in data.items() if k in allowed_fields}
        
        if not update_data:
            return jsonify({"error": "No valid fields to update"}), 400
            
        # Update the user
        success = DB.update_user(user_id, update_data)
        
        if success:
            logger.info(f"User ID {user_id} updated by admin {admin_username}")
            return jsonify({"success": True, "message": "User updated successfully"}), 200
        else:
            logger.error(f"Failed to update user {user_id}")
            return jsonify({"error": "Failed to update user"}), 500
            
    except Exception as e:
        logger.exception(f"Error updating user {user_id}: {str(e)}")
        error_details = str(e) if app.debug else "Internal server error"
        return jsonify({"error": "Failed to update user", "details": error_details}), 500


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


@app.route("/api/admin/alerts", methods=["POST"])
@jwt_required()
def create_alert():
    """Admin-only alert creation with proper field mapping"""
    try:
        # Verify admin role
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Admin privileges required"}), 403

        data = request.get_json()

        # Required fields validation
        required_fields = ["username", "type", "title", "message", "severity"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return (
                jsonify(
                    {"error": "Missing required fields", "missing": missing_fields}
                ),
                400,
            )

        # Create alert with mapped fields
        alert_data = {
            "username": data["username"],
            "type": data.get("type", "crime"),
            "title": data["title"],
            "message": data["message"],
            "severity": data.get("severity", "medium"),
        }

        if DB.create_alert(alert_data):
            return jsonify({"success": True}), 201
        return jsonify({"error": "Failed to create alert"}), 500

    except Exception as e:
        logger.error(f"Alert creation error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


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
    """Get paginated crime reports submitted by the current user."""
    try:
        # Get authenticated user's identity
        username = get_jwt_identity()

        # Validate username exists
        if not username:
            logger.error("No username found in JWT token")
            return jsonify({"error": "User not authenticated"}), 401

        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        # Validate pagination parameters
        if page < 1:
            page = 1
        if per_page < 1 or per_page > 50:
            per_page = 5

        # Fetch paginated reports from database
        result = DB.get_reports_by_user(username, page, per_page)
        logger.debug(f"🔍 Reports retrieved from DB for {username}: {result}")

        # Log successful retrieval
        logger.info(
            f"Successfully retrieved {len(result['reports'])} reports for user {username} (page {page})"
        )

        # Return paginated reports
        return jsonify(result), 200

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


@app.route("/api/user/reports/<int:report_id>", methods=["PUT"])
@jwt_required()
def update_user_report(report_id):
    """Update a crime report submitted by the current user."""
    try:
        username = get_jwt_identity()
        
        if not username:
            logger.error("No username found in JWT token")
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get the request data
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Check if report exists and belongs to user
        report = DB.get_report_by_id(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
            
        if report["username"] != username and get_jwt().get("role") != ADMIN_ROLE:
            return jsonify({"error": "Unauthorized to modify this report"}), 403
            
        # Update the report
        success = DB.update_crime(
            report_id=report_id,
            category=data.get("category"),
            description=data.get("description"),
            status=data.get("status"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude")
        )
        
        if success:
            logger.info(f"Report {report_id} updated successfully by {username}")
            return jsonify({"success": True, "message": "Report updated successfully"}), 200
        else:
            logger.error(f"Failed to update report {report_id}")
            return jsonify({"error": "Failed to update report"}), 500
            
    except Exception as e:
        logger.exception(f"Error updating report {report_id}: {str(e)}")
        error_details = str(e) if app.debug else "Internal server error"
        return jsonify({"error": "Failed to update report", "details": error_details}), 500


@app.route("/api/user/reports/<int:report_id>", methods=["DELETE"])
@jwt_required()
def delete_user_report(report_id):
    """Delete a crime report submitted by the current user."""
    try:
        username = get_jwt_identity()
        
        if not username:
            logger.error("No username found in JWT token")
            return jsonify({"error": "User not authenticated"}), 401
            
        # Check if report exists and belongs to user
        report = DB.get_report_by_id(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
            
        if report["username"] != username and get_jwt().get("role") != ADMIN_ROLE:
            return jsonify({"error": "Unauthorized to delete this report"}), 403
            
        # Delete the report
        success = DB.delete_crime(report_id)
        
        if success:
            logger.info(f"Report {report_id} deleted successfully by {username}")
            return jsonify({"success": True, "message": "Report deleted successfully"}), 200
        else:
            logger.error(f"Failed to delete report {report_id}")
            return jsonify({"error": "Failed to delete report"}), 500
            
    except Exception as e:
        logger.exception(f"Error deleting report {report_id}: {str(e)}")
        error_details = str(e) if app.debug else "Internal server error"
        return jsonify({"error": "Failed to delete report", "details": error_details}), 500


# Admin crime report routes
@app.route("/api/admin/crime-reports/<int:report_id>", methods=["PUT"])
@jwt_required()
def update_admin_crime_report(report_id):
    """Update a crime report (admin only)."""
    try:
        if get_jwt().get("role") != ADMIN_ROLE:
            logger.warning("Unauthorized access attempt to update crime report")
            return jsonify({"error": "Unauthorized"}), 403
            
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        success = DB.update_crime(
            report_id=report_id,
            category=data.get("category"),
            description=data.get("description"),
            status=data.get("status"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude")
        )
        
        if success:
            logger.info(f"Admin updated report {report_id}")
            return jsonify({"success": True, "message": "Report updated successfully"}), 200
        else:
            logger.error(f"Admin failed to update report {report_id}")
            return jsonify({"error": "Failed to update report"}), 500
            
    except Exception as e:
        logger.exception(f"Admin error updating report {report_id}: {str(e)}")
        error_details = str(e) if app.debug else "Internal server error"
        return jsonify({"error": "Failed to update report", "details": error_details}), 500


@app.route("/api/admin/crime-reports/<int:report_id>", methods=["DELETE"])
@jwt_required()
def delete_admin_crime_report(report_id):
    """Delete a crime report (admin only)."""
    try:
        if get_jwt().get("role") != ADMIN_ROLE:
            logger.warning("Unauthorized access attempt to delete crime report")
            return jsonify({"error": "Unauthorized"}), 403
            
        success = DB.delete_crime(report_id)
        
        if success:
            logger.info(f"Admin deleted report {report_id}")
            return jsonify({"success": True, "message": "Report deleted successfully"}), 200
        else:
            logger.error(f"Admin failed to delete report {report_id}")
            return jsonify({"error": "Failed to delete report"}), 500
            
    except Exception as e:
        logger.exception(f"Admin error deleting report {report_id}: {str(e)}")
        error_details = str(e) if app.debug else "Internal server error"
        return jsonify({"error": "Failed to delete report", "details": error_details}), 500


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
    """Get the latest crime reports with proper date handling."""
    try:
        crimes = []
        for crime in DB.get_latest_crimes(limit=5):
            # Parse the date whether it comes as string or datetime
            crime_date = crime["date"]
            if isinstance(crime_date, str):
                try:
                    # Try parsing as MySQL datetime format
                    crime_date = datetime.strptime(crime_date, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    # Fallback to current time if parsing fails
                    crime_date = datetime.now()

            crimes.append(
                {
                    "category": crime["category"],
                    "location": reverse_geocode(crime["latitude"], crime["longitude"]),
                    "timestamp": crime_date.strftime("%Y-%m-%d %I:%M %p"),
                }
            )
        logger.info("Latest crimes retrieved successfully")
        return jsonify({"crimes": crimes}), 200
    except Exception as e:
        logger.error(f"Latest crimes retrieval error: {str(e)}", exc_info=True)
        return (
            jsonify({"error": "Failed to fetch latest crimes", "details": str(e)}),
            500,
        )


@app.route("/api/crime-stats", methods=["GET"])
def get_crime_stats():
    try:
        # Correct path to static/data/heatmap_data.json
        json_path = os.path.join(
            os.path.dirname(__file__), "static", "data", "heatmap_data.json"
        )

        with open(json_path, "r") as file:
            raw_data = json.load(file)

        # Aggregate total counts by crime type
        stats = defaultdict(int)
        for entry in raw_data:
            crime_type = entry.get("crime_type")
            count = entry.get("count", 0)
            stats[crime_type] += count

        # Format for charting
        chart_data = [{"category": k, "count": v} for k, v in stats.items()]
        return jsonify(chart_data)

    except Exception as e:
        logger.error(f"Error reading or processing file: {e}")
        return jsonify({"error": "Failed to load crime stats"}), 500


@app.route("/api/admin/alerts/<int:alert_id>", methods=["PUT"])
@jwt_required()
def update_alert(alert_id):
    """Update an existing alert (admin only)."""
    try:
        # Verify admin role
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Admin privileges required"}), 403

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Update alert with mapped fields
        alert_data = {
            "username": data.get("username"),
            "type": data.get("type"),
            "title": data.get("title"),
            "message": data.get("message"),
            "severity": data.get("severity"),
        }

        if DB.update_alert(alert_id, alert_data):
            logger.info(f"Alert {alert_id} updated successfully")
            return jsonify({"success": True, "message": "Alert updated successfully"}), 200
        else:
            logger.error(f"Failed to update alert {alert_id}")
            return jsonify({"error": "Failed to update alert"}), 500

    except Exception as e:
        logger.error(f"Alert update error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/admin/alerts/<int:alert_id>", methods=["DELETE"])
@jwt_required()
def delete_alert(alert_id):
    """Delete an alert (admin only)."""
    try:
        # Verify admin role
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Admin privileges required"}), 403

        if DB.delete_alert(alert_id):
            logger.info(f"Alert {alert_id} deleted successfully")
            return jsonify({"success": True, "message": "Alert deleted successfully"}), 200
        else:
            logger.error(f"Failed to delete alert {alert_id}")
            return jsonify({"error": "Failed to delete alert"}), 500

    except Exception as e:
        logger.error(f"Alert deletion error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/user/profile", methods=["GET"])
@jwt_required()
def get_user_profile():
    """Get user profile data."""
    try:
        username = get_jwt_identity()
        profile = DB.get_user_profile(username)
        return jsonify({"profile": profile}), 200
    except Exception as e:
        logger.error(f"User profile retrieval error: {str(e)}")
        return jsonify({"error": "Failed to fetch user profile", "details": str(e)}), 500


@app.route("/api/user/preferences", methods=["PUT"])
@jwt_required()
def update_user_preferences():
    """Update user preferences."""
    try:
        username = get_jwt_identity()
        # Get preferences from request
        preferences = request.get_json()
        
        if DB.update_user_preferences(username, preferences):
            logger.info(f"Preferences updated successfully for user {username}")
            return jsonify({"success": True, "message": "Preferences updated successfully"}), 200
        else:
            logger.error(f"Failed to update preferences for user {username}")
            return jsonify({"error": "Failed to update preferences"}), 500
            
    except Exception as e:
        logger.error(f"Preferences update error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    logger.info("Starting Crime Reporting API")
    app.run(port=5000, debug=True)
