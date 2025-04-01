import logging
import pymysql
import dbconfig
import requests
from datetime import datetime
from typing import Optional, Dict, Union, List

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class DBHelper:
    def __init__(self, database="crimemap"):
        self.database = database
        self.logger = logging.getLogger(f"{__name__}.DBHelper")

    def connect(self):
        """Connects to the MySQL database with retry logic."""
        try:
            return pymysql.connect(
                host="localhost",
                user=dbconfig.db_user,
                passwd=dbconfig.db_password,
                db=self.database,
                autocommit=True,
                cursorclass=pymysql.cursors.DictCursor,
                charset="utf8mb4",
                connect_timeout=5,
            )
        except pymysql.MySQLError as e:
            self.logger.error(f"Database connection failed: {e}")
            raise ConnectionError("Could not connect to database") from e

    def create_user(self, username, hashed_password, role="user"):
        """Creates a new user with additional validation."""
        if not all([username, hashed_password]):
            self.logger.error("Missing required fields for user creation")
            return False

        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    INSERT INTO users (username, password, role) 
                    VALUES (%s, %s, %s)
                    """
                    cursor.execute(query, (username, hashed_password, role))
                self.logger.info(f"User {username} created successfully")
                return True
        except pymysql.IntegrityError:
            self.logger.warning(f"Username {username} already exists")
            return False
        except pymysql.MySQLError as e:
            self.logger.error(f"Error creating user {username}: {e}")
            return False

    def get_user(self, username):
        """Fetch user details by username with case sensitivity check."""
        if not username:
            self.logger.error("Empty username provided")
            return None

        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    SELECT username, password, role 
                    FROM users 
                    WHERE BINARY username = %s
                    """
                    cursor.execute(query, (username,))
                    user = cursor.fetchone()

                    if user:
                        self.logger.debug(f"Retrieved user {username}")
                    else:
                        self.logger.debug(f"User {username} not found")
                    return user
        except pymysql.MySQLError as e:
            self.logger.error(f"Error fetching user {username}: {e}")
            return None

    def get_reports_by_user(self, username):
        """Fetch reports with complete error handling and validation."""
        if not username or not isinstance(username, str):
            self.logger.error(f"Invalid username format: {type(username)}")
            return []

        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    # Verify user exists first
                    cursor.execute(
                        "SELECT 1 FROM users WHERE BINARY username = %s LIMIT 1",
                        (username,),
                    )
                    if not cursor.fetchone():
                        self.logger.warning(f"User {username} not found")
                        return []

                    # Get reports with proper field selection
                    query = """
                    SELECT 
                        id, 
                        category, 
                        DATE_FORMAT(date, '%%Y-%%m-%%d %%H:%%i:%%s') as date,
                        latitude,
                        longitude,
                        description,
                        status,
                        username
                    FROM crimes 
                    WHERE BINARY username = %s
                    ORDER BY date DESC
                    """
                    cursor.execute(query, (username,))
                    reports = cursor.fetchall()

                    # Validate and clean data
                    valid_reports = []
                    for report in reports:
                        try:
                            if report.get("date"):
                                datetime.strptime(report["date"], "%Y-%m-%d %H:%M:%S")
                            valid_reports.append(report)
                        except ValueError as e:
                            self.logger.error(f"Invalid report data: {e} - {report}")

                    self.logger.info(
                        f"Retrieved {len(valid_reports)} reports for {username}"
                    )
                    return valid_reports

        except pymysql.MySQLError as e:
            self.logger.exception(f"Database error fetching reports for {username}")
            return []
        except Exception as e:
            self.logger.exception("Unexpected error in get_reports_by_user")
            return []

    def get_alerts_for_user(self, username: str) -> List[Dict]:
        """Fetch alerts for a specific user with complete debugging"""
        try:
            self.logger.debug(f"Fetching alerts for {username}")

            with self.connect() as connection:
                with connection.cursor() as cursor:
                    # Get alerts with all available fields
                    query = """
                    SELECT 
                        id,
                        crime_category as type,
                        title,
                        description as message,
                        severity,
                        active as is_active,
                        created_at,
                        username
                    FROM alerts 
                    WHERE username = %s OR username = 'all'
                    AND active = 1
                    ORDER BY created_at DESC
                    LIMIT 50
                    """
                    cursor.execute(query, (username,))
                    alerts = cursor.fetchall()
                    self.logger.debug(f"Raw alerts from DB: {alerts}")

                    # Format response
                    formatted_alerts = []
                    for alert in alerts:
                        try:
                            formatted = {
                                "id": alert["id"],
                                "type": alert.get("type", "crime"),
                                "title": alert.get("title", "Alert"),
                                "message": alert.get("message", ""),
                                "severity": alert.get("severity", "medium"),
                                "created_at": (
                                    alert["created_at"].isoformat()
                                    if alert.get("created_at")
                                    else datetime.now().isoformat()
                                ),
                                "is_active": bool(alert.get("is_active", True)),
                            }
                            formatted_alerts.append(formatted)
                        except Exception as e:
                            self.logger.error(
                                f"Error formatting alert {alert}: {str(e)}"
                            )

                    self.logger.info(
                        f"Formatted {len(formatted_alerts)} alerts for {username}"
                    )
                    return formatted_alerts

        except Exception as e:
            self.logger.error(f"Error in get_alerts_for_user: {str(e)}", exc_info=True)
            return []

    def reverse_geocode(self, lat: float, lon: float) -> str:
        """
        Convert coordinates to address using external service
        Implement this method based on your geocoding service
        """
        # Implementation would go here
        return f"{lat:.6f}, {lon:.6f}"  # Default return coordinates if no geocoding

    def create_alert(self, alert_data: Dict) -> bool:
        """Create a new alert in the database with proper field mapping"""
        try:
            # Field mapping between API and database
            field_mapping = {
                "username": "username",
                "type": "crime_category",
                "title": "title",
                "message": "description",
                "severity": "severity",
            }

            # Validate all required fields exist in input
            required_fields = ["username", "type", "title", "message", "severity"]
            missing_fields = [
                field for field in required_fields if field not in alert_data
            ]
            if missing_fields:
                self.logger.error(
                    f"Missing required fields in alert data: {missing_fields}"
                )
                return False

            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    INSERT INTO alerts (
                        username,
                        crime_category,
                        title,
                        description,
                        severity,
                        active,
                        created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    """
                    cursor.execute(
                        query,
                        (
                            alert_data["username"],
                            alert_data["type"],
                            alert_data["title"],
                            alert_data["message"],
                            alert_data["severity"],
                            1,  # Set active to true by default
                        ),
                    )
                    self.logger.info(
                        f"Alert created successfully for {alert_data['username']}"
                    )
                    return True
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error creating alert: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error in create_alert: {str(e)}")
            return False

    def mark_alert_read(self, alert_id: str, username: str) -> bool:
        """Mark an alert as read by a specific user"""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    UPDATE alerts 
                    SET is_read = TRUE 
                    WHERE id = %s AND username = %s
                    """
                    cursor.execute(query, (alert_id, username))
                    if cursor.rowcount == 0:
                        self.logger.warning(f"No alert {alert_id} found for {username}")
                        return False
                    self.logger.info(f"Marked alert {alert_id} as read for {username}")
                    return True
        except pymysql.MySQLError as e:
            self.logger.error(f"Error marking alert read: {str(e)}")
            return False

    def add_crime(
        self, category, date, latitude, longitude, description, username="Anonymous"
    ):
        """Insert a new crime report with data validation."""
        try:
            # Validate coordinates
            float(latitude)
            float(longitude)
        except ValueError:
            self.logger.error(f"Invalid coordinates: {latitude}, {longitude}")
            return False

        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    INSERT INTO crimes (
                        category, 
                        date, 
                        latitude, 
                        longitude, 
                        description, 
                        username
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(
                        query,
                        (category, date, latitude, longitude, description, username),
                    )
                self.logger.info(
                    f"New crime reported by {username}: {category} at {latitude},{longitude}"
                )
                return True
        except pymysql.MySQLError as e:
            self.logger.error(f"Error adding crime report: {e}")
            return False

    def get_latest_crimes(self, limit: int = 5) -> List[Dict]:
        """Fetch the latest crime reports with proper date handling"""

        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    SELECT 
                        id,
                        category,
                        date,
                        latitude,
                        longitude,
                        description,
                        username
                    FROM crimes
                    ORDER BY date DESC
                    LIMIT %s
                    """
                    cursor.execute(query, (limit,))
                    crimes = cursor.fetchall()

                    # Process and format the results
                    formatted_crimes = []
                    for crime in crimes:
                        # Ensure date is either datetime object or properly parsed
                        crime_date = crime["date"]
                        if isinstance(crime_date, str):
                            try:
                                crime_date = datetime.strptime(
                                    crime_date, "%Y-%m-%d %H:%M:%S"
                                )
                            except ValueError:
                                crime_date = datetime.now()  # fallback to current time

                        formatted_crimes.append(
                            {
                                "id": crime["id"],
                                "category": crime["category"],
                                "date": crime_date.strftime("%Y-%m-%d %H:%M:%S"),
                                "latitude": crime["latitude"],
                                "longitude": crime["longitude"],
                                "description": crime.get("description", ""),
                                "username": crime.get("username", "Anonymous"),
                                "location": self.reverse_geocode(
                                    crime["latitude"], crime["longitude"]
                                ),
                            }
                        )

                    return formatted_crimes

        except Exception as e:
            self.logger.error(f"Error in get_latest_crimes: {str(e)}", exc_info=True)
            return []

    def get_all_users(self) -> List[Dict]:
        """Fetch all users from the database (admin only)."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    SELECT 
                        id,
                        username,
                        role,
                        DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') as created_at,
                        last_login
                    FROM users
                    ORDER BY created_at DESC
                    """
                    cursor.execute(query)
                    users = cursor.fetchall()

                    # Sanitize sensitive data
                    for user in users:
                        if "password" in user:
                            del user["password"]

                    self.logger.info(f"Retrieved {len(users)} users")
                    return users
        except pymysql.MySQLError as e:
            self.logger.error(f"Error fetching all users: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error in get_all_users: {e}")
            return []

    def get_all_crimes(self) -> List[Dict]:
        """Fetch all crime reports with detailed information."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    SELECT 
                        c.id,
                        c.category,
                        DATE_FORMAT(c.date, '%%Y-%%m-%%d %%H:%%i:%%s') as date,
                        c.latitude,
                        c.longitude,
                        c.description,
                        c.status,
                        c.username,
                        u.role as reporter_role
                    FROM crimes c
                    LEFT JOIN users u ON c.username = u.username
                    ORDER BY c.date DESC
                    """
                    cursor.execute(query)
                    crimes = cursor.fetchall()

                    # Add location information
                    for crime in crimes:
                        crime["location"] = self.reverse_geocode(
                            crime["latitude"], crime["longitude"]
                        )

                    self.logger.info(f"Retrieved {len(crimes)} crime reports")
                    return crimes
        except pymysql.MySQLError as e:
            self.logger.error(f"Error fetching all crimes: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error in get_all_crimes: {e}")
            return []
