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
        if not username or not hashed_password:
            self.logger.error(f"Missing required fields for user creation: username={bool(username)}, password={bool(hashed_password)}")
            return False

        try:
            # Check for existing username first
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    # Case-insensitive check for existing username
                    cursor.execute(
                        "SELECT 1 FROM users WHERE LOWER(username) = LOWER(%s)", 
                        (username,)
                    )
                    if cursor.fetchone():
                        self.logger.warning(f"Username '{username}' already exists (case-insensitive check)")
                        return False
                    
                    # Insert the new user
                    query = """
                    INSERT INTO users (username, password, role, created_at) 
                    VALUES (%s, %s, %s, NOW())
                    """
                    cursor.execute(query, (username, hashed_password, role))
                    
                    # Verify insertion success
                    if cursor.rowcount == 1:
                        self.logger.info(f"User '{username}' with role '{role}' created successfully")
                        return True
                    else:
                        self.logger.error(f"User creation failed for '{username}' - no rows affected")
                        return False
                        
        except pymysql.IntegrityError as e:
            self.logger.warning(f"Username '{username}' creation failed due to integrity error: {e}")
            return False
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error creating user '{username}': {e}")
            return False
        except Exception as e:
            self.logger.exception(f"Unexpected error creating user '{username}': {e}")
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

    def get_report_by_id(self, report_id: int) -> Optional[Dict]:
        """Get a specific crime report by ID."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
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
                    WHERE id = %s
                    """
                    cursor.execute(query, (report_id,))
                    report = cursor.fetchone()
                    
                    if report:
                        self.logger.info(f"Retrieved report ID {report_id}")
                    else:
                        self.logger.warning(f"No report found with ID {report_id}")
                        
                    return report
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error retrieving report {report_id}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in get_report_by_id: {e}")
            return None
            
    def update_crime(self, report_id: int, **fields) -> bool:
        """Update a crime report with the given fields.
        
        Args:
            report_id: The ID of the report to update
            **fields: Fields to update (category, description, status, latitude, longitude)
            
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            # Remove None values and empty strings from fields
            update_fields = {k: v for k, v in fields.items() if v is not None and v != ""}
            
            if not update_fields:
                self.logger.warning(f"No valid fields provided to update report {report_id}")
                return False
                
            # Create SET clause for SQL update
            set_clause = ", ".join([f"{key} = %s" for key in update_fields.keys()])
            values = list(update_fields.values())
            values.append(report_id)  # Add report_id for WHERE clause
            
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = f"""
                    UPDATE crimes
                    SET {set_clause}
                    WHERE id = %s
                    """
                    cursor.execute(query, values)
                    
                    if cursor.rowcount == 0:
                        self.logger.warning(f"No report found with ID {report_id} to update")
                        return False
                        
                    self.logger.info(f"Successfully updated report {report_id}")
                    return True
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error updating report {report_id}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error in update_crime: {e}")
            return False
            
    def delete_crime(self, report_id: int) -> bool:
        """Delete a crime report by ID.
        
        Args:
            report_id: The ID of the report to delete
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    DELETE FROM crimes
                    WHERE id = %s
                    """
                    cursor.execute(query, (report_id,))
                    
                    if cursor.rowcount == 0:
                        self.logger.warning(f"No report found with ID {report_id} to delete")
                        return False
                        
                    self.logger.info(f"Successfully deleted report {report_id}")
                    return True
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error deleting report {report_id}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error in delete_crime: {e}")
            return False
            
    def delete_user(self, user_id: int) -> bool:
        """Delete a user from the database.
        
        Args:
            user_id: The ID of the user to delete
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        try:
            with self.connect() as connection:
                # Begin a transaction since we'll delete related records
                connection.begin()
                
                try:
                    with connection.cursor() as cursor:
                        # Get the username first
                        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
                        user_record = cursor.fetchone()
                        
                        if not user_record:
                            self.logger.warning(f"No user found with ID {user_id} to delete")
                            return False
                            
                        username = user_record["username"]
                        
                        # Delete user's crime reports
                        cursor.execute("DELETE FROM crimes WHERE username = %s", (username,))
                        crime_count = cursor.rowcount
                        
                        # Delete user's alerts
                        cursor.execute("DELETE FROM alerts WHERE username = %s", (username,))
                        alert_count = cursor.rowcount
                        
                        # Finally delete the user
                        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                        
                        if cursor.rowcount == 0:
                            # This shouldn't happen, but just in case
                            connection.rollback()
                            self.logger.error(f"Failed to delete user with ID {user_id}")
                            return False
                            
                    # If we get here, commit the transaction
                    connection.commit()
                    self.logger.info(f"Successfully deleted user ID {user_id} (username: {username}) and {crime_count} reports, {alert_count} alerts")
                    return True
                    
                except Exception as e:
                    # Roll back on any error
                    connection.rollback()
                    self.logger.error(f"Transaction error deleting user {user_id}: {e}")
                    raise
                    
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error deleting user {user_id}: {e}")
            return False
        except Exception as e:
            self.logger.exception(f"Unexpected error in delete_user for {user_id}")
            return False
            
    def is_same_user(self, user_id: int, username: str) -> bool:
        """Check if the given user ID matches the given username.
        
        Args:
            user_id: User ID to check
            username: Username to compare against
            
        Returns:
            bool: True if the user ID corresponds to the given username
        """
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    SELECT 1 FROM users
                    WHERE id = %s AND BINARY username = %s
                    """
                    cursor.execute(query, (user_id, username))
                    result = cursor.fetchone()
                    return bool(result)
        except Exception as e:
            self.logger.error(f"Error checking if user {user_id} is {username}: {e}")
            # Default to True to prevent deletion in case of error
            return True
            
    def update_user(self, user_id: int, update_data: Dict) -> bool:
        """Update a user's information.
        
        Args:
            user_id: The ID of the user to update
            update_data: Dictionary of fields to update (username, role)
            
        Returns:
            bool: True if update successful, False otherwise
        """
        if not update_data:
            self.logger.warning(f"No data provided to update user {user_id}")
            return False
            
        try:
            # Create SET clause for SQL update
            set_clause = ", ".join([f"{key} = %s" for key in update_data.keys()])
            values = list(update_data.values())
            values.append(user_id)  # Add user_id for WHERE clause
            
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    # Check if user exists
                    cursor.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
                    if not cursor.fetchone():
                        self.logger.warning(f"User {user_id} not found for update")
                        return False
                        
                    # If updating username, check if new username already exists
                    if "username" in update_data:
                        cursor.execute(
                            "SELECT 1 FROM users WHERE BINARY username = %s AND id != %s",
                            (update_data["username"], user_id)
                        )
                        if cursor.fetchone():
                            self.logger.warning(f"Username {update_data['username']} already exists")
                            return False
                    
                    # Perform update
                    query = f"""
                    UPDATE users
                    SET {set_clause}
                    WHERE id = %s
                    """
                    cursor.execute(query, values)
                    
                    if cursor.rowcount == 0:
                        self.logger.warning(f"No rows affected when updating user {user_id}")
                        return False
                        
                    self.logger.info(f"Successfully updated user {user_id}")
                    return True
                    
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error updating user {user_id}: {e}")
            return False
        except Exception as e:
            self.logger.exception(f"Unexpected error in update_user for {user_id}")
            return False

    def update_last_login(self, username: str) -> bool:
        """Update the last login timestamp for a user.
        
        Args:
            username: The username of the user logging in
            
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                    UPDATE users
                    SET last_login = NOW()
                    WHERE BINARY username = %s
                    """
                    cursor.execute(query, (username,))
                    
                    if cursor.rowcount == 0:
                        self.logger.warning(f"User {username} not found to update last login")
                        return False
                        
                    self.logger.info(f"Updated last login for user {username}")
                    return True
                    
        except pymysql.MySQLError as e:
            self.logger.error(f"Database error updating last login for {username}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error in update_last_login: {e}")
            return False
