import pymysql
import dbconfig


class DBHelper:
    def __init__(self, database="crimemap"):
        self.database = database

    def connect(self):
        """Connects to the MySQL database."""
        return pymysql.connect(
            host="localhost",
            user=dbconfig.db_user,
            passwd=dbconfig.db_password,
            db=self.database,
            autocommit=True,  # Enable autocommit
            cursorclass=pymysql.cursors.DictCursor,  # Return results as dictionaries
        )

    def create_user(self, username, hashed_password, role="user"):
        """Creates a new user."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)"
                    cursor.execute(query, (username, hashed_password, role))
                return True
        except pymysql.IntegrityError:
            return False  # Username already exists
        except pymysql.MySQLError as e:
            print(f"🔥 DB Error: {e}")
            return False

    def get_user(self, username):
        """Fetch user details by username."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = "SELECT username, password, role FROM users WHERE username = %s;"
                    cursor.execute(query, (username,))
                    return cursor.fetchone()  # Returns None if user doesn't exist
        except pymysql.MySQLError as e:
            print(f"🔥 DB Error: {e}")
            return None

    def get_all_inputs(self):
        """Fetch all crime descriptions."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = "SELECT description FROM crimes;"
                    cursor.execute(query)
                    return [row["description"] for row in cursor.fetchall()]
        except pymysql.MySQLError as e:
            print(f"🔥 DB Error: {e}")
            return []

    def get_latest_crimes(self, limit=5):
        """Fetch the latest crime reports."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                        SELECT category, latitude, longitude, date, description 
                        FROM crimes 
                        ORDER BY date DESC 
                        LIMIT %s;
                    """
                    cursor.execute(query, (limit,))
                    return cursor.fetchall()  # List of dicts
        except pymysql.MySQLError as e:
            print(f"🔥 DB Error: {e}")
            return []

    def get_all_crimes(self):
        """Fetch all crime reports."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = "SELECT latitude, longitude, date, category, description FROM crimes;"
                    cursor.execute(query)
                    crimes = cursor.fetchall()

                return [
                    {
                        "latitude": crime["latitude"],
                        "longitude": crime["longitude"],
                        "date": crime["date"].strftime("%Y-%m-%d"),
                        "category": crime["category"],
                        "description": crime["description"],
                    }
                    for crime in crimes
                ]
        except pymysql.MySQLError as e:
            print(f"🔥 DB Error: {e}")
            return []

    def add_crime(
        self, category, date, latitude, longitude, description, username="Anonymous"
    ):
        """Insert a new crime report with username."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = """
                        INSERT INTO crimes (category, date, latitude, longitude, description, username) 
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(
                        query,
                        (category, date, latitude, longitude, description, username),
                    )
                connection.commit()  # Ensure data is committed
            return True
        except pymysql.MySQLError as e:
            print(f"🔥 Database Error: {e}")
            return False

    def clear_all(self):
        """Delete all crime records."""
        try:
            with self.connect() as connection:
                with connection.cursor() as cursor:
                    query = "DELETE FROM crimes;"
                    cursor.execute(query)
                connection.commit()  # Ensure deletion is saved
            return True
        except pymysql.MySQLError as e:
            print(f"🔥 DB Error: {e}")
            return False
