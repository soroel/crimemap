import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash


class DBHelper:
    def __init__(
        self,
        dbname="crimemap",
        host="localhost",
        user="your_user",
        password="your_password",
    ):
        self.dbname = dbname
        try:
            self.conn = mysql.connector.connect(
                host=host, user=user, password=password, database=dbname
            )
            if self.conn.is_connected():
                print("Connected to MySQL database")
            self.create_tables()
        except Error as e:
            print(f"Error connecting to MySQL: {e}")

    def create_tables(self):
        query_users = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'user') DEFAULT 'user'
        );
        """
        query_crimes = """
        CREATE TABLE IF NOT EXISTS crimes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            category VARCHAR(255) NOT NULL,
            date DATETIME NOT NULL,
            latitude DOUBLE NOT NULL,
            longitude DOUBLE NOT NULL,
            description TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(query_users)
            cursor.execute(query_crimes)
            self.conn.commit()
            cursor.close()
        except Error as e:
            print(f"Error creating tables: {e}")

    def add_user(self, username, password, role="user"):
        hashed_pw = generate_password_hash(password)
        query = "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)"
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, (username, hashed_pw, role))
            self.conn.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error inserting user: {e}")
            return False

    def get_user(self, username):
        """Fetch user by username and return as a dictionary."""
        query = "SELECT id, username, password, role FROM users WHERE username = %s"
        cursor = self.conn.cursor()
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return {
                "id": user[0],
                "username": user[1],
                "password": user[2],
                "role": user[3],
            }
        return None
