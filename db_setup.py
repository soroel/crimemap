import pymysql
import dbconfig

try:
    # Establish connection
    connection = pymysql.connect(
        host="localhost",
        user=dbconfig.db_user,
        passwd=dbconfig.db_password,
        charset="utf8mb4",
        autocommit=True,  # Ensures queries execute immediately
    )

    with connection.cursor() as cursor:
        # Create database if not exists
        cursor.execute("CREATE DATABASE IF NOT EXISTS crimemap")

        # Select the database
        cursor.execute("USE crimemap")

        # Create crimes table if it doesn't exist
        sql = """
        CREATE TABLE IF NOT EXISTS crimes (
            id INT NOT NULL AUTO_INCREMENT,
            latitude FLOAT(10,6),
            longitude FLOAT(10,6),
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            category VARCHAR(50) NOT NULL,
            description VARCHAR(1000),
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        )
        """
        cursor.execute(sql)
        print("✅ Database and table setup complete.")

except pymysql.MySQLError as e:
    print(f"❌ MySQL Error: {e}")
except Exception as e:
    print(f"❌ Unexpected Error: {e}")
finally:
    connection.close()
