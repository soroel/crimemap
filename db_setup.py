import pymysql
import dbconfig

connection = pymysql.connect(host='localhost',
                             user=dbconfig.db_user,
                             passwd=dbconfig.db_password)

try:
    with connection.cursor() as cursor:
        # Create database if it doesn't exist
        sql = "CREATE DATABASE IF NOT EXISTS crimemap"
        cursor.execute(sql)

        # Create table if it doesn't exist
        sql = """CREATE TABLE IF NOT EXISTS crimemap.crimes (
                    id int NOT NULL AUTO_INCREMENT,
                    latitude FLOAT(10,6),
                    longitude FLOAT(10,6),
                    date DATETIME,
                    category VARCHAR(50),
                    description VARCHAR(1000),
                    updated_at TIMESTAMP,
                    PRIMARY KEY (id)
                 )"""
        cursor.execute(sql)

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    connection.close()
