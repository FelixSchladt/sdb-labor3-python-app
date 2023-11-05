# Module Imports
import mariadb
import sys

# Connect to MariaDB Platform

try: con = mariadb.connect( 

    user="app_usrdb", 

    password="secret", 
    
    host="localhost",

    unix_socket="/run/mysqld/mysqld.sock",

    database="usrdb", 

)

except mariadb.Error as ex: 

    print(f"An error occurred while connecting to MariaDB: {ex}") 

    sys.exit(1) 


# Get Cursor 

cur = con.cursor()
statement = "SELECT * FROM user"
cur.execute(statement)
print(cur.fetchall())
