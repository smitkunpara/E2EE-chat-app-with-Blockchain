import mysql.connector

# Establish a connection to your MySQL database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="mydatabase"
)

cursor = db.cursor()

def print_all_data():
    # Execute a SELECT query to fetch all data from a table (e.g., 'users' table)
    query = "SELECT * FROM users"  # Replace 'your_table_name' with the actual table name

    cursor.execute(query)

    # Fetch all rows from the result set
    rows = cursor.fetchall()

    # Print the retrieved data
    for row in rows:
        print(row)

if __name__ == "__main__":
    print_all_data()

    # Close the database connection when done
    db.close()
