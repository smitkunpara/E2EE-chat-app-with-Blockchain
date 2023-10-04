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
    query = """create database UROP
    use UROP
    create table users(
        username varchar(255) primary key,
        password varchar(255),
        pub_key varchar(2048)
    )

    create table messages(
        id int auto_increment primary key,
        sender varchar(255),
        recipient varchar(255),
        message varchar(2048)
    )
    
            """
    cursor.execute(query)
    db.commit()
    """
    query = "SELECT * FROM users"
    cursor.execute(query)
    rows = cursor.fetchall()
    for row in rows:
        print(row)
    """
    
if __name__ == "__main__":
    print_all_data()

    # Close the database connection when done
    db.close()
