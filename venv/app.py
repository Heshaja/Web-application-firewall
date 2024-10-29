from flask import Flask, render_template, request, redirect, url_for, abort
import mysql.connector
import re

app = Flask(__name__)

db = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Munni@06',
    'database': 'users_db'
}

# Open a new database connection for each request
db_connection = mysql.connector.connect(**db)
cursor = db_connection.cursor()

# SQL AND XSS ATTACK'S PATTERNS
sql_injection_pattern = re.compile(
    r"\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|EXEC|REVOKE|GRANT|--|OR\s+\d+=\d+|CHAR\(|SLEEP\(|BENCHMARK\()",
    re.IGNORECASE
)

xss_pattern = re.compile(
    r"(<script\b[^>]*>(.?)</script>|<[^>]+on\w+=[\"']?[^>]+>|window\.location|document\.cookie|<iframe\b[^>]*>|<img\b[^>]*onerror=|eval\(|innerHTML|alert\()",
    re.IGNORECASE
)

# FUNCTION FOR CHECKING THE INPUT
def check(input):
    if sql_injection_pattern.search(input):
        return "SQL INJECTION DETECTED"
    if xss_pattern.search(input):
        return "XSS ATTACK DETECTED"
    return None

@app.before_request
def middleware():
    for key, value in request.args.items():
        error = check(value)
        if error:
            return error

    for key, value in request.form.items():
        error = check(value)
        if error:
            return error

@app.route('/')
def main():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    name = request.form['username']
    password = request.form['password']

    # Validate the name and password
    Name_Validation = check(name)
    Password_Validation = check(password)

    if Name_Validation or Password_Validation:
        error = Name_Validation or Password_Validation
        return f"Input Validation Failed. {error}"



    # Parameterized SQL query
    query = "SELECT * FROM users WHERE username=%s AND password=%s"
    parameters = (name, password)

    
    print("*")
    print("Executing Query:", query)
    print("Parameters:", parameters)
    print("*")


    try:
        cursor.execute(query, parameters)
        user = cursor.fetchall()

        print(f'USER: {user}')

        if user:
            user_data = []
            for i in user:
                username, email, password = i
                user_data.append({'username': username, 'email': email, 'password': password})
            print(f"USER DATA: {user_data}")
            return render_template('login_success.html', user_data=user_data)
        else:
            return 'User not found'

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return 'An error occurred. Please try again later.'

    finally:
        cursor.close()
        db_connection.close()

if __name__ == '__main__':
    app.run(debug=True)
