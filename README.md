# PyAuth

## 🧐 About

The Python script is a user authentication system that provides a straightforward way to set up a login system for basic applications. It utilizes a MySQL database and SQLAlchemy for simple and efficient storage of user data. The password hashing functionality is implemented using [argon2](https://en.wikipedia.org/wiki/Argon2), a secure and modern hashing algorithm that ensures the passwords are stored securely in the database. The script also includes basic password and username validation using regular expressions, allowing for customizable validation rules to ensure strong password and username requirements if needed. 

Overall, this script provides an easy-to-use solution for implementing user authentication with password hashing and basic validation in Python applications. Additionally, the script can be extended with features such as account lockout to enhance security further. Overall, it is a simple and efficient solution for adding user authentication to basic applications. Note that additional security measures may be required depending on the specific use case and security requirements of the application.

## 🏁 Setup

Just run
```
pip install -r requirements.txt
```
and you should be good to go!