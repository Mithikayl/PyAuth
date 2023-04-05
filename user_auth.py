import argon2 # main hashing lib
from sqlalchemy import create_engine, Column, Integer, String # lovely db 
from sqlalchemy.orm import sessionmaker # lovely db 
from sqlalchemy.ext.declarative import declarative_base # lovely db 
import re # validate pw
import getpass # we are using a CLI so getpass but not necessary otherwise

# script to handle user auth + hashing pw

Base = declarative_base()
DATABASE_NAME = 'details.db'
password_hasher = argon2.PasswordHasher()


class User(Base): # boilerplate to easily access user data
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String)
    password = Column(String)

    def __repr__(self):
        return f"<User(username='{self.username}', password='{self.password}')>"
    
    def change_password(self, new_password):
        self.password = new_password

def main():
    engine = create_engine(f'sqlite:///{DATABASE_NAME}')
    Base.metadata.create_all(engine)
    account_manager(engine)

def account_manager(engine):
    existing_account = input("Do you have an existing account? (Y/N)\n")
    Session = sessionmaker(bind=engine)
    session = Session()
    if existing_account.upper() == "Y":
        login(session)
    elif existing_account.upper() == "N":
        register(session)
    else:
        exit("Invalid Input")

def login(session):
    while True:
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")
        user = session.query(User).filter_by(username=username).first()
        if user is None:
            print("Invalid username or password. The user may not exist.")
        else:
            hash = get_password_hash_for_user(username, password, session)
            try:
                password_hasher.verify(hash, password)
                if password_hasher.check_needs_rehash(hash):
                    set_hash_for_user(username, hash, session)
            except argon2.exceptions.VerifyMismatchError:
                print("Invalid username or password. The user may not exist.")
            else:
                print("Login successful.")
                print("Welcome back, %s." % username)
                break
                

def register(session):
    while True:
        try:
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            if username == password:
                raise ValueError
            # if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', username):
                # raise ValueError
                # uncomment if you want email checking
            if not re.match(r'(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$', password):
                raise ValueError
        except ValueError:
            print("Invalid password. Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character (!@#$%^&*) and cannot be your username.")
        else:
            user = session.query(User).filter_by(username=username).first()
            if user:
                print("Username already exists. Please choose a different username.")
            else:
                break
    hashed_password = password_hasher.hash(password)
    user = User(username=username, password=hashed_password)
    session.add(user)
    session.commit()
    print("Registration successful.")


def get_password_hash_for_user(username, session):
    user = session.query(User).filter_by(username=username).first()
    return user.password

def set_hash_for_user(username, hash, session):
    user = session.query(User).filter_by(username=username).first()
    user.set_password(hash)

if __name__ == '__main__':
    main()
