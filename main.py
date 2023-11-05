import sys
import os
import getpass
import argparse
import mariadb
from Crypto.Hash import SHA512


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Totally Secure Authenticator",
        epilog="Copyright © 2023 Felix Schladt https://github.com/FelixSchladt"
    )

    options = parser.add_mutually_exclusive_group()

    options.add_argument(
        "-l",
        "--login",
        action="store_true",
        help="Login to your account",
        required=False
    )

    options.add_argument(
        "-n",
        "--new",
        action="store_true",
        help="Create a new account",
        required=False
    )

    parser.add_argument(
        "-c",
        "--change",
        action="store_true",
        help="Change the password after authentication",
        required=False
    )

    args = parser.parse_args()
    return args


class CLI:
    @staticmethod
    def delete_last_line():
        sys.stdout.write('\x1b[1A')
        sys.stdout.write('\x1b[2K')
        sys.stdout.flush()

    @staticmethod
    def new_password():
        password = getpass.getpass("Password: ")
        CLI.delete_last_line()
        if password == getpass.getpass("Confirm password: "):
            CLI.delete_last_line()
            return password
        print("Passwords do not match")
        sys.exit(-1)

    @staticmethod
    def enter_password():
        password = getpass.getpass("Password: ")
        CLI.delete_last_line()
        return password

    @staticmethod
    def enter_username():
        print("Username: ", end="")
        username = input().strip()
        CLI.delete_last_line()
        return username


class UserDB:
    def __init__(self):
        # Read database credentials from environment variables
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")
        db_host = os.environ.get("DB_HOST")
        db_unix_socket = os.environ.get("DB_UNIX_SOCKET")
        db_database = os.environ.get("DB_DATABASE")

        try:
            self.con = mariadb.connect(
                user=db_user,
                password=db_password,
                host=db_host,
                unix_socket=db_unix_socket,
                database=db_database,
            )
            self.cur = self.con.cursor()
        except mariadb.Error as ex:
            print(f"An error occurred while connecting to MariaDB: {ex}")
            sys.exit(-1)

    def authenticate(self, username, pwd_hash) -> bool:
        query = "SELECT username, password FROM user WHERE username = ?"
        self.cur.execute(query, (username,))
        data = self.cur.fetchall()
        if len(data) - 1:
            print("Error database corrupted, duplicate username")
            return False
        return data[0][1] == pwd_hash

    def get_salt(self, username: str):
        query = "SELECT salt FROM user WHERE username = ?"
        self.cur.execute(query, (username,))
        res = self.cur.fetchone()
        if res is None:
            return None
        return res[0]

    def user_exists(self, username: str):
        query = "SELECT username FROM user WHERE username = ?"
        self.cur.execute(query, (username,))
        return len(self.cur.fetchall()) > 0

    def create_user(self, username, pwd_hash, salt):
        if self.user_exists(username):
            print(f"Username {username} already taken")
            sys.exit(-1)
        query = "INSERT INTO user (username, password, admin, lastpasswordchange, salt, created_at) VALUES (?, ?, 0, NOW(), ?, NOW())"
        self.cur.execute(query, (username, pwd_hash, salt))
        self.con.commit()

    def change_password(self, user, new_pwd_hash):
        if not self.authenticate(user.username, user.pwd_hash):
            print("Error: User could not be authenticated")
            sys.exit(-1)
        query = "UPDATE user SET password = ? WHERE username = ?"
        self.cur.execute(query, (new_pwd_hash, user.username))
        self.con.commit()

class User:
    def __init__(self, db: UserDB):
        self.db = db
        self.username = None
        self.pwd_hash = None

    @staticmethod
    def hash_pwd(psd: str, salt: str) -> str:
        sha512_hash = SHA512.new()
        sha512_hash.update((psd + salt).encode())
        return sha512_hash.hexdigest()


    def login(self):
        username = CLI.enter_username()
        salt = self.db.get_salt(username)
        if not salt:
            print(f"Error user \"{username}\" not found")
            return False

        pwd_hash = User.hash_pwd(CLI.enter_password(), salt)
        auth = self.db.authenticate(username, pwd_hash)
        if auth:
            self.username = username
            self.pwd_hash = pwd_hash
        return auth

    def create_user(self):
        self.username = CLI.enter_username()
        if self.db.user_exists(self.username):
            print(f"Username {self.username} is already taken")
            sys.exit(-1)

        psd  = CLI.new_password()
        salt = os.urandom(32).hex()
        self.pwd_hash = User.hash_pwd(psd, salt)
        self.db.create_user(self.username, self.pwd_hash, salt)

    def change_password(self):
        new_psd = CLI.new_password()
        salt = self.db.get_salt(self.username)
        if not salt:
            print(f"Error user \"{self.username}\" not found")
            return False

        new_psd_hash = User.hash_pwd(new_psd, salt)
        self.db.change_password(self, new_psd_hash)
        self.pwd_hash = new_psd_hash
        return True


def main():
    db = UserDB()
    user = User(db)
    args = get_args()

    if args.new:
        print("Creating new useraccount")
        user.create_user()
        print("User account created")
        sys.exit(0)
    if not user.login():
        print("Invalid credentials")
        sys.exit(-1)

    print("Successfully logged in")
    if args.change:
        print("New Password")
        if not user.change_password():
            print("Failed")
            sys.exit(-1)
        print("Successfully changed password")


if __name__ == "__main__":
    main()
