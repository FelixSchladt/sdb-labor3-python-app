import os
import pytest
from main import *



def test_login_wrong_credentials():
    db = UserDB()
    user = User(db)
    user.username = "test"
    user.pwd_hash = User.hash_pwd("falsch", "salt")
    assert db.authenticate(user.username, user.pwd_hash) == False

def test_login_bad_pwd(): 
    db = UserDB()
    user = User(db)
    user.username = "test"
    user.pwd_hash = User.hash_pwd("falsch", "salt")
    assert db.authenticate(user.username, user.pwd_hash) == False

def test_get_salt():
    db = UserDB()
    assert db.get_salt("test")

def test_login_psd_of_other_user():
    db = UserDB()
    user = User(db)
    user.username = "test"
    user.pwd_hash = User.hash_pwd("test2", db.get_salt("test"))
    assert db.authenticate(user.username, user.pwd_hash) == False
    

def test_valid_login():
    db = UserDB()
    user = User(db)
    user.username = "test"
    user.pwd_hash = User.hash_pwd("test", db.get_salt("test"))
    assert db.authenticate(user.username, user.pwd_hash)

def test_create_user():
    db = UserDB()
    user = User(db)
    user.username = "test3"
    if db.user_exists(user.username):
        return
    salt = os.urandom(32).hex()
    user.pwd_hash = User.hash_pwd("test3", salt)
    db.create_user(user.username, user.pwd_hash, salt)
    assert db.user_exists(user.username)
    
def test_change_psd():
    db = UserDB()
    user = User(db)
    user.username = "test"
    salt = db.get_salt(user.username)
    user.pwd_hash = User.hash_pwd("test", salt)
    new_pwd_hash = User.hash_pwd("testtest", salt)
    db.change_password(user, new_pwd_hash)
    old_pwd_hash = user.pwd_hash
    user.pwd_hash = new_pwd_hash
    assert db.authenticate(user.username, new_pwd_hash)
    db.change_password(user, old_pwd_hash)
    user.pwd_hash = old_pwd_hash
    assert db.authenticate(user.username, user.pwd_hash)
    
    
