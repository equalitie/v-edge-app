from flask import current_app
from flask_login import UserMixin


class User(UserMixin):

    id = None
    email = None
    password_hash = None
    password_salt = None
    date_joined = None
    status = None
    password_reset = None
    reset_link = None

    def __init__(self, data=None):
        """
        Fill out attributes on init
        """
        if data is not None:
            for k, v in data.iteritems():
                setattr(self, k, v)

    def create(self):
        """
        Signup a new user
        """
        return current_app.db.create_user(self)

    def is_authenticated(self):
        """
        Needed for flask-login
        """
        if self.id is not None:
            return True
        return False

    def save(self):
        """
        Update the user object
        """
        return current_app.db.save_user(self)