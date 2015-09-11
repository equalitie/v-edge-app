"""
Everything we want available to the 'admin' app module
"""

import os
from flask import Flask
from flask_login import LoginManager
import config.check_config as check
from lib.models.User import User
from lib.models.MailSender import MailSender
from lib.models.Redminer import Redminer
from flask_mail import Mail

from views.all import admin_bp

static_paths = [os.getcwd(), '/lib/static']
app = Flask(__name__, instance_relative_config=True, static_folder="".join(static_paths))
app = check.check_config(app)

app.register_blueprint(admin_bp)

login_manager = LoginManager()
login_manager.init_app(app)

app.redminer = Redminer(
    app.config["REDMINE_URL"],
    app.config["REDMINE_API_KEY"],
    app.config["SERVER_ENV"],
    app.config["SUPPORT_SUBJECT_VALUES"]
)


mail = Mail(app)
mail_sender = MailSender(mail, app)
app.mail_sender = mail_sender


# required for login manager
@login_manager.user_loader
def load_user(user_id):
    return User({"id": user_id})