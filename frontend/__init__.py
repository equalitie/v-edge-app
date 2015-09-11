"""
Everything we want available to the 'frontend' app module
"""

import os
from flask import Flask, request, redirect
from flask_login import LoginManager
from flask_mail import Mail
from flask_babel import Babel

import config.check_config as check
from lib.models.MailSender import MailSender
from lib.models.Redminer import Redminer
from lib.models.User import User
from views.signup import signup_bp
from views.signin import login_bp
from views.signout import logout_bp
from views.dashboard import dashboard_bp
from views.lang import lang_bp
from views.dns import dns_bp
from views.support import support_bp
from werkzeug.contrib.cache import SimpleCache


# FLASK APP
static_paths = [os.getcwd(), '/lib/static']
app = Flask(__name__, instance_relative_config=True, static_folder="".join(static_paths))
app = check.check_config(app)

# MAIL. mail_sender is a thin wrapper around the Mail instance.
mail = Mail(app)
mail_sender = MailSender(mail, app)
app.mail_sender = mail_sender

# REDMINE instance. redminer is a thin wrapper around the redmine lib.
app.redminer = Redminer(
    app.config["REDMINE_URL"],
    app.config["REDMINE_API_KEY"],
    app.config["SERVER_ENV"],
    app.config["SUPPORT_SUBJECT_VALUES"]
)

# LOCALIZED CONTENT
babel = Babel(app)

# CACHE
app.cache = SimpleCache()

# BLUEPRINTS
app.register_blueprint(signup_bp)
app.register_blueprint(login_bp)
app.register_blueprint(logout_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(lang_bp)
app.register_blueprint(dns_bp)
app.register_blueprint(support_bp)

# Login ext for session management
login_manager = LoginManager()
login_manager.init_app(app)

# flask overrides


@login_manager.user_loader
def load_user(user_id):
    """
    Required for the login manager
    """
    user_data = app.db.get_user_by_id(user_id)
    user = User(user_data)
    return user


@app.errorhandler(401)
def custom_401(error):
    """
    User trying to access protected resources
    """
    return redirect("/login")


@babel.localeselector
def get_locale():
    cookie_lang = request.cookies.get('lang')
    return cookie_lang if cookie_lang is not None else 'en'