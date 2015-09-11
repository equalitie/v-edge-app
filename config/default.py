import datetime
import os
import inspect
from flask_babel import lazy_gettext as ___

# general options

# all of these can (and in most cases should) be overridden in /config and /instance config files
# /config files are mostly for environment-dependent configs
# /instance are mostly for local development. /instance/config.py is in the .gitignore

DEBUG = False
BABEL_DEFAULT_LOCALE = "en"
SECRET_KEY = "12345"
DB_USER = ""
DB_PASS = ""
DB_NAME = "deflect"
DB_HOST = "localhost"
ADMIN_EMAIL = "The Deflect Team <outreach@deflect.ca>"
SYSOPS_EMAIL = "sysops@equalit.ie"
REDMINE_URL = "https://redmine.equalit.ie/redmine"
REDMINE_API_KEY = "8dc015ecd4a1ebd7cdfcc645f97391168bba74ff"
DASHBOARD_HOST = "http://deflect.ca"
PERMANENT_SESSION_LIFETIME = datetime.timedelta(hours=24)
UPLOAD_FOLDER = "/tmp"
APP_FOLDER = os.path.dirname(
    os.path.realpath(os.path.abspath(os.path.split(inspect.getfile(inspect.currentframe()))[0]))
)

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USERNAME = 'a_valid_email'
MAIL_PASSWORD = 'a_great_strong_password_like_12345'

# frontend specific configs
FRONTEND_HOST_IP = "127.0.0.1"
FRONTEND_PORT = 5000

# admin specific configs
ADMIN_HOST_IP = "127.0.0.1"
ADMIN_PORT = 5001
ADMIN_HOST = "{0}:{1}".format(ADMIN_HOST_IP, ADMIN_PORT)
ADMIN_USER = "d$3s53slaAPsL}sd01!s"  # override this
ADMIN_PASSWORD = "$rT*AsdOA)#ASDO$d"  # override this

# support ticket options (at the same time, redmine subjects)
SUPPORT_SUBJECT_VALUES = {
    1: ___("DNS zone file configuration issues"),
    2: ___("General support"),
    3: ___("Incident report")
}

# string values for different setup steps
SETUP_STRING_VALUES = {
    0: "USER: User has added Website to dashboard, setup not started.",
    1: "USER: Review and correct DNS zone file records",
    2: "USER: Create website administration access",
    3: "ADMIN: Deflect needs to validate configuration, buy DNS hosting and update NS info.",
    4: "USER: User needs to change their NS settings",
    5: "ADMIN: Deflect checks current NS against Deflect NS settings and confirms all is OK.",
    -1: "USER: Setup is done, redirected to stats."
}