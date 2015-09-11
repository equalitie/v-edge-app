import gnupg

DEBUG = True
SECRET_KEY = "12345"
DB_USER = ""
DB_PASS = ""
DB_NAME = ""
DB_HOST = "localhost"
DASHBOARD_HOST = "127.0.0.1:5000"  # the dashboard host is mainly used for email links
GPGHOME = "/home/user/gpg"
KEYFILE_LOCATION = "instance/keyfile.asc"
GPG_EMAIL = "someone@email.com"
GPG = gnupg.GPG(gnupghome=GPGHOME)

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USERNAME = 'a_valid_email'
MAIL_PASSWORD = 'a_great_strong_password_like_12345'