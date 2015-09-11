import sys
import os


def check_server_env():
    if "SERVER_ENV" not in os.environ:
        print "Please make sure to set the SERVER_ENV environment variable before continuing. Value should be one of: "\
            "DEV, STAGING, PRODUCTION."
        sys.exit(1)


def check_enc_setup(app):
    if not app.config["GPGHOME"]:
        print "Please set the value of your GPG home folder in your local settings (instance/config.py)"
        sys.exit(1)

    if not os.path.isdir(app.config["GPGHOME"]):
        print "Please make sure that your GPG home folder exists."
        sys.exit(1)

    if len(os.listdir(app.config["GPGHOME"])) == 0 or not os.path.isfile(app.config["KEYFILE_LOCATION"]):
        print "Either your GPGHOME is empty, or the 'instance/keyfile.asc' file does not exist."
        print "Please go to /instance and run 'python genkeys.py' before continuing."
        sys.exit(1)

    return app


def load_settings(app):
    app.config.from_object('config.default')
    app.config.from_pyfile('config.py')

    check_server_env()
    app.config["SERVER_ENV"] = os.environ["SERVER_ENV"]

    if app.config["SERVER_ENV"] == "STAGING":
        app.config.from_object('config.staging')
    elif app.config["SERVER_ENV"] == "PRODUCTION":
        app.config.from_object('config.production')

    return app


def check_config(app):
    app = load_settings(app)
    app = check_enc_setup(app)
    return app