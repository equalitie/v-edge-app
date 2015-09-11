import datetime
import os
import logging
from whois import whois
from whois.parser import PywhoisError
import requests


def timestamp_to_date_string(ts):
    """
    Convert a timestamp to a string in %Y-%m-%d %H:%M:%S format (human-readable)
    :param ts:
    :return:
    """
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def delete_file(filename):
    """
    Delete file if it exists
    :param filename:
    :return:
    """
    return os.remove(filename) if filename and os.path.exists(filename) else None


def encrypt_ssl_file(current_app, filename):
    """
    Encrypt a file from filename, assuming the gpg home is configured properly.
    :param current_app:
    :param filename:
    :return:
    """
    logging.info("Starting encryption of {}".format(filename))
    enc_filename = "{}.gpg".format(filename)
    with open(filename, 'rb') as f:
        status = current_app.config["GPG"].encrypt_file(
            f, recipients=[current_app.config["GPG_EMAIL"]], output=enc_filename
        )

    logging.info(status.ok)
    logging.info(status.status)
    logging.info(status.stderr)
    logging.info("Done.")

    return enc_filename


def check_domain(url):
    """
    Check a domain whois + make a request to see if it returns a correct status code.
    Return early if you can.
    """
    not_exists = lambda: (False, "Please check your spelling and make sure your domain exists.")
    incorrect = lambda: (False, "Please check your spelling and make sure this website is configured correctly.")

    # check whois
    try:
        w = whois(url)
        if 'status' not in w or not w.status:
            return not_exists()
    except PywhoisError:
        return not_exists()

    # make a simple GET, expect a 200
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return incorrect()
    except Exception as e:
        # turns out too many things can go wrong here, make a generic error catch
        logging.error("Error in request: {}".format(e.message))
        return incorrect()

    return True, ""
