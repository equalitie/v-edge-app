import binascii
import logging
import time
import random
import string
import re

import requests
from flask import current_app
from flask_login import current_user
import MySQLdb
import bcrypt
from models.Permission import Permission
from models.User import User
from models.Record import Record
from models.Website import Website
import lib.Utils as MiscUtils
import base64
import hashlib
from flask_babel import lazy_gettext as ___


"""
Useful functions to interface with the data layer
"""


def generate_new_user_password():
    """
    Get 8 random chars, bcrypt it with a salt and return all 3 elements.
    """
    plain_text_password = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plain_text_password, salt)
    return plain_text_password, hashed_password, salt


def update_auth_settings(website, auth_password, admin_key):
    """
    Store new website settings
    """
    website.banjax_auth_hash = base64.encodestring(hashlib.sha256(auth_password).digest()).rstrip()
    website.admin_key = admin_key

    return website


def get_single_server(hash_id):
    """
    Return a Server instance, or None if we can't find the website corresponding to the hash
    """
    server_data = current_app.db.get_server_by_hash(hash_id)
    if server_data:
        return Server(server_data)
    else:
        return None


def get_servers():
    """
    Get the servers for the currently logged in user
    """
    servers = current_app.db.get_servers()
    return [Server(x) for x in servers]


def get_current_server(servers, hash_id):
    """
    Once we have a list of all the servers, find a specific one by hash id
    """
    hash_bin = binascii.unhexlify(hash_id)
    return next((x for x in servers if x.hash_id == hash_bin), None)


def get_server_data(hash_id):
    """
    Get both the websites for the user, and a specific one at the same time. Return a tuple.
    """
    all_servers = get_servers()
    try:
        active_server = get_current_server(all_servers, hash_id)
        return all_servers, active_server
    except TypeError, e:
        logging.error(e.message)
        return None, None


def create_user(email, hashed_password, password_salt):
    """
    Create a new user
    """
    user = User({
        "email": email,
        "password_hash": hashed_password,
        "password_salt": password_salt,
        "date_joined": int(time.time()),
        "status": 0
    })
    try:
        result = user.create()
        user.id = result['lastrowid']
        return user
    except MySQLdb.IntegrityError:
        # user already exists (there is a unique constraint on the email DB field)
        return None


def add_server(url, user, ip_address):
    """
    Add a new website record
    """
    server = Server({
        "url": MiscUtils.get_clean_url(url),
        "status": 0,
        "creator_id": user.id,
        "ip_address": ip_address
    })
    try:
        result = server.create()
        server.id = result["lastrowid"]
        return server
    except MySQLdb.IntegrityError as e:
        logging.error("{0} Seems to already exist : {0}".format(url, e.message))
        return None
    except MySQLdb.ProgrammingError as e:
        logging.error("Mysql query error: {0}".format(e.message))
        return None


def add_permission(server, user=None, role=0):
    """
    Add a new user to the permissions table. Must be associated with a server
    """
    if user is None:
        user = current_user

    if server is not None:
        permission = Permission({
            "user_id": user.id,
            "server_id": server.id,
            "role": role
        })
        try:
            result = permission.create()
            permission.id = result["lastrowid"]
            return permission
        except Exception as e:
            logging.error("Could not add user permission to server: {0}".format(e.message))
            return None


def update_user_email(new_email):
    """
    Save the users' new email
    """
    current_user.email = new_email
    return current_user.save()


def check_old_password(text_value):
    """
    Returns whether the alleged password + salt matches what we have in the DB for this user
    """
    stored_pwd = str(current_user.password_hash)
    stored_salt = str(current_user.password_salt)
    hashed_pwd = bcrypt.hashpw(str(text_value), stored_salt)

    if stored_pwd != hashed_pwd:
        return False
    return True


def update_user_password(new_password, user=None):
    """
    If everything passed validation, create a new password hash and new salt for this user. Save to DB.
    """
    if user is None:
        user = current_user
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    user.password_hash = hashed_password
    user.password_salt = salt
    user.password_reset = 1
    return user.save()


def get_users_by_hash_id(hash_id):
    """
    Get all users that are associated to a website.
    """
    return current_app.db.get_users_by_server_hash_id(hash_id)


def delete_user_from_server(server, user_id_to_delete):
    """
    Delete a user permission from a server
    - Check to make sure that you're an admin for this site
    - Delete the permission
    """
    return current_app.db.delete_permission(server, user_id_to_delete)


def add_user_to_server(server, email, role):
    """
    Add a user to the server permissions
    Check if the user already exists in the user table. If not create the entry and send an email. In both cases,
    add an entry to the permissions table if it doesn't already exist.
    """
    user_data = current_app.db.get_user_by_email(email)

    if user_data:
        user = User(user_data)
        result = add_permission(server, user, role)

        if not result:
            return False, ___("User has already been added to this server.")

        return True, ___("User added successfully.")
    else:
        # create password data
        plain_text_password, hashed_password, password_salt = generate_new_user_password()

        # create the user
        user = create_user(email, hashed_password, password_salt)

        # send the new user confirmation emails
        current_app.mail_sender.notify_user_signed_up(user, plain_text_password)

        # add them to the website users
        add_permission(website, user=user, role=role)

        return True, ___("User was sent a confirmation email and added to this DDeflect v edge successfully.")


def save_records(records_list):
    """
    Get a list of tuples and save it to DB.
    """
    return current_app.db.save_records_list(records_list)


def get_records_for_server(hash_id, active_server):
    """
    Get all records for a particular server
    """
    records_data = current_app.db.get_records_for_server(hash_id)
    if not records_data:
        return []
    records = [Record(x) for x in records_data if x['id'] is not None]
    records = add_warnings(records, active_server)
    return records


def add_warnings(records, server):
    for r in records:
        if r.type == "CNAME" and r.hostname[-1] != ".":
            r.warning = 1
            r.warning_message = ___("Are you sure this is correct? Your CNAME records does not end in a '.'")
        else:
            r.warning = 0
    return records


def delete_record_for_website(record_id):
    """
    Delete a DNS zone file record
    """
    result = current_app.db.delete_record(record_id)
    return result


def delete_server_simple(active_server, user):
    """
    Delete a server from the dashboard before it was setup (no other users were added)
    """
    result = current_app.db.delete_server_by_id(active_server.id)
    logging.info("Deletion of server result: {}".format(result))

    result = current_app.db.delete_permissions_for_server(active_server.id)
    logging.info("Deletion of permissions result: {}".format(result))

    result = current_app.db.delete_records_for_server(active_server.id)
    logging.info("Deletion of records result: {}".format(result))

    current_app.mail_sender.notify_of_server_deletion(active_server, user)

    return result


def get_server_stats(hash_id, server):
    """
    Go to AWStats to retrieve the stats, or the cache if we can
    """
    stats_key = "stats:{}".format(hash_id)
    data = current_app.cache.get(stats_key)
    logging.info("Looking up stats in cache for {}.".format(stats_key))

    # if we have stats in cache, return those early
    if data is not None:
        return data

    logging.info("Cache data is not set. Making request to AWStats.")

    username = website.url
    password = website.awstats_password

    txt = ___("There was an error retrieving stats, please try again later")
    error_string = "<p style='margin-top:20px;'>"+txt+".</p>"
    try:
        a = requests.Session()
        a.auth = (username.replace(".", "_"), password)
        response = a.get("https://users.deflect.ca/awstats/awstats.pl?config=%s&framename=mainright" % username)
        if response.status_code != 200:
            logging.error("Request to awstats failed - status code was %d", response.status_code)
            return error_string  # don't set cache

        begin = '.*<body style="margin-top: 0px">'
        end = '</body>.*'
        regex_to_match = begin + "(.+?)" + end
        html = response.text.replace('\n', '')
        m = re.search(regex_to_match, html)
        data = m.group(1)
        data = data.replace("table", "table class='table-condensed table'")
        data = data.replace("#ECECEC", "#FAFAFA")
    except Exception as e:
        logging.error(e.message)
        import traceback
        print traceback.format_exc()
        data = error_string

    # set the cache
    current_app.cache.set(stats_key, data, timeout=60*60)

    return data


def create_incident_report(form):
    """
    Create a new incident report. Generates a redmine ticket and sends an email to sysops.
    """
    data = {
        "Server IP": form.server_ip.data,
        "Incident date and time": form.incident_date_time.data,
        "Problem description": form.problem_description.data,
        "Email": form.email.data,
        "Via Header": form.via_header.data
    }
    try:
        issue = current_app.redminer.create_user_ticket(3, "New incident report", [data, current_user])
    except Exception as e:
        logging.error("Could not create redmine ticket: {}".format(e.message))
        return None

    try:
        issue_url = "{0}/projects/signups/issues/{1}".format(current_app.config["REDMINE_URL"], issue.id)
        current_app.mail_sender.send_incident_report(data, issue_url)
    except Exception as e:
        logging.error("Could not send email to sysops: {}".format(e.message))
        return None

    return True
