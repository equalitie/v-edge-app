import logging

from flask import Blueprint, Response
from flask_login import login_required

import frontend.utils.Exceptions as Exceptions


dns_bp = Blueprint('dns', __name__)


@dns_bp.errorhandler(Exceptions.NoZoneFileExists)
def return_on_missing_zone_file(error):
    """
    If there's an issue parsing the DNS zone file, return an error here.
    """
    logging.error("Missing DNS zone file: %s", error)
    return Response("No DNS zone file found", 404)


@dns_bp.errorhandler(Exceptions.CannotParseDNSZoneFile)
def return_on_bad_dns_zone_file(error):
    """
    If there's an issue parsing the DNS zone file, return an error here.
    """
    logging.error("Failed to parse DNS zone file: %s", error)
    return Response("Could not parse DNS zone file", 409)


@dns_bp.route('/dns/<hash_id>')
@login_required
def fetch_dns_zone_file(hash_id):
    """
    Try to fetch the DNS zone file for this domain. If it succeeded, save it to the DB, otherwise tell the client
    that it failed, and they need to paste their file in an editor.

    For now, we're just going to block the server for a few seconds and return a hardcoded string.
    """
    return "1"