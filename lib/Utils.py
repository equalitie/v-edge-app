import urlparse
import logging
import string
import random
from flask import current_app

import fess_up
from fess_up import dnsnames


def generate_hidden_domain(domain_len=10):
    """
    Generate the random hidden domain for a website
    """
    char_list = list(string.ascii_letters + "0123456789")
    domain_string = "".join(
        [char_list[int(random.random() * len(char_list))] for _ in range(domain_len)]
    )
    return domain_string.lower()


def get_clean_url(url):
    """
    Get a url without protocol nor www. prefixes
    """
    try:
        url_parts = urlparse.urlparse(url)
        if url_parts.netloc.startswith('www.'):
            return str(url_parts.netloc[4:])
        return str(url_parts.netloc)
    except Exception, e:
        logging.error("Couldn't get clean URL: %s", e)
        return None


def fetch_dns_records(website, db):
    """
    Fetch DNS records using fess_up (lock website in the meantime) and try to save them to DB.
    """
    # lock website until the scan is done
    db.lock_website(website)
    try:
        logging.info("Locked website, starting scan of %s for results", website.url)
    except AttributeError:
        logging.error("Could not find website url.")

    try:
        # get the records
        dnsname_list = dnsnames.dnsnames + [None]
        ds = fess_up.DomainScan(website.url, dnsname_list)
        ds.runScan()

        logging.info("Finished domain scan")

        # don't go further if we have a wildcard
        if not ds.wildcard:
            records = parse_record_results(ds.data, website)
            logging.info("Found %s records" % len(records))

            # save
            if records:
                db.save_records_list(records)
        else:
            logging.warn("Wildcard seems to be true, ignoring results.")

    except Exception as e:
        logging.error("Could not fetch records: {}".format(e.message))
    finally:
        # no matter what:
        # unlock website and return True to signify we're done here.
        db.unlock_website(website)
        logging.info("Unlocked website")

        return True


def parse_record_results(records, website):
    """
    After fetching the records, try to parse them.
    """
    r = []
    for hostname, record_list in records.iteritems():
        for record_type, value in record_list.iteritems():
            # if hostname is None, this should be the root of the domain
            if hostname is None:
                if record_type == "A":
                    for item in record_list["A"]:
                        r.append((website.id, 'A', ("%s." % website.url), item, None, 0))
                if record_type == "TXT":
                    for item in record_list["TXT"]:
                        r.append((website.id, 'TXT', ("%s." % website.url), item, None, 0))
                if record_type == "MX":
                    for item in record_list["MX"]:
                        r.append((website.id, 'MX', ("%s." % website.url), item[0], item[1], 0))
            else:
                if record_type == "A" or record_type == "CNAME":
                    for item in record_list[record_type]:
                        r.append((website.id, record_type, "{0}.{1}.".format(hostname, website.url), item, None, 1))
    return r


def add_to_failed_attempts(ip, email):
    """
    Add a failed password attempt.
    """
    timeout = 60*5
    cache_key = "{}{}".format(ip, email)
    logging.info("Adding failed attempt for {}".format(cache_key))

    current_value = current_app.cache.get(cache_key)
    if current_value is None:
        current_app.cache.set(cache_key, 1, timeout=timeout)
    else:
        current_app.cache.set(cache_key, current_value+1, timeout=timeout)


def get_failed_attempts(ip, email):
    """
    Get failed password attempts.
    """
    cache_key = "{}{}".format(ip, email)
    attempts = current_app.cache.get(cache_key)
    logging.info("Found {} attempts for {}".format(attempts, cache_key))
    return attempts
