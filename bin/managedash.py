#!/usr/bin/env python

DB_PASSWD=""
DB_USER=""

import MySQLdb
import argparse

class ManageDash(object):

    def __init__(self):
        self.db = MySQLdb.connect(db="vedgedash", user=DB_USER, passwd=DB_PASSWD)
        self.sitemap = self.get_sites()

    def get_sites(self):
        thecursor = self.db.cursor()
        thecursor.execute("SELECT url, id FROM websites;")
        sitemap = {}
        for result in thecursor.fetchall():
            sitemap[result[0]] = result[1]
        return sitemap

    def get_records(self, sitename):
        thecursor = self.db.cursor()
        thecursor.execute("select id,type,hostname,value,priority from records where website_id = %s;", (str(self.sitemap[sitename]),))
        for result in thecursor.fetchall():
            record_id, record_type, hostname, value, priority = result
            if not hostname:
                continue
            print hostname,
            print record_type,
            print value,
            if priority:
                print priority
            else:
                print

    def add_record(self, sitename, subdomain, record_type, record_value, priority):
        thecursor = self.db.cursor()
        if subdomain == "@":
            subdomain = sitename + "."
        else:
            subdomain = subdomain + "." + sitename + "."
        thecursor.execute("INSERT INTO records (website_id,type,hostname,value,priority) VALUES (%s,%s,%s,%s,%s);",
                          (self.sitemap[sitename],record_type,subdomain,record_value,priority))
        self.db.commit()

def check_args(args):
    if not args.add_record:
        if args.subdomain or args.record_type or args.record_value or args.priority:
            return "Arguments passed that are only valid when using --add"
    if args.record_type:
        if args.record_type not in ["A", "CNAME", "MX", "TXT", "AAAA", "SPF"]:
            return "Record type of incorrect type"
    return None

def main():
    parser = argparse.ArgumentParser(description='Modify the V Edge Dashboard data')
    parser.add_argument('domain', metavar='domain', type=str,
                        help='The domain to modify')
    parser.add_argument("--list", "-L", dest="list_records", action="store_true",
                        help="List all arguments")

    parser.add_argument("--add", "-A", dest="add_record", action="store_true",
                        help="Add record")
    parser.add_argument("--subdomain", "-S", dest="subdomain",
                        help="The name value for the record to be added")
    parser.add_argument("--value", "-V", dest="record_value",
                        help="The value of the record to be added")
    parser.add_argument("--type", "-T", dest="record_type",
                        help="Type of record to add")
    parser.add_argument("--priority", "-P", dest="priority", default=None,
                        help="Priority of record if setting an MX record")
    args = parser.parse_args()
    md = ManageDash()

    check_res = check_args(args)
    if check_res:
        raise SystemExit(check_res)

    if args.list_records:
        md.get_records(args.domain)
    if args.add_record:
        md.add_record(args.domain, args.subdomain, args.record_type, args.record_value, args.priority)

if __name__ == "__main__":
    main()
