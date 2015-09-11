import dns.resolver
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')


def check_current_ns(website):
    try:
        r = dns.resolver.Resolver()

        # set a specific nameserver ip here if we want
        #r.nameservers = [nameserver]

        expected_ns_info_values = website.nsinfo.strip().split("\n")
        expected_ns_info = {x.strip().lower() for x in expected_ns_info_values}
        answers = r.query(website.url, 'NS')
        servers = {str(s) for s in answers}
        logging.info("Servers returned are: %s" % servers)
        matches = expected_ns_info.intersection(servers)
        logging.info("Found %s matches" % len(matches))
        return matches, servers
    except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN):
        return False