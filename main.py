#!/bin/python3

from urllib.request import urlopen, Request
from multiprocessing import Pool
from json import dump
import dns.resolver
import logging
import urllib
import ssl
import sys
import re

logging.basicConfig(level=logging.INFO)
logging.getLogger().setLevel(logging.INFO)

# num_cpus = cpu_count() * 2
# let`s not do that! -> DOS yourself
num_cpus = 4


def write_json(file, data):
    with open(file, 'w') as f:
        dump(data, f, indent=4)


def load_file(file):
    f = open(file, encoding="utf8")
    return f.read()


def request(url):
    web_request = Request(
        url,
        data=None,
        headers={}
    )

    try:
        with urlopen(web_request, context=ssl.create_default_context()) as response:
            if response.status != 200:
                return None
            else:
                return response.read().decode('utf-8')
    except urllib.error.HTTPError:
        return None


def ns_tld_worker(tld):
    logging.info(f"Fetching tld {tld}")
    tld_data = []
    try:
        nameservers = dns.resolver.resolve(tld, 'ns')
        for entry in nameservers:
            entry = entry.to_text()[::-1].replace(".", "", 1)
            entry = entry[::-1]
            nameserver_ips = dns.resolver.resolve(entry, 'a')
            for ip in nameserver_ips:
                ip = ip.to_text()
                tld_data.append({
                    "fqdn": entry,
                    "ip": ip,
                    "ns": "tld",
                    "tld": "de"
                })

        return tld_data
    except dns.resolver.NoNameservers:
        logging.error(f"Error (NoNameservers) while fetching tld: {tld}")
        return []
    except dns.resolver.NoAnswer:
        logging.error(f"Error (NoAnswer) while fetching tld: {tld}")
        return []
    except dns.resolver.LifetimeTimeout:
        logging.error(f"Error (LifetimeTimeout) while fetching tld: {tld}")
        return []
    except dns.resolver.NXDOMAIN:
        logging.error(f"Error (NXDOMAIN) while fetching tld: {tld}")
        return []


def ns_tld():
    tld_data = request("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
    if tld_data is None:
        logging.warning("Couldn`t fetch https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
        return None
    else:
        pool = Pool(num_cpus)
        tlds = pool.map(ns_tld_worker, tld_data.split('\n'))
        # remove None values from list
        tlds = [i for i in tlds if i]
        write_tld = []
        for list_item in tlds:
            write_tld += list_item
        write_json("./json/nstld.json", write_tld)


def ns_root():
    root_data = request("https://www.internic.net/domain/named.root")
    if root_data is None:
        logging.warning("Couldn`t fetch https://www.internic.net/domain/named.root")
        return None
    else:
        root_servers = []
        for line in root_data.split('\n'):
            if " A " in line:
                fqdn_regex = r"^[A-Z]\.[A-Z-]{1,}\.(NET)"
                ip_regex = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
                fqdn = re.search(fqdn_regex, line, re.MULTILINE).group()
                ip = re.search(ip_regex, line, re.MULTILINE).group()
                root_servers.append({
                    "fqdn": fqdn,
                    "ip": ip,
                    "ns": "root"
                })

        # remove None values from list
        root_servers = [i for i in root_servers if i]
        write_json("./json/nsroot.json", root_servers)


def ns_public_dns_worker(public_resolver):
    ip_regex = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    data = public_resolver.split(",")
    if len(data) == 1 or "#" in data[0]:
        return

    fqdn = ""
    if not re.search(ip_regex, data[0], re.MULTILINE):
        fqdn = data[0]

    data = data.pop()

    try:
        public_dns = dns.resolver.resolve(fqdn, 'A')
        for entry in public_dns:
            ip = entry.to_text()

        return {
            "fqdn": fqdn,
            "ip": ip,
            "ns": "public",
            "tags": data
        }
    except dns.resolver.NXDOMAIN:
        logging.info(f"Error (NXDOMAIN) while fetching resolver: {public_resolver}")
        return
    except dns.resolver.NoNameservers:
        logging.info(f"Error (NoNameservers) while fetching resolver: {public_resolver}")
        return
    except dns.resolver.NoAnswer:
        logging.info(f"Error (NoAnswer) while fetching resolver: {public_resolver}")
        return
    except dns.resolver.LifetimeTimeout:
        logging.info(f"Error (LifetimeTimeout) while fetching resolver: {public_resolver}")
        return


def ns_public_dns():
    public_data = load_file("./public_dns.txt")
    pool = Pool(num_cpus)
    public_result = pool.map(ns_public_dns_worker, public_data.split('\n'))
    # remove None values from list
    public_result = [i for i in public_result if i]
    write_dns = []
    for list_item in public_result:
        write_dns += list_item
    write_json("./json/public_dns.json", write_dns)


def ns_public_suffix_worker(line):
    if line == "" or "//" in line:
        return
    else:
        logging.info(f"Fetching tld: {line.lower()}")
        try:
            suffix_ns = dns.resolver.resolve("ac", 'ns')
            for entry in suffix_ns:
                entry = entry.to_text()[::-1].replace(".", "", 1)
                entry = entry[::-1]
                suffix_a = dns.resolver.resolve(entry, 'a')
                for a_record in suffix_a:
                    ip = a_record.to_text()
                    return {
                        "fqdn": entry,
                        "ip": ip,
                        "ns": "tld",
                        "tld": line
                    }

        except dns.resolver.NXDOMAIN:
            logging.error(f"Error while fetching tld: {line}")
            return
        except dns.resolver.NoAnswer:
            logging.error(f"Error while fetching tld: {line}")
            return
        except dns.resolver.LifetimeTimeout:
            logging.error(f"Error while fetching tld: {line}")
            return
        except dns.resolver.NoNameservers:
            logging.error(f"Error while fetching tld: {line}")
            return


def ns_public_suffix():
    public_suffix_data = request("https://publicsuffix.org/list/public_suffix_list.dat")
    if public_suffix_data is None:
        logging.warning("Couldn`t fetch https://publicsuffix.org/list/public_suffix_list.dat")
        return None
    else:
        pool = Pool(num_cpus)
        public_suffix = pool.map(ns_public_suffix_worker, public_suffix_data.split('\n'))
        # remove None values from list
        public_suffix = [i for i in public_suffix if i]
        write_suffix = []
        for list_item in public_suffix:
            write_suffix += list_item
        write_json("./json/nspublicsuffix.json", write_suffix)


def ns_domains_worker(line):
    if line == "" or "//" in line:
        return
    else:
        logging.info(f"Fetching domain: {line.lower()}")
        try:
            domain_ns = dns.resolver.resolve(line, 'ns')
            domains = []
            for entry in domain_ns:
                entry = entry.to_text()[::-1].replace(".", "", 1)
                entry = entry[::-1]
                domain_a = dns.resolver.resolve(entry, 'a')
                ip = domain_a[0].to_text()
                domains.append({
                    "fqdn": entry,
                    "ip": ip,
                    "ns": "domain",
                    "domain": line
                })

            return domains

        except dns.resolver.NXDOMAIN:
            logging.error(f"Error (NXDOMAIN) while fetching domain: {line}")
            return
        except dns.resolver.NoAnswer:
            logging.error(f"Error (NoAnswer) while fetching domain: {line}")
            return
        except dns.resolver.LifetimeTimeout:
            logging.error(f"Error (LifetimeTimeout) while fetching domain: {line}")
            return
        except dns.resolver.NoNameservers:
            logging.error(f"Error (NoNameservers) while fetching domain: {line}")
            return


def ns_domains():
    domain_data = load_file("./domains.txt")
    if domain_data is None:
        logging.warning("Couldn`t load domains.txt")
        return None
    else:
        pool = Pool(num_cpus)
        domains_data_dns = pool.map(ns_domains_worker, domain_data.split('\n'))
        # remove None values from list
        domains_data_dns = [i for i in domains_data_dns if i]
        write_domains = []
        for list_item in domains_data_dns:
            write_domains += list_item
        write_json("./json/nsdomains.json", write_domains)


if __name__ == "__main__":
    actions = ["root", "tld", "public", "suffix", "domains"]
    arguments = sys.argv
    try:
        arguments[1]
        if arguments[1] not in actions:
            logging.warning("Please define a action to use: root | tld | public | suffix | domains")
            sys.exit()
    except IndexError:
        logging.warning("Please define a action to use: root | tld | public | suffix | domains")
        sys.exit()

    try:
        num_cpus = arguments[2]
    except IndexError:
        pass

    try:
        if arguments[1] not in actions:
            try:
                num_cpus = arguments[1]
            except IndexError:
                pass
    except IndexError:
        pass

    num_cpus = int(num_cpus)

    logging.info(f"Using {num_cpus} threads.")

    if arguments[1] == "root":
        logging.info("Fetching root servers")
        ns_root()
    elif arguments[1] == "tld":
        logging.info("Fetching tld servers")
        ns_tld()
    elif arguments[1] == "public":
        logging.info("Fetching public dns servers")
        ns_public_dns()
    elif arguments[1] == "suffix":
        logging.info("Fetching public suffix")
        ns_public_suffix()
    elif arguments[1] == "domains":
        logging.info("Fetching domains")
        ns_domains()
