#!/bin/python3

from urllib.request import urlopen, Request
from multiprocessing import Pool, cpu_count
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
    # logging.info(f"Fetching tld {tld}")
    ip_regex = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    fqdn_regex = r"[a-zA-Z0-9-.]{1,}\.[a-zA-Z0-9]{1,}\.[a-zA-Z0-9]{1,}\.$"
    tld_data = []
    try:
        for rdata in str(dns.resolver.resolve(tld, 'ns').response).split('\n'):
            domain = re.search(fqdn_regex, rdata, re.MULTILINE)
            if domain is None:
                continue
            else:
                dns_query = str(dns.resolver.resolve(domain.group(), 'a').response)
                entry_ip = re.search(ip_regex, dns_query, re.MULTILINE)
                if entry_ip is None:
                    continue
                else:
                    entry_ip = entry_ip.group()
                    entry_domain = domain.group()
                    # replace the last dot e.g. "ns1.dns.nic.aaa." to "ns1.dns.nic.aaa"
                    entry_domain = entry_domain[::-1].replace(".", "", 1)
                    entry_domain = entry_domain[::-1]
                    tld_data.append({
                        "fqdn": entry_domain,
                        "ip": entry_ip,
                        "ns": "tld",
                        "tld": tld
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
        write_json("./json/nstld.json", tlds)


def ns_root_worker(line):
    if " A " in line:
        fqdn_regex = r"^[A-Z]\.[A-Z-]{1,}\.(NET)"
        ip_regex = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        fqdn = re.search(fqdn_regex, line, re.MULTILINE).group()
        ip = re.search(ip_regex, line, re.MULTILINE).group()
        return {
            "fqdn": fqdn,
            "ip": ip,
            "ns": "root"
        }


def ns_root():
    root_data = request("https://www.internic.net/domain/named.root")
    if root_data is None:
        logging.warning("Couldn`t fetch https://www.internic.net/domain/named.root")
        return None
    else:
        pool = Pool(num_cpus)
        root_servers = pool.map(ns_root_worker, root_data.split('\n'))
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
        for line in str(dns.resolver.resolve(fqdn, 'A').response).split('\n'):
            search = re.search(ip_regex, line, re.MULTILINE)
            if search is not None:
                return {
                    "fqdn": fqdn,
                    "ip": search.group(),
                    "ns": "public",
                    "tags": data
                }
    except dns.resolver.NXDOMAIN:
        logging.info(f"Error while fetching resolver: {public_resolver}")
        return
    except dns.resolver.NoNameservers:
        logging.info(f"Error while fetching resolver: {public_resolver}")
        return
    except dns.resolver.NoAnswer:
        logging.info(f"Error while fetching resolver: {public_resolver}")
        return
    except dns.resolver.LifetimeTimeout:
        logging.info(f"Error while fetching resolver: {public_resolver}")
        return


def ns_public_dns():
    public_data = load_file("./public_dns.txt")
    pool = Pool(num_cpus)
    public_result = pool.map(ns_public_dns_worker, public_data.split('\n'))
    # remove None values from list
    public_result = [i for i in public_result if i]

    write_json("./json/public_dns.json", public_result)


def ns_public_suffix_worker(line):
    ip_regex = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    public_suffix_regex = r"^[a-zA-Z]{1,}\. [0-9]{1,} IN NS [a-zA-Z0-9]{1,}\.[a-zA-Z0-9]{1,}\.[a-zA-Z0-9]{1,}\.$"
    fqdn_regex = r"[a-zA-Z0-9-.]{1,}\.[a-zA-Z0-9]{1,}\.[a-zA-Z0-9]{1,}\.$"

    if line == "" or "//" in line:
        return
    else:
        logging.info(f"Fetching tld: {line.lower()}")
        try:
            for ns_line in str(dns.resolver.resolve(line, 'ns').response).split('\n'):
                suffix_match = re.match(public_suffix_regex, ns_line, re.MULTILINE)
                if suffix_match:
                    fqdn = re.search(fqdn_regex, ns_line, re.MULTILINE).group()
                    for a_line in str(dns.resolver.resolve(fqdn, 'a').response).split('\n'):
                        ip = re.search(ip_regex, a_line, re.MULTILINE)
                        if ip is not None:
                            return {
                                "fqdn": fqdn,
                                "ip": ip.group(),
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
        write_json("./json/nspublicsuffix.json", public_suffix)


def ns_domains_worker(line):
    ip_regex = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    fqdn_regex = r"[a-zA-Z0-9]{1,}\.[a-zA-Z0-9]{1,}\.[a-zA-Z0-9]{1,}\.$"
    ips = []
    return_data = []

    if line == "" or "//" in line:
        return
    else:
        logging.info(f"Fetching domain: {line.lower()}")
        try:
            for ns_line in str(dns.resolver.resolve(line, 'ns').response).split('\n'):
                fqdn = re.search(fqdn_regex, ns_line, re.MULTILINE)
                if fqdn is None:
                    continue
                else:
                    fqdn = fqdn.group()
                    for a_line in str(dns.resolver.resolve(fqdn, 'a').response).split('\n'):
                        ip = re.search(ip_regex, a_line, re.MULTILINE)
                        if ip is None:
                            continue
                        else:
                            ips.append(ip.group())

                for ip in ips:
                    return_data.append({
                        "fqdn": fqdn,
                        "ip": ip,
                        "ns": "domain",
                        "domain": line
                    })

            return return_data

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
        write_json("./json/nsdomains.json", domains_data_dns)


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
