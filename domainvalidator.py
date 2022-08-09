#!/usr/bin/python3
""" Validate domains """

import time
import argparse

from swisssign_ra_api.v2.model.client_dns import ClientDNS
from swisspki_session import RaApiSession

class DomainValidator():
    """ Prevalidate domains """
    def __init__(self, args):
        session = RaApiSession(args.env)

        domains_to_validate = session.config['domains']

        if session.client:
            domains = session.api.get_client_prevalidated_domains(session.client.uuid)

            for domain in domains:
                if domain.domain in domains_to_validate:
                    domains_to_validate.remove(domain.domain)

            if len(domains_to_validate):
                print(f"Triggering validation for domains: {', '.join(domains_to_validate)}")
                added_domains = session.api.create_client_prevalidated_domains(session.client.uuid, domains_to_validate )

                # Wait for domains to be validated (-> DNS)
                while True:
                    one_pending = False

                    #domains = session.api.get_client_prevalidated_domains(session.client.uuid)
                    domain:ClientDNS
                    for domain in added_domains:
                        domain_to_test = session.api.get_client_prevalidated_domain(domain.uuid)
                        if str(domain_to_test.status) == 'PENDING':
                            one_pending = True
                            session.api.validate_client_prevalidated_domain(domain.uuid)
                        print(f"{domain.status} {domain.domain} {domain.random_value}")

                    if not one_pending:
                        break
                    print("-----------------------------------------------------")
                    time.sleep(5)


parser = argparse.ArgumentParser(description='Parse args')
parser.add_argument('--env',     '-e', dest='env',      action='store', help='Environment File')
parser.add_argument('--verbose', '-v', dest='verbose',  action='store_true', help='Verbose', default=False)

obj = DomainValidator(parser.parse_args())
