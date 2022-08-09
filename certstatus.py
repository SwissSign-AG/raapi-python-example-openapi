#!/usr/bin/python3
""" Search for certificate order"""

import argparse

import OpenSSL
import OpenSSL.crypto

from swisssign_ra_api.v2.model.certificate_order import CertificateOrder
from swisssign_ra_api.v2.model.client import Client
from swisssign_ra_api.v2.model.certificate import Certificate
from swisssign_ra_api.v2.model.revocation_request import RevocationRequest

from swisspki_session import RaApiSession

class CertStatus():
    """ POC to issue fca certificates via api """
    def __init__(self, args):
        session = RaApiSession(environment=args.env)

        client = session.client
        client:Client
        print(f"Your client is {client.name}")

        all_orders = []
        all_orders:list[CertificateOrder]

        if args.cn:
            all_orders = session.api.get_certificate_orders({"attribute": args.cn})

        elif args.serial:
            serial = args.serial.replace(":","")

            if len(serial) == 39:
                serial = f"0{serial}"

            all_orders = session.api.get_certificate_orders({"serialNumber": serial})

        elif args.file:
            f = open(args.file,'rb')
            pem = f.read()
            f.close()
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
            serial = "{0:0{1}X}".format(x509.get_serial_number(),40)
            all_orders = session.api.get_certificate_orders({"serialNumber": serial})

        if len(all_orders):
            #pprint(all_orders)
            for i in all_orders:
                if i.certificate:
                    cert = i.certificate
                    print(f"Found certificate:\n  Serial: {cert.serial}\n  Revocation status: {cert.revocation_status}\n  Order UUID: {i.uuid}")

                    if args.revoke:
                        cert:Certificate
                        if cert and cert.revocation_status is None:
                            revocation_request = RevocationRequest(serial_number=cert.serial, issuer_name=cert.issuer)
                            session.api.revoke_certificates(body=[revocation_request])
                            print("Certificate is now revoked")
                        else:
                            print("Certificate is already revoked")
        else:
            print("Certificate not found")

parser = argparse.ArgumentParser(description='Get certificate details')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--serial',   '-S', dest='serial', action='store', help='Cert Serial', default=None)
group.add_argument('--cn',       '-c', dest='cn',     action='store', help='Cert cn',     default=None)
group.add_argument('--file',     '-f', dest='file',   action='store', help='Read cert to investigate from file', default=None)
parser.add_argument('--revoke',  '-r', dest='revoke', action='store_true', help='Revoke found certificates', default=False)
parser.add_argument('--env',     '-e', dest='env',    action='store', help='Environment', default=None)

swisspki = CertStatus(parser.parse_args())
