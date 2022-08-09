#!/usr/bin/python3

import os
import sys
from datetime import datetime
import base64
from pprint import pprint

import argparse
import time
import yaml

import OpenSSL
import OpenSSL.crypto

from swisssign_ra_api.v2.model.certificate_order import CertificateOrder
from swisssign_ra_api.v2.model.certificate import Certificate
from swisssign_ra_api.v2.model.revocation_request import RevocationRequest

from swisspki_session import RaApiSession

class CertIssuer():
    """ POC to issue fca certificates via api """
    def __init__(self, args):
        self.pkey = None

        session = RaApiSession(environment=args.env)

        client = session.client
        cert_template = session.config['certificates'][args.profile]

        my_product = None
        product_dict = dict()
        for cert_crypto in client.products:
            product_dict[cert_crypto.product_name] = cert_crypto.to_dict()

            if cert_crypto.product_name == cert_template['product']:
                my_product = cert_crypto
                print(f"Found Product {cert_crypto.product_name}")

        yaml_products = yaml.dump(product_dict, explicit_start=True, default_flow_style=False)
        with open('./products.yml','w', encoding='utf-8') as f:
            f.write(yaml_products)

        if not my_product:
            raise Exception(f"Product not found: {cert_template['product']}")

        if not args.csr:
            if not args.key:
                # Generate privatekey
                if args.verbose:
                    print("--- Generating Key ---")
                self.pkey = self.gen_key()
            else:
                if args.verbose:
                    print(f"--- Loading Key from File {args.key} ---")

                with open(args.key, 'r', encoding='utf-8') as file:
                    key_pem = file.read()

                self.pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem)

            subject_fields = cert_template['subject']
            san_fields = []
            if 'san' in cert_template:
                san_fields = cert_template['san']
            if args.verbose:
                print("--- Generating CSR ---")
            csr = self.build_csr (subject_fields, san_fields, self.pkey)
            csr_pem = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)

        else:
            if args.verbose:
                print(f"--- Loading CSR from File {args.csr} ---")
            with open(args.csr, 'rb') as file:
                csr_pem = file.read()

            csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)

        order_start = datetime.now()

        if args.verbose:
            print("--- Order Start ---")
        order = session.api.issue_certificate(my_product.uuid, body=csr_pem.decode('utf-8'))

        if args.verbose:
            print(f"--- Order UUID {order.uuid} ---")

        order_dir = f"./out/{order.uuid}"
        if not os.path.exists("./out"):
            os.mkdir("./out")
        os.mkdir(order_dir)

        if self.pkey:
            with open(f"{order_dir}/key","wb") as key_file:
                key_file.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.pkey))

        with open(f"{order_dir}/csr","wb") as csr_file:
            csr_file.write(csr_pem)

        while True:
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            try:
                orderstatus = session.api.get_certificate_order_status(order.uuid)
            except:
                print(f"{ order.uuid } - could not get order status")
                continue

            status_back = datetime.now()
            print(f"{ order.uuid } - {current_time}: {orderstatus} - {str(status_back - now)}")
            if str(orderstatus) == "ISSUED":
                break
            if str(orderstatus) == "FAILED":
                break

            time.sleep(2)

        order:CertificateOrder
        order.certificate:Certificate
        order = session.api.get_certificate_order(order.uuid)
        if order.status == "FAILED":
            print("order failed - exiting")
            sys.exit(2)

        if order.status == "ISSUED":
            if args.verbose:
                print("--- Order issued successfully ---")

        order_issued_time = datetime.now()
        print(f"\n{ order.uuid } - Duration until issue: {str(order_issued_time - order_start)}\n")

        cert_chain = session.api.get_certificate_chain(order.uuid)
        if args.verbose:
            print("--- Cert Chain ---")

        for cert in cert_chain:
            cert_crypto = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, base64.b64decode(str(cert)))
            cn = cert_crypto.get_subject().commonName.replace(' ','_')
            if args.verbose:
                print (cert_crypto.get_subject().commonName)

            with open(f"{order_dir}/{cn}.pem","wb") as cert_file:
                cert_file.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_crypto))

        print(f"\n{ order.uuid } - {datetime.now()} - Revocation start\n")
        rev_request = RevocationRequest(serial_number=order.certificate.serial, issuer_name=order.certificate.issuer)
        session.api.revoke_certificates(revocation_request=[rev_request])
        print(f"\n{ order.uuid } - {datetime.now()} - Revocation end\n")

    def build_csr (self, subject_fields, san_fields, pkey):
        """ Build CSR based on profile in account.yml """
        csr = OpenSSL.crypto.X509Req()

        # Set subject fields
        subj = csr.get_subject()
        for i in subject_fields:
            for key, value in i.items():
                setattr(subj,key,value)

        # Set SAN
        san_items = []
        if len(san_fields):
            for i in san_fields:
                for key, value in i.items():
                    san_items.append("%s:%s" % (key,value))

            san = ", ".join(san_items)

            csr.add_extensions([
                OpenSSL.crypto.X509Extension(
                    b"subjectAltName", False, san.encode()
                )
            ])

        # Sign csr
        csr.set_pubkey(pkey)
        csr.sign(pkey, "SHA256")

        return csr

    def gen_key(self):
        """ Generate RSA Privatekey """
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        return pkey

parser = argparse.ArgumentParser(description='Parse args')
parser.add_argument('--profile', '-p', dest='profile',  action='store', help='Profile to use')
parser.add_argument('--env',     '-e', dest='env',      action='store', help='Environment')
parser.add_argument('--csr',     '-c', dest='csr',      action='store', help='CSR File')
parser.add_argument('--key',     '-k', dest='key',      action='store', help='Key File')
parser.add_argument('--verbose', '-v', dest='verbose',  action='store_true', help='Verbose', default=False)

swisspki = CertIssuer(parser.parse_args())
