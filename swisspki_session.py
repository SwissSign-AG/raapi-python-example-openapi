#!/usr/bin/python3

import requests
import yaml
from pprint import pprint

import swisssign_ra_api.v2
from swisssign_ra_api.v2.api import api_registration_api
from swisssign_ra_api.v2.model.client import Client

class RaApiSession():
    def __init__(self, config_file='./account.stage.yml'):

        with open(config_file,encoding='utf-8') as y:
            config = yaml.load(y, Loader=yaml.FullLoader)

        client=config['client']
        serviceaccount=config['serviceaccount']
        user_secret=config['secret']
        baseurl = config['baseurl']

        self.config = config

        self.session = requests.Session()
        if 'proxy' in config:
            proxies = {
                'https': config['proxy']
            }
            self.session.proxies.update(proxies)

        configuration = swisssign_ra_api.v2.Configuration(
            host = baseurl
        )
        configuration.api_key_prefix['ApiKeyAuth'] = 'Bearer'
        configuration.username = serviceaccount
        configuration.discard_unknown_keys = True

        # Get JWT
        self.api_client = swisssign_ra_api.v2.ApiClient(configuration)
        self.api = api_registration_api.ApiRegistrationApi(self.api_client)
        jwt = self.api.jwt(user_secret=user_secret, user_name=serviceaccount)
        configuration.api_key['ApiKeyAuth'] = jwt

        #pprint(configuration.auth_settings())

        clients = self.api.search_clients(search=client)
        if len(clients) > 1:
            raise Exception('more than one client matches to %s' % client)

        self.client:Client
        self.client = clients[0]
