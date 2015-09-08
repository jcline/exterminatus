#!/usr/bin/env python3

import argparse
import datetime
import json
import logging
import os
import re
import requests
import sys
import time

import dateutil.parser

logging.basicConfig(level=logging.DEBUG)

class api(object):
    def __init__(self, creds):
        self.credentials = creds
        self.set_headers()

    def set_headers(self):
        self.headers = {
            'User-Agent': 'Exterminatus/0.1 by /u/lenish',
            'Authorization': 'bearer %s' % self.credentials.token
        }

    def check_creds(self):
        if self.credentials.is_expired():
            self.gain_access()

    def gain_access(self):
        body = {
            'grant_type': 'password',
            'username': self.credentials.user,
            'password': self.credentials.password
        }
        r = requests.post('https://www.reddit.com/api/v1/access_token',
            data=body,
            auth=(self.credentials.client_id, self.credentials.client_secret)
        )
        self.credentials.init_token(r.json())
        self.set_headers()
        time.sleep(2)

    def load_comments(self, thread):
        match = re.match('.*/(r/.*)', thread)
        if not match:
            return None

        self.check_creds()

        r = requests.get('https://oauth.reddit.com/%s' % match.group(1),
            headers=self.headers
        )

        time.sleep(2)

        return r.json()

    def remove(self, thing):
        self.check_creds()
        body = {
            'id': thing,
            'spam': False,
        }
        r = requests.post('https://oauth.reddit.com/api/remove',
            headers=self.headers,
            data=body
        )
        time.sleep(2)

class credentials(object):
    def __init__(self, user, password, client_id, client_secret, token=None, token_expiry=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.user = user
        self.password = password

        self.file_name = None

        if not token:
            self.token = ''
            self.token_expiry = datetime.datetime.utcnow()
        else:
            self.token = token
            self.token_expiry = token_expiry

    def init_token(self, token):
        if not 'access_token' in token:
            print(token)
            sys.exit(1)
        self.token = token['access_token']
        self.token_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=(token['expires_in']-30))

        credentials.save_credentials(self, self.file_name)

    def is_expired(self):
        return datetime.datetime.utcnow() > self.token_expiry

    @staticmethod
    def load_credentials(conf_file_name):
        if os.path.isfile(conf_file_name):
            with open(conf_file_name) as config_file:
                config = config_file.read()
            config = json.loads(config)

            if 'token_expiry' in config:
                config['token_expiry'] = dateutil.parser.parse(config['token_expiry'])

            config = credentials(**config)
            config.file_name = conf_file_name

            return config
        return None

    @staticmethod
    def save_credentials(creds, conf_file_name):
        if not creds:
            return

        config_dict = {
            'user': creds.user,
            'password': creds.password,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret
        }
        if creds.token != '':
            config_dict['token'] = creds.token
            config_dict['token_expiry'] = creds.token_expiry.isoformat()

        with open(conf_file_name, mode='w') as config_file:
            config_file.write(json.dumps(config_dict))

    @staticmethod
    def load_or_create_credentials(conf_file_name):
        creds = credentials.load_credentials(conf_file_name)
        if not creds:
            user = input('Username: ')
            password = input('Password: ')
            client_id = input('Client ID: ')
            client_secret = input('Client Secret: ')
            creds = credentials(user, password, client_id, client_secret)
            creds.file_name = conf_file_name
            credentials.save_credentials(creds, conf_file_name)
            return creds
        return creds


def extract_comment_ids_top(thread):
    ids = []
    for child in thread:
        ids.extend(extract_comment_ids_replies(child['data']['children']))
    return ids

def extract_comment_ids_replies(comment):
    ids = []
    for child in comment:
        if not child['data']['banned_by']:
            ids.append(child['data']['name'])
        if 'replies' in child['data'] and 'data' in child['data']['replies']:
            ids.extend(extract_comment_ids_replies(child['data']['replies']['data']['children']))
    return ids

def load_all_comments(client, threads):
    ids = []
    for thread in threads:
        if re.match('http.*/comments/[^/]+/[^/]+/[^/]+', thread):
            # We're only removing a comment subthread, not the entire post
            comments = client.load_comments(thread)
            assert len(comments) == 2, json.dumps(comments)
            ids.extend(extract_comment_ids_replies(comments[1]['data']['children']))
        else:
            ids.extend(extract_comment_ids_top(client.load_comments(thread)))
    return ids

def exterminatus(client, ids):
    progress = 0
    for i in ids:
        client.remove(i)
        progress += 1
        print('Progress: %d/%d' % (progress, len(ids)))

def main():
    parser = argparse.ArgumentParser(description='Declare Exterminatus on a Reddit thread.')
    parser.add_argument('thread', nargs='+', help='The thread(s) to declare Exterminatus on')
    args = parser.parse_args()

    threads = args.thread

    config = credentials.load_or_create_credentials('config')

    if not config:
        print('Could not load or generate config')
        sys.exit(1)

    print('Before declaring Exterminatus, thou shalt update AutoModerator to delete all new comments.')
    char = input('Begin reconnaissance? y/n ')
    if char != 'y':
        return

    client = api(config)

    ids = load_all_comments(client, threads)

    print('Blasphemers:\n %s' % ids)
    char = input('Begin Exterminatus? y/n ')
    if char != 'y':
        return

    print('It is now that we perform our charge.')
    print('In fealty of the God-Emperor (our undying lord) and by the grace of the Golden Throne I declare Exterminatus upon those who would deny our faith. The Emperor protects.')

    exterminatus(client, ids)

main()
