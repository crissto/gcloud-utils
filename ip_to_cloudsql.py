import argparse
import os
import sys
import json
import requests

from googleapiclient import discovery
import httplib2
from oauth2client import client
from oauth2client import file as oauthFile
from oauth2client import tools
from oauth2client.file import Storage

argparser = argparse.ArgumentParser(add_help=False)
argparser.add_argument('-p', '--project', help="Project ID", required=True)
argparser.add_argument('-i', '--instance', help="Instance Name")

parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser, argparser])
flags = parser.parse_args(sys.argv[1:])

CREDENTIAL_STORE_FILE = 'credentials.dat'

OAUTH_SCOPES = ['https://www.googleapis.com/auth/sqlservice.admin']


def authenticate_using_user_account(path_to_client_secrets_file):
    
    flow = client.flow_from_clientsecrets(
        path_to_client_secrets_file, scope=OAUTH_SCOPES)


    storage = Storage(CREDENTIAL_STORE_FILE)
    credentials = storage.get()

    
    if credentials is None or credentials.invalid:
        credentials = tools.run_flow(flow, storage,
                                     tools.argparser.parse_known_args()[0])

    # Use the credentials to authorize an httplib2.Http instance.
    return credentials.authorize(httplib2.Http())


def setup():
    # Authenticate using the supplied user account credentials
    http = authenticate_using_user_account('client_secrets.json')
    service = discovery.build('sqladmin', 'v1beta4', http=http)
    return service


service = setup()
project = flags.project


def list_instances():
    resp = service.instances().list(project=project).execute()

    return json.dumps([instance['name']
                       for instance in resp['items']], indent=2)


def get_instance_data(instance_name):
    return service.instances().get(project="bmindtracker", instance=instance_name).execute()


def add_ip_to_body(body):
    authorized_networks = body['settings']['ipConfiguration']['authorizedNetworks']
    ip = requests.get('http://ipinfo.io/json').json()['ip']
    authorized_networks = [
        network for network in authorized_networks if network['name'] != 'Chris AUTO-IP']

    authorized_networks.append(
        {'value': ip, 'name': 'Chris AUTO-IP', 'kind': 'sql#aclEntry'})

    return {'settings': {'ipConfiguration': {'authorizedNetworks': authorized_networks}}}


def patch_instance(instance_name, body):
    return service.instances().patch(project="bmindtracker", instance=instance_name, body=body).execute()


def main():
    instance = flags.instance
    data = get_instance_data(instance)
    new_body = add_ip_to_body(data)
    print(patch_instance(instance, new_body))


if __name__ == '__main__':
    if (not flags.instance):
        print("Las instancias en este proyecto son las siguientes")
        print("\n")
        print(list_instances())
        print("\n")
        print("Por favor especifique instancia")
        sys.exit(0)
    else:
        main()
    # main()
#   print(get_instance_data('stories-front'))
