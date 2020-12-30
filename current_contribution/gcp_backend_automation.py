#!/usr/bin/env python3
"""
GCP script which is capable of interacting with backends and instance groups
Todo:
* Make sure the add and remove function output same type
* Make sure new filter function is in the right place
* audit status and message.
"""
# Copyright (c) Microsoft Corporation.
# Licensed under the GPL-3.0-only license.

import json
import time
import argparse
import logging
import os
import requests
import jwt


from oauth2client.client import AccessTokenCredentials
from googleapiclient import discovery

LEVEL = logging.WARNING
FORMATS = "\n %(asctime)s-%(levelname)s: %(message)s"
HANDLERS = [logging.StreamHandler()]
logging.basicConfig(level=LEVEL, format=FORMATS, handlers=HANDLERS)

# Remove
GCP_PROJECT = 'project-name'
# Insert your zones
GCP_ZONES = ['us-central1-a', 'us-central1-c', 'us-central1-f']
# Replace variable with the value
GCE_HOST = "www.googleapis.com"

GCE_SCOPES = "https://" + GCE_HOST + "/auth/cloud-platform"

# Will definte later
"""
This code was written using a file which contained the necessary information
for authenticating to GCP. Instructions for creating this file will be
provided in the repository. This will eventually be deprecated and instead,
we will use the native operation for ansible-collection/google.cloud
"""
gcp_cred_FILE_PATH = ""

EXPIRES_IN = 3600

def find_gcp_file(name, path):
    """
    Function is used to find the file path of the gcp_cred.json file locally

    Parameters:
    name (str): The name of the file gcp_cred.json
    path (str): The path of where you are, it will find relative location to ansible-playbook

    Returns:
    str: The path to the gcp_cred.json file
    """

    if not os.path.isfile(path):
        path = os.getcwd()
    search_path = path.split("google.cloud", 1)[0]
    for root, dirs, files in os.walk(search_path):
        if name in files:
            return os.path.join(root, name)

def load_json_credentials(filename):
    """
    Load the credentials from the  gcp_cred.json

    Parameters:
    filename (str): Path to file

    Returns:
    dict: content of the credentials

    """
    with open(filename, 'r') as credential_file:
        data = credential_file.read()

    return json.loads(data)

def create_signed_jwt(pkey, pkey_id, email, scope):
    """
    Created a Json Web Tocken necessary for querying the API

    Parameters:
    pkey (str): Private key from credentials
    pkey_id (str): Private key ID from credentials
    email (str): email from credentials
    scope (str): url for cloud API

    Returns:
    bytes: contains the jwt

    """
    # jhanley.com
    # Google Endpoint for creating OAuth 2.0 Access Tokens from Signed-JWT
    auth_url = "https://" + GCE_HOST + "/oauth2/v4/token"

    issued = int(time.time())
    expires = issued + EXPIRES_IN    # EXPIRES_IN is in seconds

    # JWT Headers
    additional_headers = {
        'kid': pkey_id,
        "alg": "RS256",
        "typ": "JWT"    # Google uses SHA256withRSA
    }

    # JWT Payload
    payload = {
        "iss": email,        # Issuer claim
        "sub": email,        # Issuer claim
        "aud": auth_url,    # Audience claim
        "iat": issued,        # Issued At claim
        "exp": expires,        # Expire time
        "scope": scope        # Permissions
    }

    # Encode the headers and payload and sign creating a Signed JWT (JWS)
    sig = jwt.encode(payload, pkey, algorithm="RS256", headers=additional_headers)

    return sig

def exchange_jwt_for_access_token(signed_jwt):
    """
    Take the signed json web token and turn it into an access token

    Parameters:
    signed_jwt (bytes): the signed_jwt

    Returns:
    dict: contains the jwt object to be parsed

    """
    auth_url = "https://" + GCE_HOST + "/oauth2/v4/token"

    params = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt
    }

    access_token = requests.post(auth_url, data=params)

    return access_token.json()

def create_service_object(token):
    """
    Takes the token and create a service object to Query GCP API

    Parameters:
    token (str): str containing the jwt

    Returns:
    oauth2client.client.AccessTokenCredentials : An object created using
    GCP's API which allows us to make requests
    """
    new_credentials = AccessTokenCredentials(token, "test-service-account", None)
    service = discovery.build('compute', 'v1', credentials=new_credentials, cache_discovery=False)

    return service

def get_all_backends(service):
    """
    Gets all the backends from GCP which have an instance group configured
    It then formats them so that each backend shows which instance groups belong to them

    Parameters:
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    list(dicts): An object which formats the backends with their related instance groups
    Sample:
    [{'backend_name': 'backend-1',
      'instance_group_info': [{'instance_group_name': 'ig-1',
        'zone': 'us-central1-a',
        'instances': None}]},
     {'backend_name': 'backend-2',
      'instance_group_info': [{'instance_group_name': 'ig-2',
        'zone': 'us-central1-a',
        'instances': None},
       {'instance_group_name': 'ig-3',
        'zone': 'us-central1-c',
        'instances': None},
       {'instance_group_name': 'ig-4',
        'zone': 'us-central1-f',
        'instances': None}]}]

    """
    backends_information = []
    request = service.backendServices().list(project=GCP_PROJECT)

    while request is not None:
        response = request.execute()

        for backend_services in response['items']:
            backend_dict = {}
            backend_name = backend_services['name']
            instance_group_list = []
            try:
                backend_groups = backend_services['backends']
                for instance_groups in backend_groups:
                    instance_group_dict = {}
                    instance_group_name = instance_groups['group'].split("/")[-1]
                    instance_group_dict['instance_group_name'] = instance_group_name
                    instance_group_dict['zone'] = instance_groups['group'].split("/")[-3]
                    instance_group_dict['instances'] = None
                    instance_group_list.append(instance_group_dict)
            except KeyError:
                pass
            backend_dict['backend_name'] = backend_name
            backend_dict['instance_group_info'] = instance_group_list
            backends_information.append(backend_dict)

        request = service.backendServices().list_next(previous_request=request,
                                                      previous_response=response)

    return backends_information

def get_instances_groups_not_in_backends(instance_groups_present, service):
    """
    Get all of the instances groups which are not in a backend

    Parameters:
    instance_groups_present (list): List of instance groups which are behind a backend
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    list: List of dictionaries containing all the instance groups
    not in backends and their information
    """
    instance_group_list = []
    for zones in GCP_ZONES:
        request = service.instanceGroups().list(project=GCP_PROJECT, zone=zones)
        while request is not None:
            response = request.execute()
            for instance_group in response['items']:
                instance_group_info = {}
                if instance_group['name'] not in instance_groups_present:
                    instance_group_info['instance_group_name'] = instance_group['name']
                    instance_group_info['zone'] = instance_group['zone'].split("/")[-1]
                    instance_group_info['instances'] = None
                    instance_group_list.append(instance_group_info)
            request = service.instanceGroups().list_next(previous_request=request,
                                                         previous_response=response)

    return instance_group_list

def extract_instance_list_from_all_backends(all_backends):
    """
    Create a list containing all of the instance groups behind backend services

    Parameters:
    all_backends (list): List of dicts containing information about each backend

    Returns:
    list: List of instance group names
    """
    instance_groups_present = []
    for backends in all_backends:
        for instance_groups in backends['instance_group_info']:
            instance_groups_present.append(instance_groups['instance_group_name'])

    return instance_groups_present

def get_instance_group_info(instance_group, zone, service):
    """
    Provides the list of instances within an instnace group

    Parameters:
    instance_group (str): Name of instance group
    zone (str): The zone of the instance group
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    list: A list which contains all of the RUNNING instances within an instance group
    """
    instance_list = []

    instance_groups_list_instances_request_body = {
        "instanceState": "RUNNING"
    }
    request = service.instanceGroups().listInstances(project=GCP_PROJECT,
                                                     zone=zone,
                                                     instanceGroup=instance_group,
                                                     body=instance_groups_list_instances_request_body)

    try:
        while request is not None:
            response = request.execute()
            for instance_with_named_ports in response['items']:
                instance_name = instance_with_named_ports['instance'].split("/")[-1]
                instance_list.append(instance_name)
            request = service.instanceGroups().listInstances_next(previous_request=request,
                                                                  previous_response=response)
    except KeyError:
        pass

    return instance_list

def get_instances_for_instance_groups(instance_group_info, service):
    """

    Parameters:
    instance_group_info (dict): Contains instance group information
    service (): Serivce API

    Return:
    instance_list (list): List of instances belonging to the group
    """
    zone = instance_group_info['zone']
    instance_group_name = instance_group_info['instance_group_name']
    instance_list = (get_instance_group_info(instance_group_name, zone, service))
    return instance_list

def create_inventory_object(infra_snapshot):
    """
    Massage the infra_snapshot so that it can be easily passed off to the inventory.py script
    #https://stackoverflow.com/questions/44734858/python-calling-a-module-that-uses-argparser

    Parameters:
    infra_snapshot (list): A List object which contains all the backends in GCP

    Returns:
    dict: Containing full description of the backend
    """
    instance_group_inventory = {"_meta": {"hostvars": {}}}
    for backends in infra_snapshot:
        for instance_groups in backends['instance_group_info']:
            hosts_dict = {}
            instance_group_name = instance_groups['instance_group_name']
            # might need this feature.
            instance_group_list = [instance + "domain.name" for instance in instance_groups['instances']]
            hosts_dict["hosts"] = instance_group_list
            instance_group_inventory[instance_group_name] = hosts_dict

    return instance_group_inventory

def group_infra(inventory_object, client_name="", env=""):
    """
    Take the inventory object created by create_inventory_object
    Then filter it on either client name, env, both or niether
    Print the output as a string seperated by spaces

    Parameters:
    inventory_object (dict): The inventory object used by ansible

    Returns:
    str: Separating the relevant instance groups
    """
    pass
    filter_ig = []
    for instance_group in list((inventory_object.keys())):
        if client_name not in instance_group:
            continue
        if env not in instance_group:
            continue
        filter_ig.append(instance_group)
    return " ".join(filter_ig)

def run_all(all_backends, service):
    """
    Append all_backends for all backends
    Parameters:
    instance_filter (list): A list of instances to find within all_backends
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    list: Containing all backends
    """
    infra_snapshot = []
    for backends in all_backends:
        for instance_groups in backends['instance_group_info']:
            instance_groups['instances'] = get_instances_for_instance_groups(instance_groups,
                                                                             service)
        infra_snapshot.append(backends)
    return infra_snapshot

def run_backends(all_backends, backend_filter, service):
    """
    Filter all_backends based on specified backend_filter

    Parameters:
    all_backends (dict): The backend dictionary containing all_backends you want to parse through
    backend_filter (list): A list of backends to find within all_backends
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    list: Containing only the backends in backend_filter
    """
    infra_snapshot = []
    for backends in all_backends:
        if backends['backend_name'] in backend_filter:
            for instance_groups in backends['instance_group_info']:
                instance_groups['instances'] = get_instances_for_instance_groups(instance_groups,
                                                                                 service)
            infra_snapshot.append(backends)
    return infra_snapshot

def run_instance_groups(all_backends, instance_group_filter, service):
    """
    Filter all_backends based on specified instance_group_filter

    Parameters:
    all_backends (dict): The backend dictionary containing all_backends you want to parse through
    instance_group_filter (list): A list of instance groups to find within all_backends
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    list: Containing only the backends with the specified instance groups
    """
    infra_snapshot = []
    for backends in all_backends:
        found = False
        for instance_groups in backends['instance_group_info']:
            if instance_groups['instance_group_name'] in instance_group_filter:
                found = True
                break
        if found:
            for instance_groups in backends['instance_group_info']:
                instance_groups['instances'] = get_instances_for_instance_groups(instance_groups,
                                                                                 service)
            if backends not in infra_snapshot:
                infra_snapshot.append(backends)
    return infra_snapshot

def run_instance(all_backends, instance_filter, service):
    """
    Filter all_backends based on specified instance_filter

    Parameters:
    all_backends (dict): The backend dictionary containing all_backends you want to parse through
    instance_filter (list): A list of instances to find within all_backends
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    list: Containing only the backends with the specified instances
    """
    infra_snapshot = []
    for backends in all_backends:
        found = False
        for instance_groups in backends['instance_group_info']:
            instance_groups['instances'] = get_instances_for_instance_groups(instance_groups,
                                                                             service)
            for instance in instance_filter:
                if instance in instance_groups['instances']:
                    found = True
                    break
        if found:
            infra_snapshot.append(backends)
    return infra_snapshot

class HealthCheckError(Exception):
    """
    Used as a custom exception handler for health checks
    """
    pass

def check_healthy_instance_groups(backend_dict, service):
    """
    Provides the list of healthy instances within a backend service

    Parameters:
    backend_dict (dict): A dictionary object which is each item within the infra_snapshot
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    tuple(list, list): A tuple which contains a list of healthy nodes and unhealthy nodes
    """

    healthy_nodes = []
    unhealthy_nodes = []

    for instance_groups in backend_dict['instance_group_info']:
        resource_group_reference_body = {
            "group": "/zones/{z}/instanceGroups/" \
                     "{i}".format(z=instance_groups['zone'],
                                  i=instance_groups['instance_group_name'])
            }

        request = service.backendServices().getHealth(project=GCP_PROJECT,
                                                      backendService=backend_dict['backend_name'],
                                                      body=resource_group_reference_body)
        response = request.execute()

        try:
            for node_health_status in response['healthStatus']:
                if node_health_status['healthState'] == "HEALTHY":
                    healthy_nodes.append(node_health_status['instance'].split("/")[-1])
                else:
                    unhealthy_nodes.append(node_health_status['instance'].split("/")[-1])
        except KeyError:
            raise HealthCheckError

    return (healthy_nodes, unhealthy_nodes)

def run_check_health(infra_snapshot, service):
    """
    Run the health check, and amend the health check object to
    include the healthy and unhealthy nodes

    Parameters:
    infra_snapshot (list): A List object which contains all the backends in GCP
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    dict: Containing full description of the backend
    """

    for backends in infra_snapshot:
        healthy_nodes, unhealthy_nodes = check_healthy_instance_groups(backends, service)
        backends['healthy_nodes'] = healthy_nodes
        backends['unhealthy_nodes'] = unhealthy_nodes
    return infra_snapshot

def get_backend_info(backend_name, service):
    """
    Provides all information for a backend

    Parameters:
    backend_dict (dict): A dictionary object which is each item within the infra_snapshot
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    dict: Containing full description of the backend
    """
    initial_request = service.backendServices().get(project=GCP_PROJECT,
                                                    backendService=backend_name)
    raw_backend = initial_request.execute()

    return raw_backend

def remove_instance_group_from_backend(raw_backend, target_instance_group, service):
    """
    Remove an instance group from a backend
    Check to make sure the IG belongs to the backend, if it does, remove it

    Parameters:
    raw_backend (dict): The response to the get request, outlining all of attributes of the backend
    target_instance_group (str): The instance group that is to be removed
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    dict: The response to the removal of the instance group from the backend
    """
    # Make sure instance group to be removed belongs to that backend
    backend_name = raw_backend['name']
    backend_instance_groups = raw_backend['backends']

    for raw_instance_group in backend_instance_groups:
        if raw_instance_group['group'].split("/")[-1] == target_instance_group:
            backend_instance_groups.remove(raw_instance_group)
            break
    # Format the PATCH to remove just the single backend
    raw_backend['backends'] = backend_instance_groups


    # Push it
    remove_request = service.backendServices().patch(project=GCP_PROJECT,
                                                     backendService=backend_name,
                                                     body=raw_backend)
    remove_request.execute()

    message = "Removed {t} from {b}".format(t=target_instance_group,
                                            b=backend_name)
    status = "success"

    return (message, status)

def run_remove_instance_group(all_backends, instance_group_to_remove, service):
    """
    Run remove_instance_group_from_backend, which will remove an instance group from a backend

    Parameters:
    all_backends (list): A list object which contains all the backends in GCP
    instance_group_to_remove (list): A list of instance groups that should be removed,
    should only contain one item
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    dict: Containing full description of the backend without the removed instance group
    """

    infra_snapshot = run_instance_groups(all_backends, instance_group_to_remove, service)
    backend_list = [backend["backend_name"] for backend in infra_snapshot]

    if len(infra_snapshot) == 1 and len(instance_group_to_remove) == 1:
        backend_name = infra_snapshot[0]['backend_name']
        instance_group_name = instance_group_to_remove[0]

        raw_backend_info = get_backend_info(backend_name, service)

        found = False
        for raw_instance_group in raw_backend_info['backends']:
            if raw_instance_group['group'].split("/")[-1] == instance_group_name:
                found = True
                remove_request = remove_instance_group_from_backend(raw_backend_info,
                                                                    instance_group_name, service)
                message = remove_request[0]
                status = remove_request[1]
                break
        if not found:
            message = "Instance Group {i} not found in {b}".format(i=instance_group_name,
                                                                   b=backend_name)
            status = "failure"

    if len(infra_snapshot) == 0:
        message = "{i} doesn't belong to a backend, cant be removed.".format(i=instance_group_to_remove)
        status = "failure"

    elif len(instance_group_to_remove) > 1:
        message = "Too many instance groups specified: {i}".format(i=instance_group_to_remove)
        status = "failure"

    elif len(infra_snapshot) > 1:
        message = "Too many Backends in infra_snapshot: {i}".format(i=infra_snapshot)
        status = "failure"

    return_dict = {
        "action": "remove",
        "status": status,
        "message": message,
        "backend": backend_list,
        "instance_group": instance_group_to_remove
    }

    return return_dict

def add_instance_group_to_backend(raw_backend, target_instance_group, zone, service):
    """
    Add an instance group to a backend
    Then add the instance group to the backend

    Parameters:
    raw_backend (dict): The response to the get request, outlining all of attributes of the backend
    target_instance_group (str): The instance group that is to be added
    zone (str): The zone of the target_instance_group
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API

    Returns:
    dict: The response to the removal of the instance group from the backend
    """
    backend_name = raw_backend['name']
    # Format the PATCH to remove just the single backend
    try:
        backend_instance_groups = raw_backend['backends']
    except KeyError:
        backend_instance_groups = []

    instance_group_endpoint = 'https://www.googleapis.com/compute/v1/projects/' \
                              GCP_PROJECT + '/zones/' \
                              '{z}/instanceGroups/{t}'.format(z=zone,
                                                              t=target_instance_group)
    backend_instance_groups.append({'group': instance_group_endpoint,
                                    'balancingMode': 'RATE',
                                    'maxRatePerInstance': 1500,
                                    'capacityScaler': 1})
    raw_backend['backends'] = backend_instance_groups


    # Push it
    add_request = service.backendServices().patch(project=GCP_PROJECT,
                                                  backendService=backend_name,
                                                  body=raw_backend)
    add_request.execute()

    message = "Added {t} to {b}".format(t=target_instance_group, b=backend_name)
    status = "success"
    return (message, status)

def run_add_instance_group(instance_group_to_add, backend_to_append,
                           remaining_instance_groups, service, timeout=420):
    """
    Run add_instance_group_to_backend, which will add an instance group to a backend

    Parameters:
    instance_group_to_add (list): A list of instance groups that should be added,
    should only contain one item
    backend_to_append (list): A list of backends that instance group should be added to,
    should only contain one item
    remaining_instance_groups (list): A list of instance groups not being used by a backend
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API
    timeout (int): The amount of time in seconds to wait for the backend to be healthy

    Returns:
    list: Containing the infra_snapshot with the healthy and unhealthy nodes
    """
    if len(instance_group_to_add) == 1 and len(backend_to_append) == 1:
        logging.debug("Starting loop")
        found = False
        for instance_groups in remaining_instance_groups:
            # Checking to make sure instance group doesn't belong to a backend
            if instance_groups['instance_group_name'] == instance_group_to_add[0]:
                found = True
                instance_group_name = instance_groups['instance_group_name']
                instance_group_zone = instance_groups['zone']
                break
        if found:
            logging.debug("Found")
            backend_name = backend_to_append[0]
            raw_backend_info = get_backend_info(backend_name, service)
            logging.debug("Starting Add request")
            add_request = add_instance_group_to_backend(raw_backend_info,
                                                        instance_group_name,
                                                        instance_group_zone,
                                                        service)
            message = add_request[0]
            status = add_request[1]

            if status != "success":
                return_dict = {
                    "action": "add",
                    "status": status,
                    "message": message,
                    "backend": backend_to_append,
                    "instance_group": instance_group_to_add
                    }
                return return_dict

            logging.debug("Add request complete")

            all_healthy = False
            t_end = time.time() + timeout
            while time.time() < t_end and not all_healthy:
                all_backends = get_all_backends(service)
                infra_snapshot = run_instance_groups(all_backends, instance_group_to_add, service)
                # Give GCP some time to see the instances are present
                time.sleep(2)
                try:
                    infra_snapshot_health = run_check_health(infra_snapshot, service)
                except HealthCheckError:
                    continue
                for each_instance_group in infra_snapshot_health[0]['instance_group_info']:
                    if each_instance_group['instance_group_name'] == instance_group_name:
                        added_instance_list = each_instance_group['instances']
                unhealthy_node_number = len(infra_snapshot_health[0]['unhealthy_nodes'])
                healthy_node_number = len(infra_snapshot_health[0]['healthy_nodes'])

                if unhealthy_node_number == 0 and healthy_node_number >= len(added_instance_list):
                    all_healthy = True
                    message += " , all nodes healthy"
            if not all_healthy:
                message += ", All nodes not healthy"
                status = "failure"

        else:
            all_backends = get_all_backends(service)
            found_back = False
            for backends in all_backends:
                for instance_groups in backends['instance_group_info']:
                    if instance_groups['instance_group_name'] == instance_group_to_add[0]:
                        found_back = True
                        found_backend = backends['backend_name']

            if found_back:
                message = "{i} belongs to {b}, Instance group cannot" \
                " be in 2 backends!!".format(i=instance_group_to_add[0],
                                             b=found_backend)
                status = "failure"
            else:
                message = "{i} doesn't exist".format(i=instance_group_to_add[0])
                status = "failure"
    else:
        logging.debug("Loop skipped")
        message = "Correct number of backends and instance group not provided"
        message += " Backends: {b}".format(b=backend_to_append)
        message += " Instance Groups: {i}".format(i=instance_group_to_add)
        status = "failure"

    return_dict = {
        "action": "add",
        "status": status,
        "message": message,
        "backend": backend_to_append,
        "instance_group": instance_group_to_add
    }

    return return_dict


def run_infra_filter(all_backends, service, backend_filter=None,
                     instance_group_filter=None,
                     instance_filter=None):
    """
    Filter all_backends based on arguments provided

    Parameters:
    all_backends (dict): The backend dictionary containing all_backends you want to parse through
    service (oauth2client.client.AccessTokenCredentials): GCP service aobject to leverage API
    backend_filter (list): A list of backends to find within all_backends
    instance_group_filter (list): A list of instance groups to find within all_backends
    instance_filter (list): A list of instances to find within all_backends

    Returns:
    list: Containing only the backends with the specified instance groups
    """
    if backend_filter:
        infra_snapshot = run_backends(all_backends, backend_filter, service)
        return infra_snapshot

    if instance_group_filter:
        infra_snapshot = run_instance_groups(all_backends, instance_group_filter, service)
        return infra_snapshot

    if instance_filter:
        infra_snapshot = run_instance(all_backends, instance_filter, service)
        return infra_snapshot

    infra_snapshot = run_all(all_backends, service)
    return infra_snapshot

def main(raw_args=None):
    """
    Only one operation can be performed at a time
    The main function performs and returns a value based on the operation
    †hat is specified
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('--operation', help='Action for the script to do.',
                        action="store", choices=["return_args",
                                                 "print_active_backend_infra",
                                                 "create_inventory_object",
                                                 "print_grouped_infra",
                                                 "print_filter_infra",
                                                 "print_instance_groups_not_in_backends",
                                                 "print_all_infra",
                                                 "check_if_instance_group_is_active",
                                                 "check_health_filter",
                                                 "remove_instance_group_from_backend",
                                                 "add_instance_group_to_backend"],
                        default="create_inventory_object",)
    parser.add_argument('--instance_groups',
                        help='Name of the relevant instance group.',
                        nargs='+', type=str,
                        default=[],)
    parser.add_argument('--list', help='Used to print inventory_object for ansible',
                        action='store_true')
    parser.add_argument('--host', help='Used to filter inventory_object for ansible',
                        action='store', type=str)
    parser.add_argument('--instances', help='Name of the relevant instance.',
                        nargs='+', type=str, default=[],)
    parser.add_argument('--backends', help='Name of the relevant backend.',
                        type=str, nargs='+',
                        default=[],)
    # Edit this
    parser.add_argument('--gcp_cred', help='Path to the gcp_cred.json file.',
                        default="./gcp_cred.json",)
    parser.add_argument('--timeout', help='time to wait for instance group to be healthy',
                        type=int, default=420,)
    parser.add_argument('--client_name', help='Client name to group output by',
                        default="",)
    parser.add_argument('--env', help='env to group output by',
                        default="",)

    args = parser.parse_args(raw_args)

    global gcp_cred_FILE_PATH

    # Edit this
    """
    Instructions for creating gcp_cred.json in base repo
    This file is necessary for preliminary testing
    But will eventually be deprecated.
    """
    gcp_cred_FILE_PATH = find_gcp_file("gcp_cred.json", args.gcp_cred)

    if args.operation == "return_args":
        return args

    cred = load_json_credentials(gcp_cred_FILE_PATH)

    s_jwt = create_signed_jwt(
        cred['private_key'],
        cred['private_key_id'],
        cred['client_email'],
        GCE_SCOPES)

    try:
        token = exchange_jwt_for_access_token(s_jwt)["access_token"]
    except KeyError:
        logging.error("Invalid Acess Token Request: %s", exchange_jwt_for_access_token(s_jwt))
        return None #Change this to exit

    service = create_service_object(token)
    all_backends = get_all_backends(service)

    instance_groups_present = extract_instance_list_from_all_backends(all_backends)
    remaining_instance_groups = get_instances_groups_not_in_backends(instance_groups_present,
                                                                     service)


    if args.host:
        infra_snapshot = {}

    elif args.operation == "print_active_backend_infra":
        infra_snapshot = run_all(all_backends, service)

    elif args.operation == "print_grouped_infra":
        all_backends.append({
            'backend_name': "instance_groups_not_in_backends",
            'instance_group_info': remaining_instance_groups
        })
        infra_snapshot_tmp = run_all(all_backends, service)
        infra_object = create_inventory_object(infra_snapshot_tmp)
        grouped_output = group_infra(infra_object, client_name=args.client_name,
                                     env=args.env)

    elif args.operation == "create_inventory_object" or args.list:
        all_backends.append({
            'backend_name': "instance_groups_not_in_backends",
            'instance_group_info': remaining_instance_groups
        })
        infra_snapshot_tmp = run_all(all_backends, service)
        infra_snapshot = create_inventory_object(infra_snapshot_tmp)

    elif args.operation == "print_filter_infra":
        #If someone provides a backend, ig and instance then only a backend will be processed.
        #Can have multiple IG or backends when running a print but not for add or remove
        infra_snapshot = run_infra_filter(all_backends, service,
                                          args.backends, args.instance_groups,
                                          args.instances)

    elif args.operation == "print_instance_groups_not_in_backends":
        all_backends = []
        all_backends.append({
            'backend_name': "instance_groups_not_in_backends",
            'instance_group_info': remaining_instance_groups
        })
        infra_snapshot = run_all(all_backends, service)

    elif args.operation == "print_all_infra":
        all_backends.append({
            'backend_name': "instance_groups_not_in_backends",
            'instance_group_info': remaining_instance_groups
        })
        infra_snapshot = run_all(all_backends, service)

    elif args.operation == "check_if_instance_group_is_active":
        # Only check one instance group at a time
        if len(args.instance_groups) == 1:
            infra_snapshot = run_infra_filter(all_backends, service,
                                              instance_group_filter=args.instance_groups)
            if len(infra_snapshot) == 1:
                message = "{i} in {b}".format(i=args.instance_groups,
                                              b=infra_snapshot[0]['backend_name'])
                status = "success"
            elif len(infra_snapshot) == 0:
                message = "Instance group not active: {i}".format(i=args.instance_groups)
                status = "failure"
            elif len(infra_snapshot) > 1:
                message = "Instance group in too many backends"
                status = "failure"
        else:
            message = "Too many instance groups specified"
            status = "failure"

        check_active = {
            "message": message,
            "status": status
        }


    elif args.operation == "check_health_filter":
        infra_snapshot_tmp = run_infra_filter(all_backends, service,
                                              args.backends, args.instance_groups,
                                              args.instances)
        infra_snapshot = []
        for backends in infra_snapshot_tmp:
            try:
                infra_snapshot.extend(run_check_health([backends], service))
            except HealthCheckError:
                continue

    if args.operation == "remove_instance_group_from_backend":
        change_request = run_remove_instance_group(all_backends,
                                                   args.instance_groups, service)

    elif args.operation == "add_instance_group_to_backend":
        change_request = run_add_instance_group(args.instance_groups, args.backends,
                                                remaining_instance_groups,
                                                service, args.timeout)
    if "check_active" in locals():
        print(json.dumps(check_active, indent=2, sort_keys=True))
        return check_active
    if "infra_snapshot" in locals():
        print(json.dumps(infra_snapshot, indent=2, sort_keys=True))
        return infra_snapshot
    if "grouped_output" in locals():
        print(grouped_output)
        return grouped_output
    if "change_request" in locals():
        print(json.dumps(change_request, indent=2, sort_keys=True))
        return change_request

    return []

if __name__ == '__main__':
    main()
