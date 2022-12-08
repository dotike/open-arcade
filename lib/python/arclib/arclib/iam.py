# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
cli -- A library for common or uniform iam operations, particularly
things which we want to do consistently or often across all tools.
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "ARCADE common iam operations"
__version__ = '1.0.0'


import os
import sys
import boto3


# --------------------------------------------------------------------
#
# get_all_roles
#
# --------------------------------------------------------------------
def get_all_roles():
    '''
    Retrieve all roles account-wide by paginating boto3.list_roles()
    calls.  Returns a rich dictionary, keyed by 'RoleName', containing
    all the metadata we can get.
    '''
    roles_response = {}

    client = boto3.client('iam')
    role_paginator = client.get_paginator('list_roles')
    for response in role_paginator.paginate():
        for role_dict in response['Roles']:
          roles_response[role_dict['RoleName']] = role_dict
    return roles_response
    # End of get_all_roles


# --------------------------------------------------------------------
#
# get_all_roles
#
# --------------------------------------------------------------------
def get_policies_for_roles():
    """
    Takes some time to return:

    Create a rich dictionary of all policies, for all roles, by
    paginating over boto3.list_attached_role_policies() calls for
    each role name.  Returns a rich dictionary, keyed by 'RoleName',
    containing all the metadata we can get.

    Response identical to get_all_roles(), adding 'AttachedPolicies'.
    """
    role_list = get_all_roles()

    return_policy_map = {}

    client = boto3.client('iam')
    policy_paginator = client.get_paginator('list_attached_role_policies')
    for role_name in role_list.keys():
        return_policy_map[role_name] = role_list[role_name]
        for response in policy_paginator.paginate(RoleName=role_name):
            return_policy_map[role_name]['AttachedPolicies'] = response.get('AttachedPolicies')
    return return_policy_map
    # End of get_policies_for_roles

# --------------------------------------------------------------------
#
# id_user
#
# --------------------------------------------------------------------
def id_user(mfa=None):
    """
    A quick method to identify the calling user.
    Strips 'ResponseMetadata'.
    Adds 'UserName' dictionary key because AWS doesn't print it.
    """
    client = boto3.client('sts')
    response = client.get_caller_identity()
    response.pop('ResponseMetadata')
    response['UserName'] = response['Arn'].split('/')[-1].split('@')[0]

    if mfa:
        iam = boto3.client('iam')
        mfa_resp = iam.list_mfa_devices(
            UserName=response['UserName']
        )
        response['MFADevices'] = mfa_resp['MFADevices']


    return response


# --------------------------------------------------------------------
#
# list_users
#
# --------------------------------------------------------------------
def list_users(mfa=None):
    """
    Quick method to list all users in the account called.

    Input:
        mfa = option to make extra call to include MFA device list

    Output:
        Dict of user dicts, keyed by username
    """

    users_response = {}
    iam = boto3.client('iam')

    paginator = iam.get_paginator('list_users')
    for response in paginator.paginate():
        for userd in response.get('Users'):
            if mfa:
                mfa_resp = iam.list_mfa_devices(
                    UserName=userd['UserName']
                )
                userd['MFADevices'] = mfa_resp['MFADevices']

            users_response[userd['UserName']] = userd

        #print(response)
    return users_response



# --------------------------------------------------------------------
#
# get_user_roles
#
# --------------------------------------------------------------------
def get_user_roles(user_name=None):
    """
    Get all roles attached to a user, including inline roles.
    Return a dict of role data, keyed by role name.

    Input:
        user_name - optional user name, if none supplied the name
                    of the caller is used.
    """
    #if not user_name:
    #    user_name = grv.aws_whoami()

    #iam = boto3.resource('iam')
    #user_policy = iam.UserPolicy('user_name','name')

    sys.exit(44)
    # End of get_user_roles





