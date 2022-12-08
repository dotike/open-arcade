# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
vpc -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'

import sys
import common

# -----------------------------------------------------------------------
#
# get_vpc_id_by_name
#
# -----------------------------------------------------------------------
def get_vpc_id_by_name(common_dict):

    common.vprint("Getting VPC By Name")
    pp = common_dict['pp']
    ec2_client = common_dict['ec2_client']
    
    filters = [{'Name': 'tag:Name', 'Values': [common_dict['arcade_name']] }]
            
    response = ec2_client.describe_vpcs(Filters=filters)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        common_dict['response'] = response
        common_dict['vpc_response'] = response

        if common_dict['debug']:
            pp.pprint(response)
                    
        if len(response['Vpcs']) == 0:
            print(f"ERROR: VPC - {common_dict['arcade_name']} not found")
            sys.exit(1)

        common_dict['vpc_id'] = response['Vpcs'][0]['VpcId']
    else:
        print(f"ERROR: VPC - {common_dict['arcade_name']} not found")
        sys.exit(1)
        # End of if
    # End of if

    return 0
    #

# -----------------------------------------------------------------------
#
# get_vpc_id
#
# -----------------------------------------------------------------------
def get_vpc_id(common_dict):

    common.vprint("Getting VPC Id")
    pp = common_dict['pp']
    ec2_client = common_dict['ec2_client']
    
    response = ec2_client.describe_vpcs(VpcIds=[common_dict['vpc_id']])
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        common_dict['response'] = response
        common_dict['vpc_response'] = response

        if common_dict['debug']:
            pp.pprint(response)
                    
        if len(response['Vpcs']) == 0:
            print(f"ERROR: VPC {common_dict['vpc']} not found")
            sys.exit(1)
        Tags = response['Vpcs'][0]['Tags']
        for entry in Tags:
            if 'Name' in entry['Key']:
                arcadeName = entry['Value']
                common_dict['arcade_name'] = arcadeName
                break
            # End of for loop
        # End of if

    return 0
    #
