# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
inventory -- used to get info about resources in a given arcade
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.1'

import os
import sys
import json
import datetime
import boto3

from arclib import cli, common, msk

# Could use some cleaning up

# --------------------------------------------------------------------
#
# get_resource_info
#
# --------------------------------------------------------------------


def get_resource_info(arcade_name, inclusive, layer):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_class = common.ReturnStatus()

    common_dict = setup_common_dict(arcade_name, inclusive, layer)

    r_dict = get_grv_manifest(common_dict)
    if r_dict['status'] == rs_class.FAIL:
        print(f"\n\nERROR: {arcade_name} GRV manifest NOT found.\n\n")
        return arcade_name

    # Auto scale group - FIX
    r_dict = get_auto_scale_group_info(common_dict)

    # Instance - FIX
    r_dict = get_ec2_instances_info(common_dict)

    # EKS - OK
    r_dict = get_eks_info(common_dict)

    # EKS Nodegroup - OK
    r_dict = get_eks_nodegroup_info(common_dict)

    # Route53 - OK
    r_dict = get_hosted_zone_info(common_dict)

    # Route53 HealthChecks
    r_dict = get_healthcheck_info(common_dict)

    # doIgws - OK
    r_dict = get_internet_gateway_info(common_dict)

    # Key Pair - OK
    r_dict = get_key_pair_info(common_dict)

    # Load balancer - FIX
    r_dict = get_load_balancer_info(common_dict)

    # Target Groups - OK
    r_dict = get_target_group_info(common_dict)

    # MSK - FIX
    r_dict = get_msk_info(common_dict)

    # Network ACL - MIA
    r_dict = get_network_acl_info(common_dict)

    # Network Interfaces - OK
    r_dict = get_network_interface_info(common_dict)

    # Parameter Store - Untested for now
    # r_dict = get_parameter_store(common_dict)

    # RDS Instances
    r_dict = get_rds_instance_info(common_dict)

    # Route table - OK
    r_dict = get_route_table_info(common_dict)

    # Secutity Group - OK
    r_dict = get_security_group_info(common_dict)

    # Subnet - FIX
    r_dict = get_subnet_info(common_dict)

    # S3 Bucket List - OK
    r_dict = get_s3_bucket_list(common_dict)

    # S3 - OK
    r_dict = get_s3_info(common_dict)

    # Secrets - OK
    r_dict = get_secrets_info(common_dict)

    # IAM Roles - FIX
    r_dict = get_iam_roles_info(common_dict)

    # Lambda Function - Not well tested. May need pagination
    r_dict = get_lambda_function_info(common_dict)

    # Elastic IPS - Only Gets ARNs
    r_dict = get_eip_info(common_dict)

    # NAT Gateways - OK
    r_dict = get_nat_gateway_info(common_dict)

    # End points - OK
    r_dict = get_vpc_end_points_info(common_dict)

    # VPC - FIX
    r_dict = get_vpc_info(common_dict)

    if r_dict['status'] == rs_class.FAIL:
        print(f"\n\nERROR: {arcade_name} failure.\n\n")
        sys.exit(rs_class.FAIL)

    return common_dict
    # End of get_resource_info

# --------------------------------------------------------------------
#
# do_thic_func
#
# --------------------------------------------------------------------


def do_this_func(stack, func_name, stack_layer):
    """
    tmp string
    what

    Args:

    Returns:
    """
    do_it = False

    for entry in stack:
        layer = entry['layer']
        default = entry['default']
        inclusive = entry['inclusive']

        if stack_layer in layer:
            if 'gravitar' in layer:
                if func_name in default:
                    do_it = True
                    break
                elif func_name in inclusive:
                    do_it = True
                    break
                # End of if
            else:
                if func_name in default:
                    do_it = True
                    break
            # End of if
        # End of if
    # End of for loop

    return do_it
    # End of do_this_func

# --------------------------------------------------------------------
#
# my_name_is
#
# --------------------------------------------------------------------


def my_name_is():
    """
    This function returns the name of the function that invokes it.

    Args:
        None

    Returns:
        my_name: The name of the calling function
    """
    # Slim Shady

    my_name = sys._getframe(1).f_code.co_name

    return my_name
    # End of my_name_is

# --------------------------------------------------------------------
#
# build_inventory_dict
#
# --------------------------------------------------------------------


def build_inventory_dict(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    #rs_defines       = common_dict['rs_defines']
    inv_dict = common_dict['inv_dict']
    tags = common_dict['tags']

    inclusive = common_dict['inclusive']
    inv_dict['inclusive'] = inclusive

    layer = common_dict['layer']
    inv_dict['layer'] = layer

    inventory_data = {}
    inventory_data['vpc_creator'] = common_dict['vpc_creator']
    inventory_data['vpc_creation_date'] = common_dict['vpc_creation_date']
    inventory_data['vpc_id'] = common_dict['vpc_id']
    inventory_data['owner_id'] = common_dict['owner_id']
    inventory_data['layer'] = layer
    inventory_data['inclusive'] = inclusive

    now = datetime.datetime.now()
    t_s = datetime.datetime.now().timestamp()

    dt_string = now.strftime("%d-%b-%Y %H:%M:%S")
    inventory_data['inventory_created_date'] = dt_string
    inventory_data['inventory_created_date_epoch'] = str(int(t_s))

    inv_dict['inventory_data'] = inventory_data

    for entry in tags.keys():
        if common_dict['tags'][entry] == 'yes':
            inv_dict[entry] = common_dict[entry]

    return inv_dict
    # End of build_inventory_dict

# --------------------------------------------------------------------
#
# setup_common_dict
#
# --------------------------------------------------------------------


def setup_common_dict(arcade_name, inclusive, layer):
    """
    temp string
    what

    Args:

    Returns:
    """

    common_dict = {}
    rs_defines = common.ReturnStatus()

    common_dict['envConfig'] = dict(os.environ)

    common_dict['arcade_name'] = arcade_name
    common_dict['toolName'] = os.path.basename(__file__)
    common_dict['inclusive'] = inclusive
    common_dict['layer'] = layer
    common_dict['rs_defines'] = rs_defines
    common_dict['status'] = rs_defines.OK

    myhier = os.getenv('MYHIER')  # TODO: remove need for this
    if myhier is None:
        print("ERROR: MYHIER not set. Try again")
        sys.exit(1)

    base_path = f"{myhier}/etc"
    in_file = f"{base_path}/inventory-config.json"

    with open(in_file, 'r') as file_handle:
        j_str = json.load(file_handle)

    stack = j_str['resources'][0]['stack']
    common_dict['stack'] = stack

    profiles = j_str['profiles']
    common_dict['account_profiles'] = profiles

    tags = j_str['tags']
    common_dict['tags'] = tags

    # find the VPC tagged with the arcade name
    return_status = get_vpc_id_by_name(common_dict)
    if return_status == rs_defines.OK:
        vpc_dict = common_dict['vpc_response']
        common_dict['vpc_dict'] = vpc_dict
    # else:
    # VPC NOT FOUND

    for entry in profiles:
        #name     = entry['name']
        default = entry['default']
        owner_id = entry['owner_id']
        if 'yes' in default:
            common_dict['owner_id'] = owner_id
            common_dict['defaultProfile'] = 'default'
            common_dict['defaultOwnerId'] = owner_id
            break

    common_dict['debug'] = False

    common_dict['regions'] = ['us-east-1',
                              'us-east-2',
                              'us-west-1',
                              'us-west-2']

    common_dict['defaultRegion'] = 'us-east-2'
    common_dict['version'] = '__version__'

    inv_dict = dict({'arcade_name': arcade_name,
                     'owner_id': common_dict['owner_id'],
                     'vpc_id': common_dict['vpc_id'],
                     'vpc_creator': common_dict['vpc_creator'],
                     'vpc_creation_date': common_dict['vpc_creation_date']})

    common_dict['inv_dict'] = inv_dict

    return common_dict
    # End of setup_common_dict

# -----------------------------------------------------------------------
#
# get_vpc_id_by_name
#
# -----------------------------------------------------------------------


def get_vpc_id_by_name(common_dict):
    """
    This goes into vpc.py
    what

    Args:

    Returns:
    """

    cli.vprint("Getting VPC By Name")
    rs_defines = common_dict['rs_defines']

    filters = [{'Name': 'tag:Name', 'Values': [common_dict['arcade_name']]}]

    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_vpcs(Filters=filters)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        common_dict['response'] = response
        common_dict['vpc_response'] = response

        if len(response['Vpcs']) == 0:
            print(f"ERROR: VPC - {common_dict['arcade_name']} not found")
            sys.exit(rs_defines.NOT_OK)

        common_dict['vpc_id'] = response['Vpcs'][0]['VpcId']
        common_dict['vpc_info'] = response['Vpcs'][0]

        tags = response['Vpcs'][0]['Tags']
        for entry in tags:
            key = entry['Key']
            value = entry['Value']
            if key == 'creation_date':
                common_dict['vpc_creation_date'] = value

            if key == 'creator':
                common_dict['vpc_creator'] = value
    else:
        print(f"ERROR: VPC - {common_dict['arcade_name']} not found")
        sys.exit(rs_defines.NOT_OK)
        # End of if
    # End of if

    return rs_defines.OK
    # End of get_vpc_id_by_name

# -----------------------------------------------------------------------
#
# get_vpc_id
#
# -----------------------------------------------------------------------


def get_vpc_id(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    cli.vprint("Getting VPC Id")
    rs_defines = common_dict['rs_defines']

    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_vpcs(VpcIds=[common_dict['vpc_id']])
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        common_dict['response'] = response
        common_dict['vpc_response'] = response

        if len(response['Vpcs']) == 0:
            print(f"ERROR: VPC {common_dict['vpc']} not found")
            sys.exit(1)
        tags = response['Vpcs'][0]['Tags']
        for entry in tags:
            if 'Name' in entry['Key']:
                arcade_name = entry['Value']
                common_dict['arcade_name'] = arcade_name
                break
            # End of for loop
        # End of if

    return rs_defines.OK
    # End of get_vpc_id

# --------------------------------------------------------------------
#
# Begin info functions
#
# --------------------------------------------------------------------


# --------------------------------------------------------------------
#
# get Internet Gateway Info
#
# --------------------------------------------------------------------
def get_internet_gateway_info(common_dict: dict) -> dict:
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting Internet Gateway Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        reply_list = []

        ec2_client = boto3.client('ec2')

        owner_id = common_dict['owner_id']
        arcade_name = common_dict['arcade_name']

        filters = [{'Name': 'owner-id', 'Values': [owner_id]}]
        response = ec2_client.describe_internet_gateways(
            Filters=filters, MaxResults=100)

        internet_gateways = response['InternetGateways']
        for entry1 in internet_gateways:
            tags = entry1['Tags']
            for entry2 in tags:
                key = entry2['Key']
                value = entry2['Value']
                if 'Name' in key:
                    if arcade_name in value:
                        reply_list.append(entry1)
                        break
                    # End of if
                # End of if
            # End of for
        # End of for

        common_dict['internet_gateways'] = reply_list
        common_dict['tags']['internet_gateways'] = 'yes'

        r_dict['data'] = reply_list
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_internet_gateway_info


# --------------------------------------------------------------------
#
# get Subnet Info
#
# --------------------------------------------------------------------
def get_subnet_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']

    r_dict = common.gen_return_dict("Getting VPC subnet Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        ec2_client = boto3.client('ec2')
        vpc_id = common_dict['vpc_id']

        filters = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
        response = ec2_client.describe_subnets(Filters=filters)
        subnet_dict = response['Subnets']

        common_dict['vpc_subnets'] = subnet_dict
        common_dict['tags']['vpc_subnets'] = 'yes'

        r_dict['data'] = subnet_dict
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_subnet_info


# --------------------------------------------------------------------
#
# get_msk_info
#
# --------------------------------------------------------------------
def get_msk_info(common_dict):
    """
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting MSK Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        kafka_client = boto3.client('kafka')
        arcade_name = common_dict['arcade_name']

        r_dict = get_msk_cluster_arn(arcade_name)
        if r_dict['status'] == rs_defines.OK:
            cluster_arn = r_dict['data']

            response = kafka_client.describe_cluster(ClusterArn=cluster_arn)
            cluster_info = response['ClusterInfo']

            time_value = cluster_info['CreationTime']
            cluster_info['CreationTime'] = common.convert_date_time(
                time_value)

            common_dict['msk'] = cluster_info
            common_dict['tags']['msk'] = 'yes'

            r_dict['status'] = rs_defines.OK
            r_dict['msg'] = 'MSK cluster info found'
            r_dict['data'] = cluster_info
        else:
            r_dict['status'] = rs_defines.NOT_FOUND
            r_dict['msg'] = 'Cluster ARN not found'
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_msk_info


# --------------------------------------------------------------------
#
# get MSK cluster ARN
#
# --------------------------------------------------------------------
def get_msk_cluster_arn(arcade_name):
    """
    """
    rs_defines = common.ReturnStatus()
    r_dict = common.gen_return_dict('Getting MSK cluster ARN')

    cluster_arn = ''

    kafka_client = boto3.client('kafka')

    cluster_name = arcade_name.replace('_', '').replace('.', '-')
    cluster_name = f"asteroids-{cluster_name}"

    status_dict = msk.get_msk_status(cluster_name)
    if len(status_dict) > 0:
        if status_dict['State'] == 'ACTIVE':
            try:
                Response = kafka_client.list_clusters()
                ClusterInfo = Response['ClusterInfoList']
            except (Kafka.Client.exceptions.BadRequestException,
                    Kafka.Client.exceptions.InternalServerErrorException,
                    Kafka.Client.exceptions.UnauthorizedException,
                    Kafka.Client.exceptions.ForbiddenException) as err:
                r_dict['status'] = rs_defines.FAIL
                r_dict['data'] = err
                r_dict['msg'] = 'Error failed to list clusters'
            # End of try block

            if r_dict['status'] == rs_defines.OK:
                for entry in ClusterInfo:
                    if entry['ClusterName'] == cluster_name:
                        cluster = entry
                        break
                # End of for loop

                cluster_arn = cluster['ClusterArn']
            # end of if
        else:
            r_dict['status'] = rs_defines.NOT_FOUND
            r_dict['msg'] = 'MSK cluster not found'
            r_dict['data'] = {}
        # End of if

        r_dict['msg'] = "Got the Cluster ARN"
        r_dict['data'] = cluster_arn
    else:
        r_dict['status'] = rs_defines.NOT_FOUND
        r_dict['msg'] = 'MSK cluster not found'
        r_dict['data'] = {}

    return r_dict
    # End of get_msk_cluster_arn

# --------------------------------------------------------------------
#
# get VPC End Points Info
#
# --------------------------------------------------------------------


def get_vpc_end_points_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting End Points Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        ec2_client = boto3.client('ec2')
        vpc_id = common_dict['vpc_id']

        filters = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
        try:
            response = ec2_client.describe_vpc_endpoints(Filters=filters)
            vpc_endpoints = response['VpcEndpoints']
            time_value = vpc_endpoints[0]['CreationTimestamp']
            vpc_endpoints[0]['CreationTimestamp'] = common.convert_date_time(
                time_value)
        except:
            r_dict['status'] = rs_defines.FAIL
            r_dict['msg'] = f"{my_name} failed"
            return r_dict

        common_dict['vpc_end_points'] = vpc_endpoints
        common_dict['tags']['vpc_end_points'] = 'yes'

        r_dict['data'] = vpc_endpoints
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_vpc_end_points_info


# --------------------------------------------------------------------
#
# get Key Pair Info
#
# --------------------------------------------------------------------
def get_key_pair_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Key Pair Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        entry = ''
        arcade_name = common_dict['arcade_name']
        ec2 = boto3.client('ec2')
        response = ec2.describe_key_pairs()
        key_pairs = response['KeyPairs']
        for entry in key_pairs:
            key_name = entry['KeyName']
            if arcade_name in key_name:
                common_dict['key_pair'] = entry
                break

        r_dict['data'] = entry
        common_dict['tags']['key_pair'] = 'yes'
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_key_pair_info


# ---------------------------------------------------------
#
# get Security Group Info
#
# ---------------------------------------------------------
def get_security_group_info(common_dict):
    """
    getSecurityGroup

    Args:
        D - a 'global' dict

    Returns:
        None

    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Security Group Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        ec2_client = boto3.client('ec2')

        vpc_id = common_dict['vpc_id']
        #arcadeName = common_dict['arcade_name']
        sg_list = []

        filters = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
        response = ec2_client.describe_security_groups(Filters=filters)

        security_groups = response['SecurityGroups']
        if len(security_groups) > 0:
            for entry in security_groups:
                group_id = entry['GroupId']
                #groupName = entry['GroupName']
                sg_list.append(group_id)

        common_dict['security_group_list'] = sg_list
        common_dict['security_groups'] = security_groups
        common_dict['tags']['security_groups'] = 'yes'

        r_dict['data'] = security_groups
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_security_group_info


# ---------------------------------------------------------
#
# get Route Table Info
#
# ---------------------------------------------------------
def get_route_table_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Route Table Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        ec2_client = boto3.client('ec2')
        vpc_id = common_dict['vpc_id']
        #arcadeName = common_dict['arcade_name']
        route_table_list = []

        filters = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
        response = ec2_client.describe_route_tables(Filters=filters)

        route_tables = response['RouteTables']
        if len(route_tables) > 0:
            for entry in route_tables:
                route_table_id = entry['RouteTableId']
                route_table_list.append(route_table_id)

        common_dict['route_table_list'] = route_table_list
        common_dict['route_tables'] = route_tables
        common_dict['tags']['route_tables'] = 'yes'

        r_dict['data'] = route_tables
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_route_table_info


# ---------------------------------------------------------
#
# get EC2 Instances Info
#
# ---------------------------------------------------------
def get_ec2_instances_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting EC2 Instance Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        instance_list = []
        master_list = []

        ec2_client = boto3.client('ec2')

        filters = [{'Name': 'tag:grv_name',
                    'Values': [common_dict['arcade_name']]}]
        response = ec2_client.describe_instances(Filters=filters)

        reservations = response['Reservations']
        if len(reservations) > 0:
            for entry in reservations:

                # ['Instances'][0]['LaunchTime']
                time_value = entry['Instances'][0]['LaunchTime']
                entry['Instances'][0]['LaunchTime'] = common.convert_date_time(
                    time_value)

                # ['Instances'][0]['UsageOperationUpdateTime']
                time_value = entry['Instances'][0]['UsageOperationUpdateTime']
                entry['Instances'][0]['UsageOperationUpdateTime'] = \
                    common.convert_date_time(time_value)

                # ['Instances'][0]['BlockDeviceMappings'][0]['Ebs']['AttachTime']
                time_value = entry['Instances'][0]['BlockDeviceMappings'][0]['Ebs']['AttachTime']
                entry['Instances'][0]['BlockDeviceMappings'][0]['Ebs']['AttachTime'] = \
                    common.convert_date_time(time_value)

                # ['Instances'][0]['NetworkInterfaces'][0]['Attachment']['AttachTIme']
                time_value = entry['Instances'][0]['NetworkInterfaces'][0]['Attachment']['AttachTime']
                entry['Instances'][0]['NetworkInterfaces'][0]['Attachment']['AttachTime'] = \
                    common.convert_date_time(time_value)

                master_list.append(entry)
                instance_id = entry['Instances'][0]['InstanceId']
                instance_list.append(instance_id)

        common_dict['instanceList'] = instance_list
        common_dict['ec2_instance'] = master_list
        common_dict['tags']['ec2_instance'] = 'yes'

        r_dict['data'] = master_list
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_ec2_instances_info


# ---------------------------------------------------------
#
# get Auto Scale Group Info
#
# ---------------------------------------------------------
def get_auto_scale_group_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Auto Scale Group Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        arcade_name = common_dict['arcade_name'].replace('.', '-')
        asg_list = []
        master_list = []
        as_client = boto3.client('autoscaling')
        response = as_client.describe_auto_scaling_groups()
        #HTTPStatusCode = response['ResponseMetadata']['HTTPStatusCode']

        as_groups = response['AutoScalingGroups']
        for entry1 in as_groups:
            auto_scaling_group_name = entry1['AutoScalingGroupName']
            tags = entry1['Tags']
            for entry2 in tags:
                if arcade_name in entry2['Value']:
                    asg_list.append(auto_scaling_group_name)
                    time_value = entry1['CreatedTime']
                    entry1['CreatedTime'] = common.convert_date_time(
                        time_value)
                    master_list.append(entry1)

        common_dict['auto_scale_group_list'] = asg_list
        common_dict['auto_scale_groups'] = master_list
        common_dict['tags']['auto_scale_groups'] = 'yes'

        r_dict['data'] = master_list
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_auto_scale_group_info


# ---------------------------------------------------------
#
# get EKS Info
#
# ---------------------------------------------------------
def get_eks_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting EKS Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        arcade_name = common_dict['arcade_name'].replace('.', '-')
        eks_list = []
        common_dict['eks_cluster'] = ""

        eks_client = boto3.client('eks')

        response = eks_client.list_clusters()
        clusters = response['clusters']
        for entry in clusters:
            if arcade_name in entry:
                common_dict['eks_name'] = entry
                eks_list.append(entry)

        if len(eks_list) > 0:
            response = eks_client.describe_cluster(
                name=common_dict['eks_name'])
            cluster = response['cluster']
            time_value = cluster['createdAt']
            cluster['createdAt'] = common.convert_date_time(time_value)

            common_dict['tags']['eks_cluster'] = 'yes'
            common_dict['eks_cluster'] = cluster
            r_dict['data'] = cluster
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_eks_info


# ---------------------------------------------------------
#
# get EKS Nodegroup Info
#
# ---------------------------------------------------------
def get_eks_nodegroup_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting EKS Nodegroup Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        #arcadeName = common_dict['arcade_name'].replace('.', '-')
        if 'eks_cluster' in common_dict and len(common_dict['eks_cluster']) > 0:
            cluster_name = common_dict['eks_cluster']['name']
            eks_client = boto3.client('eks')
            response = eks_client.list_nodegroups(clusterName=cluster_name)
            try:
                nodegroup = response['nodegroups'][0]
                arn = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)
                common_dict['eks_nodegroup'] = nodegroup
                common_dict['eks_nodegroup_arn'] = arn['nodegroup']['nodegroupArn']
                common_dict['tags']['eks_nodegroup'] = 'yes'
                common_dict['tags']['eks_nodegroup_arn']= 'yes'
                r_dict['data'] = response
            except:
                r_dict['status'] = rs_defines.FAIL
                r_dict['msg'] = f"{my_name} failed"
                return r_dict
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_eks_nodegroup_info


# ---------------------------------------------------------
#
# get Load Balancer Info
#
# ---------------------------------------------------------
def get_load_balancer_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Load Balancer Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        vpc_id = common_dict['vpc_id']
        lb_list = []
        master_list = []

        elb_client = boto3.client('elbv2')

        load_balancers = elb_client.describe_load_balancers(PageSize=400)
        for load_balancer in load_balancers["LoadBalancers"]:
            if load_balancer['VpcId'] == vpc_id:
                time_value = load_balancer['CreatedTime']
                load_balancer['CreatedTime'] = common.convert_date_time(
                    time_value)
                master_list.append(load_balancer)
                lb_arn = load_balancer['LoadBalancerArn']
                lb_list.append(lb_arn)

        common_dict['lbList'] = lb_list
        common_dict['load_balancer'] = master_list
        common_dict['tags']['load_balancer'] = 'yes'

        r_dict['data'] = master_list
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End og get_load_balancer_info


# ---------------------------------------------------------
#
# get Hosted Zone Info
#
# ---------------------------------------------------------
def get_hosted_zone_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Hosted Zone Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        zone_id = ''

        r53_client = boto3.client('route53')
        arcade_name = common_dict['arcade_name']
        dns_name = arcade_name.replace('_', '-')

        response = r53_client.list_hosted_zones_by_name(
            DNSName=dns_name,
            MaxItems='100')

        hosted_zones = response['HostedZones']

        for entry in hosted_zones:
            name = entry['Name']
            if name.endswith('.arc.'):
                name = name.replace('.arc.', '.arc')

            if name == dns_name or name == arcade_name:
                common_dict['hosted_zone'] = entry
                zone_id = entry['Id']
                break

        try:
            response = r53_client.list_resource_record_sets(
                HostedZoneId=zone_id)
        except:
            r_dict['status'] = rs_defines.FAIL
            r_dict['msg'] = f"{my_name} Failed"
            return r_dict

        hosted_zone_records = response['ResourceRecordSets']

        common_dict['hosted_zone_records'] = hosted_zone_records
        common_dict['tags']['hosted_zone'] = 'yes'
        common_dict['tags']['hosted_zone_records'] = 'yes'

        r_dict['data'] = common_dict['hosted_zone']
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_hosted_zone_info


# ---------------------------------------------------------
#
# get S3 Info - FIX
#
# ---------------------------------------------------------
def get_s3_info(common_dict):
    """
    tmp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting S3 Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        r_dict['data'] = ''
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
        r_dict['data'] = ''

    return r_dict
    #

# ---------------------------------------------------------
#
# get grv manifest
#
# ---------------------------------------------------------


def get_grv_manifest(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting grv manifest")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        #s3List = []

        s3_name = common_dict['arcade_name'].replace('.arc', '')
        s3_name = s3_name.replace('_', '')
        common_dict['s3_name'] = s3_name

        bucket_name = ""
        gravitar_manifest = ""
        manifest_found = False

        s3_client = boto3.client('s3')
        s3_resource = boto3.resource('s3')
        response = s3_client.list_buckets()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            buckets = response['Buckets']
            for entry in buckets:
                if s3_name in entry['Name']:
                    if 'infrastructure' in entry['Name']:
                        bucket_name = entry['Name']
                        manifest_found = True
                        break
                    # End of if
                # End of if
            # End of for

            if manifest_found:
                bucket = s3_resource.Bucket(bucket_name)
                for obj in bucket.objects.all():
                    key = obj.key
                    if 'gravitar' in key:
                        body = obj.get()['Body'].read()
                        gravitar_manifest = json.loads(body.decode("utf-8"))
                        break
                    # End of if
                # End of for
            # End of if

        if len(gravitar_manifest) > 0:
            common_dict['gravitar_manifest'] = gravitar_manifest
            common_dict['tags']['gravitar_manifest'] = 'yes'
            r_dict['status'] = rs_defines.OK
        else:
            r_dict['msg'] = "ERROR: gravitar manifest not found !"
            r_dict['status'] = rs_defines.FAIL
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    if r_dict['status'] == rs_defines.OK:
        r_dict['data'] = gravitar_manifest
    else:
        r_dict['data'] = ''

    return r_dict
    # End of get_grv_mainfest


# --------------------------------------------------------------------
#
# get IAM Roles Info - FIX
#
# --------------------------------------------------------------------
def get_iam_roles_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting IAM roles Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        marker = ''
        iam_client = boto3.client('iam')
        response = iam_client.list_roles()

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            if response['IsTruncated']:
                marker = response['Marker']
            roles = response['Roles']
            for entry in roles:
                pass
        else:
            r_dict['data'] = ''

    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_iam_roles_info


# --------------------------------------------------------------------
#
# get Network ACL Info
#
# --------------------------------------------------------------------
def get_network_acl_info(common_dict):
    """
    temp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting network ACL info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        network_acl_list = []
        vpc_id = common_dict['vpc_id']

        ec2_client = boto3.client('ec2')

        filters = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
        response = ec2_client.describe_network_acls(Filters=filters)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            if 'NextToken' in response:
                next_token = response['NextToken']
                if len(next_token) == 0:
                    pass

            network_acls = response['NetworkAcls']
            for entry in network_acls:
                network_acl_list.append(entry)
        else:
            r_dict['status'] = rs_defines.NOT_OK
            r_dict['msg'] = "Call to describe_network_acls did not return 200"

        common_dict['network_acl'] = network_acl_list
        common_dict['tags']['network_acl'] = 'yes'
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    r_dict['data'] = network_acl_list

    return r_dict
    # End of get_network_acl_info

# --------------------------------------------------------------------
#
# get_vpc_info - FIX
#
# --------------------------------------------------------------------


def get_vpc_info(common_dict):
    """
    tmp string
    what

    Args:

    Returns:
    """

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting VPC Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])
    if do_this:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_vpcs(VpcIds=[common_dict['vpc_id']])
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:

            common_dict['tags']['vpc'] = 'yes'
            common_dict['vpc'] = response['Vpcs']
            r_dict['data'] = response['Vpcs']
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict
    # End of get_vpc_info


# --------------------------------------------------------------------
#
# get_s3_bucket_list
#
# --------------------------------------------------------------------
def get_s3_bucket_list(common_dict):
    """
    Do we want the contents of the buckets dumped or
    just a list of the buckets

    For now, let's just get a list of buckets. We can
    add a seperate function for bucket contents.

    Args:

    Returns:
    """
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting VPC Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])
    if do_this:
        s3_name = common_dict['arcade_name'].replace(
            '.arc', '').replace('_', '')
        s3_client = boto3.client('s3')
        bucket_dict = {}
        response = s3_client.list_buckets()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            buckets = response['Buckets']
            for entry in buckets:
                if s3_name in entry['Name']:
                    common_dict['tags']['s3_buckets'] = 'yes'
                    bucket_dict[entry['Name']] = entry
                    # End of if
                # End of if
            # End of for
            common_dict["s3_buckets"] = bucket_dict

    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict

# --------------------------------------------------------------------
#
# get_eip_info
#
# --------------------------------------------------------------------


def get_eip_info(common_dict):

    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Elastic IP Info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])
    if do_this:
        tagging_client = boto3.client('resourcegroupstaggingapi')

        response = tagging_client.get_resources(TagFilters=[{'Key': 'grv_name',
                                                             'Values': [common_dict['arcade_name']]}],
                                                ResourceTypeFilters=['ec2:elastic-ip'])
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            common_dict['tags']['eips'] = 'yes'
            common_dict['eips'] = response['ResourceTagMappingList']
            r_dict['data'] = response['ResourceTagMappingList']
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"

    return r_dict

# --------------------------------------------------------------------
#
# get_nat_gateway_info
#
# --------------------------------------------------------------------


def get_nat_gateway_info(common_dict):  # nat gateways
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting NAT Gateway Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'],
                           my_name,
                           common_dict['layer'])

    if do_this:
        reply_list = []

        ec2_client = boto3.client('ec2')

        vpc_id = common_dict['vpc_id']
        filters = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
        response = ec2_client.describe_nat_gateways(
            Filters=filters, MaxResults=100)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            common_dict['nat_gateways'] = response['NatGateways']
            common_dict['tags']['nat_gateways'] = 'yes'

        r_dict['data'] = reply_list
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict

# --------------------------------------------------------------------
#
# get_secrets_info
#
# --------------------------------------------------------------------


def get_secrets_info(common_dict):
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting Secrets ARNs')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'], my_name,
                           common_dict['layer'])

    if do_this:
        reply_list = []

        sm_client = boto3.client('secretsmanager')

        arcade_name = common_dict['arcade_name'].replace(".arc", "")
        filters = [{'Key': 'name', 'Values': [arcade_name]}]
        response = sm_client.list_secrets(Filters=filters)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            common_dict['secrets'] = response['SecretList']
            common_dict['tags']['secrets'] = 'yes' 

        r_dict['data'] = reply_list
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict

# --------------------------------------------------------------------
#
# get_parameter_info
#
# --------------------------------------------------------------------


def get_parameter_info(common_dict):
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting Parameter Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'], my_name,
                           common_dict['layer'])

    if do_this:
        reply_list = []

        sm_client = boto3.client('secretsmanager')

        arcade_name = common_dict['arcade_name'].replace(".arc", "")
        filters = [{'Key': 'name', 'Option': 'Contains',
                    'Values': [arcade_name]}]
        response = sm_client.describe_parameters(Filters=filters)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            common_dict['parameters'] = response['Parameters']
            common_dict['tags']['parameters'] = 'yes'

        r_dict['data'] = reply_list
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict


def get_rds_instance_info(common_dict):
    """
    get_rds_instance_info - does what its name implies
    """
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting RDS Instance Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'], my_name,
                           common_dict['layer'])

    if do_this:
        instance_list = []
        arcade_name = common_dict["arcade_name"]
        vpc_id = common_dict["vpc_id"]
        arcade_name = arcade_name.replace("_", "").replace(".arc", "")
        try:
            rds_client = boto3.client('rds')
            resp = rds_client.describe_db_instances()
            # checking if it belongs to the arcade. Another approach would be to compare sg's or vpcs
            for entry in resp["DBInstances"]:
                if entry["DBSubnetGroup"]["VpcId"] == vpc_id:
                    instance_list.append(entry)
            if len(instance_list) > 0:
                common_dict['rds_instance'] = instance_list
                common_dict['tags']['rds_instance'] = 'yes'
        except:
            r_dict['status'] = rs_defines.FAIL
            r_dict['msg'] = f"{my_name} failed"
            return r_dict
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict


def get_network_interface_info(common_dict):
    """
    get_network_interface_info -  instances give some but not all, so this is needed
    """
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Network Interface info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'], my_name,
                           common_dict['layer'])
    if do_this:
        vpc_id = common_dict["vpc_id"]
        try:
            ec2_client = boto3.client("ec2")
            resp = ec2_client.describe_network_interfaces(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id]
                    }
                ]
            )
            if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
                common_dict['network_interfaces'] = resp['NetworkInterfaces']
                common_dict['tags']['network_interfaces'] = 'yes'
        except:
            r_dict['status'] = rs_defines.FAIL
            r_dict['msg'] = f"{my_name} failed"
            return r_dict
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict


def get_target_group_info(common_dict):
    """
    get_target_group_info - gets load balancer target groups. Since they are
    sometimes created but not assigned, we can't just use the output of the
    auto_scale_groups or load_balancer info.
    """
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict('Getting Target Group Info')

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'], my_name,
                           common_dict['layer'])

    if do_this:
        grp_list = []

        elb_client = boto3.client('elbv2')
        arcade_name = common_dict['arcade_name'].replace(".arc", "")
        arcade_name = arcade_name.replace("_", "")
        response = elb_client.describe_target_groups()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            # loop through
            for grp in response['TargetGroups']:
                if arcade_name in grp['TargetGroupName']:
                    grp_list.append(grp)
            common_dict['target_groups'] = grp_list
            common_dict['tags']['target_groups'] = 'yes'
        else:
            r_dict['status'] = rs_defines.FAIL
            r_dict['msg'] = f"{my_name} failed"
            return r_dict
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict


def get_lambda_function_info(common_dict):
    """
    get_lambda_function_info - not well tested.
    """
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Lambda Function info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'], my_name,
                           common_dict['layer'])
    if do_this:
        func_list = []
        vpc_id = common_dict["vpc_id"]
        try:
            lambda_client = boto3.client("lambda")
            resp = lambda_client.list_functions()
            if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
                for func in resp["Functions"]:
                    if vpc_id in func['VpcConfig']['VpcId']:
                        func_list.append(func)
                if len(func_list) > 0:
                    common_dict['lambda_functions'] = func_list
                    common_dict['tags']['lambda_functions'] = 'yes'
        except:
            r_dict['status'] = rs_defines.FAIL
            r_dict['msg'] = f"{my_name} failed"
            return r_dict
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict


def get_healthcheck_info(common_dict):
    """
    get_healthcheck_info - gross because uses pagination
    """
    rs_defines = common_dict['rs_defines']
    r_dict = common.gen_return_dict("Getting Lambda Function info")

    my_name = my_name_is()
    do_this = do_this_func(common_dict['stack'], my_name,
                           common_dict['layer'])
    if do_this:
        arcade_name = common_dict["arcade_name"].replace(".arc", "")
        checks = []
        try:
            r53_client = boto3.client("route53")
            resp = r53_client.list_health_checks()
            for check in resp["HealthChecks"]:
                if arcade_name in check["CallerReference"]:
                    checks.append(check)
            while resp['IsTruncated']:
                resp = r53_client.list_health_checks(Marker=resp["NextMarker"])
                for check in resp["HealthChecks"]:
                    if arcade_name in check["CallerReference"]:
                        checks.append(check)
            if len(checks) > 0:
                common_dict['healthcheck'] = checks
                common_dict['tags']['healthcheck'] = 'yes'
        except Exception:
            r_dict['status'] = rs_defines.FAIL
            r_dict['msg'] = f"{my_name} failed"
            return r_dict
    else:
        r_dict['status'] = rs_defines.SKIP
        r_dict['msg'] = f"{my_name} Skipped"
    return r_dict


# --------------------------------------------------------------------
#
# End info functions
#
# --------------------------------------------------------------------
