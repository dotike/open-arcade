# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
eks --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.1'


import logging
import os
import time
import yaml

import boto3
from arclib import grv, common, cli
from botocore.exceptions import ClientError
from kubernetes import client, config
from kubernetes.client.rest import ApiException


ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}


ASSUME_NODEGROUP_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

ECR_ACCESS_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        }
    ]
}


# --------------------------------------------------------------------
#
# get_eks_status
#
# --------------------------------------------------------------------
def get_eks_status(cluster_name: str) -> dict:
    """
    Return the status of a EKS cluster.

    Args:
        cluster_name: cluster name

    Returns:
        status dict of the response or exception dict
    """
    eks_client = boto3.client('eks')
    try:
        response = eks_client.describe_cluster(name=cluster_name)
    except ClientError as c_e:
        return c_e.response

    return response['cluster']


# --------------------------------------------------------------------
#
# get_nodegroup_status
#
# --------------------------------------------------------------------

def get_nodegroup_status(cluster_name: str, arcade_name: str) -> str:
    """Gets the Status of the Nodegroup for a EKS cluster

    Args:
        cluster_name (str): Name of the EKS cluster
        arcade_name (str): Name of the Arcade

    Returns:
        str: a string rep of the status
    """
    format_arcade_name = arcade_name.replace('.', '-')
    nodegroup_name = f"asteroids_nodegroup-{format_arcade_name}"
    eks_client = boto3.client('eks')
    try:
        response = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        return response['nodegroup']['status']
    except ClientError as e:
        return 'Not Active'

# --------------------------------------------------------------------
#
# eks_status_return_str
#
# --------------------------------------------------------------------

def eks_status_return_str(cluster_name: str):
    """Returns a string of the status of a EKS cluster, similar to
    get_eks_status() but returns a single string.

    Args:
        cluster_name (str): eks cluster name
    """
    eks_client = boto3.client('eks')
    try:
        response = eks_client.describe_cluster(name=cluster_name)
    except ClientError as c_e:
        return 'Not Active'

    return response['cluster']['status']

# --------------------------------------------------------------------
#
# eks_cluster_ready_or_not
#
# --------------------------------------------------------------------

def eks_cluster_ready_or_not(cluster_name: str) -> bool:
    """This function will check the status of the eks cluster. This will only complete
    once the cluster is done. Once the cluster is fully ready, a bool value will return
    True or False. True if cluster is ready, False if the cluster is not ready.

    Args:
        cluster_name (str): Name of the EKS cluster

    Returns:
    
        bool: True if cluster is ready, False if the cluster is not ready.
    """
    eks_status_list = []
    offical_status = eks_status_return_str(cluster_name=cluster_name)
    eks_status_list.insert(0, str(offical_status))
    
    while eks_status_list[0] != 'ACTIVE':
        time.sleep(5)
        new_status = get_eks_status(cluster_name=cluster_name)
        
        if eks_status_list[0] == 'Not Active':
            logging.info('Not Active')
            eks_status_list.insert(0, str(new_status))
            continue
        if eks_status_list[0] == 'CREATING':
            eks_status_list.insert(0, str(new_status))
            logging.info('Creating')
            continue
        if eks_status_list[0] == 'ACTIVE':
            logging.info('Active')
            break
        if eks_status_list[0] == 'PENDING':
            eks_status_list.insert(0, str(new_status))
            logging.info('PENDING')
            continue
        if eks_status_list[0] == 'UPDATING':
            eks_status_list.insert(0, str(new_status))
            logging.info('UPDATING')
            continue
        
    if eks_status_list[0] == 'ACTIVE':
        return True
    else:
        return False


# --------------------------------------------------------------------
#
# nodegroup_ready_or_not
#
# --------------------------------------------------------------------
    
def nodegroup_ready_or_not(cluster_name: str, arcade_name: str) -> bool:
    """_summary_

    Args:
        cluster_name (str): Name of the EKS cluster
        arcade_name (str): Name of the Arcade

    Returns:
        bool: True if the cluster is Active, False if not.
    """
    nodegroup_status_list = []
    offical_nodegroup_status = get_nodegroup_status(cluster_name=cluster_name, arcade_name=arcade_name)
    nodegroup_status_list.insert(0, str(offical_nodegroup_status))
    
    while nodegroup_status_list[0] != 'ACTIVE':
        time.sleep(5)
        new_nodegroup_status = get_nodegroup_status(cluster_name=cluster_name, arcade_name=arcade_name)
        
        if nodegroup_status_list[0] == 'Not Active':
            logging.info('nodegroup is not active')
            nodegroup_status_list.insert(0, str(new_nodegroup_status))
            continue
        if nodegroup_status_list[0] == 'CREATING':
            logging.info('nodegroup is creating')
            nodegroup_status_list.insert(0, str(new_nodegroup_status))
            continue
        if nodegroup_status_list[0] == 'UPDATING':
            logging.info('nodegroup is updating')
            nodegroup_status_list.insert(0, str(new_nodegroup_status))
            continue
        if nodegroup_status_list[0] == 'ACTIVE':
            logging.info('nodegroup is active')
            break
    
    if nodegroup_status_list[0] == 'ACTIVE':
        return True
    else:
        return False

# --------------------------------------------------------------------
#
# get_eks_update_status
#
# --------------------------------------------------------------------
def get_eks_update_status(cluster_name: str,
                          update_id: str) -> dict:
    """
    Return the status of a EKS cluster.

    Args:
        cluster_name: EKS cluster name
        update_id: The id of the update to get status on.

    Returns:
        status dict of the response or exception dict
    """
    eks_client = boto3.client('eks')
    try:
        response = eks_client.describe_update(name=cluster_name,
                                              updateId=update_id)
    except ClientError as c_e:
        return c_e.response

    return response['update']


# --------------------------------------------------------------------
#
# get_eks_nodegroup_status
#
# --------------------------------------------------------------------
def get_eks_nodegroup_status(cluster_name: str,
                             node_group_name: str) -> dict:
    """
    Return the status of a EKS nodegroup.

    Args:
        cluster_name: the name of the cluster
        node_group_name: The name of the nodegroup

    Returns:
        status dict of the response or exception dict
    """
    if not cluster_name or not node_group_name:
        return {'Error': "Invalid cluster name or nodegroup name"}

    eks_client = boto3.client('eks')
    try:
        response = eks_client.describe_nodegroup(
            clusterName=cluster_name,
            nodegroupName=node_group_name
        )
        return response['nodegroup']
    except ClientError as c_e:
        return c_e.response


# --------------------------------------------------------------------
#
# create_eks
#
# --------------------------------------------------------------------
def create_eks(cluster_prefix: str,
               gravitar: str,
               eks_version: str = '1.20') -> dict:
    """
    Create an EKS cluster.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        eks_version: eks version. Defaults to '1.20'.

    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"

    status = get_eks_status(eks_name)

    if 'Error' in status:
        # Create the cluster when it does not exist.
        eks_cluster_role = 'EKSClusterRole'
        eks_cluster_policy_arns = ['arn:aws:iam::aws:policy/AmazonEKSClusterPolicy']
        eks_sg_name = f"{cluster_prefix}_eks.{gravitar}"

        vpc_id = grv.get_vpc_id(gravitar)
        eks_sg_id = grv.check_if_sg(eks_sg_name)
        if not eks_sg_id:
            eks_sg_id = grv.create_grv_sg(sg_name=eks_sg_name, vpc_id=vpc_id)

        eks_client = boto3.client('eks')

        role_status = grv.find_role(eks_cluster_role)

        if role_status:
            role_to_use = role_status['Role']['Arn']
        else:
            role_to_use = grv.create_role(role_name=eks_cluster_role,
                                          policy_arns=eks_cluster_policy_arns,
                                          assume_policy=ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT,
                                          custom_policy=ECR_ACCESS_POLICY_DOCUMENT)

        core_subnets = grv.find_grv_subnets(gravitar, "core")
        creator = os.getenv('USER', '')
        print(f'Creating Cluster {eks_name}...')
        response = eks_client.create_cluster(
            name=eks_name.replace(".", "-"),
            version=eks_version,
            roleArn=role_to_use,
            resourcesVpcConfig={
                'subnetIds': core_subnets,
                'securityGroupIds': [eks_sg_id],
                'endpointPublicAccess': True
            },
            tags={
                'grv_name': gravitar,
                'creator': creator,
            }
        )

        status = response['cluster']

        while 'CREATING' == status['status']:
            print(f'Waiting for the cluster {eks_name} to be active.')
            time.sleep(120)
            status = get_eks_status(eks_name)

        print(f"Cluster {eks_name} is created!")
        return status
    elif 'CREATING' == status['status']:
        while 'CREATING' == status['status']:
            print(f'Waiting for the cluster {eks_name} to be active.')
            time.sleep(120)
            status = get_eks_status(eks_name)
        return status
    else:
        print(f'Cluster {eks_name} already exists, status: {status["status"]}')
        return status


# --------------------------------------------------------------------
#
# create_eks_nodegroup
#
# --------------------------------------------------------------------
def create_eks_nodegroup(cluster_prefix: str,
                         gravitar: str,
                         nodes: int = 4,
                         max_nodes: int = 4,
                         instance_type: str = 't3.medium',
                         size: int = 20) -> dict:
    """
    Create an EKS nodegroup for the cluster.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        nodes: the number of nodes
        instance_type: the type of instance, default is 't3.medium'
        size: the gibibyte size of the disk, default is 20

    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"
    eks_nodegroup_name = f"{cluster_prefix}_nodegroup-{gravitar.replace('.', '-')}"

    if nodes > max_nodes:
        max_nodes = nodes

    status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    if 'Error' in status:
        eks_node_instance_role = 'EKSNodeInstanceRole'
        eks_node_instance_policy_arns = ['arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
                                         'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
                                         'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly']

        nodegroup_subnets = grv.find_grv_subnets(gravitar, "core")
        ssh_net_sg_id = grv.check_if_sg(gravitar)

        role_status = grv.find_role(eks_node_instance_role)

        if role_status:
            role_to_use = role_status['Role']['Arn']
        else:
            role_to_use = grv.create_role(role_name=eks_node_instance_role,
                                          policy_arns=eks_node_instance_policy_arns,
                                          assume_policy=ASSUME_NODEGROUP_ROLE_POLICY_DOCUMENT)

        eks_client = boto3.client('eks')
        print(f'Creating nodegroup {eks_nodegroup_name}...')
        response = eks_client.create_nodegroup(
            clusterName=eks_name,
            nodegroupName=eks_nodegroup_name,
            scalingConfig={
                'minSize': nodes,
                'maxSize': max_nodes,
                'desiredSize': nodes
            },
            diskSize=size,
            subnets=nodegroup_subnets,
            instanceTypes=[instance_type],
            amiType='AL2_x86_64',
            remoteAccess={
                'ec2SshKey': f'bootstrap.{gravitar}',
                'sourceSecurityGroups': [ssh_net_sg_id]
            },
            nodeRole=role_to_use,
            tags={
                'grv_name': gravitar
            },
            capacityType='ON_DEMAND',
        )

        status = response['nodegroup']

        while 'CREATING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be active')
            time.sleep(120)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    elif 'CREATING' == status['status']:
        while 'CREATING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be active')
            time.sleep(120)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    return status


# --------------------------------------------------------------------
#
# delete_eks
#
# --------------------------------------------------------------------
def delete_eks(cluster_prefix: str,
               gravitar: str) -> dict:
    """
    Delete EKS cluster with given cluster name.

    Args:
        cluster_prefix: name of the eks to be deleted
        gravitar: name of gravitar

    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"
    eks_sg_name = f"{cluster_prefix}_eks.{gravitar}"

    status = get_eks_status(eks_name)

    if 'Error' in status:
        grv.delete_grv_sg(eks_sg_name)
        return status

    if 'DELETING' == status['status']:
        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for eks {eks_name} to be deleted.')
            time.sleep(30)
            status = get_eks_status(eks_name)
    else:
        eks_client = boto3.client('eks')
        print(f'Deleting eks {eks_name}...')
        response = eks_client.delete_cluster(name=eks_name)
        status = response['cluster']

        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for eks {eks_name} to be deleted.')
            time.sleep(30)
            status = get_eks_status(eks_name)

    grv.delete_grv_sg(eks_sg_name)

    return status


# --------------------------------------------------------------------
#
# delete_eks_nodegroup
#
# --------------------------------------------------------------------
def delete_eks_nodegroup(cluster_prefix: str,
                         gravitar: str) -> dict:
    """
    Delete eks nodegroup for the cluster.

    Args:
        cluster_prefix: the prefix of cluster
        gravitar: the name of gravitar

    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"
    eks_nodegroup_name = f"{cluster_prefix}_nodegroup-{gravitar.replace('.', '-')}"

    status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    if 'Error' in status:
        return status

    if 'DELETING' == status['status']:
        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be deleted.')
            time.sleep(30)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)
            logging.debug(status)
    else:
        eks_client = boto3.client('eks')
        response = eks_client.delete_nodegroup(
            clusterName=eks_name,
            nodegroupName=eks_nodegroup_name
        )

        status = response['nodegroup']

        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be deleted.')
            time.sleep(30)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)
            logging.debug(status)

    logging.debug(status)

    return status

# --------------------------------------------------------------------
#
# get_eks_cluster_rich_info
#
# --------------------------------------------------------------------
def get_eks_cluster_rich_info(clusterdict: dict) -> dict:
    """
    Given an EKS cluster dict, produce a rich dict providing data
    about the EKS cluster.

    Args:
      Requires one of:
        clusterdict -  containing at minimum:
          {'clustername': <CLUSTER_NAME>,
           'region':      <AWS_REGION>}

    Returns:
      Dict containing a rich amount of data, including the same
      data passed in via 'clusterdict' arg.  Also duplicates
      tags in convienent 'TagSane' format.
    """
    cluster_return = {}

    cluster_return = clusterdict
    clustername = cluster_return['cluster_name']

    region_breadcrumb = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')
    grv.set_region(cluster_return['region'])

    #describe_cluster()
    eksclient = boto3.client('eks')
    describe_cluster_resp = eksclient.describe_cluster(name=clustername)['cluster']
    for ckey in describe_cluster_resp:
        cluster_return[ckey] = describe_cluster_resp[ckey]
        if describe_cluster_resp.get('tags'): # wow, this is different
            tag_sane = describe_cluster_resp.get('tags')
        else:
            tag_sane = {}
        cluster_return['TagSane'] = tag_sane
#
# STUB: future additons could provide args which provide a *lot* more,
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html
#
    #list_addons()
      #describe_addon()
      #describe_addon_versions()
    #list_identity_provider_configs()
      #describe_identity_provider_config()
    #list_tags_for_resource()
    #list_updates()
      #describe_update()
    #list_nodegroups()
      #describe_nodegroup()
    #list_fargate_profiles()
      #describe_fargate_profile()

    os.environ['AWS_DEFAULT_REGION'] = region_breadcrumb
    return cluster_return

# --------------------------------------------------------------------
#
# get_eks_clusters_detail
#
# --------------------------------------------------------------------
def get_eks_clusters_detail(region=None, arcade_name=None) -> dict:
    """
    Account scoped, (returns more than ARCADEs),
    A convienence function to list all EKS clusters in an account.

    Slow, this walks all regions to provide a comprehensive dict of
    EKS clusters, to return a rich dict of available information.

    Args:
        One of,
            region - optional resolver to isolate to a single region.
            arcade_name - optional resolver isolating to single ARCADE.
    ENV:
        'VERBOSE' - non null prints status messages to stderr.

    Returns:
        Dict of individual EKS clusters, keyed by EKS UID.
        Prints strings to stderr if "VERBOSE" is set.

    See Also:
        get_account_eks_clusters() provides a much faster return,
        if you merely want the names of clusters.
    """
    return_rich_cluster = {}
    region_breadcrumb = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')

    if arcade_name and region:
        raise ValueError(
            "expected either 'region' or 'arcade_name' but got both")
    elif arcade_name:
        cli.vprint("Looking up region for ARCADE: {}".format(arcade_name))
        region = grv.name_to_region(arcade_name)
        cli.vprint("Searching ARCADE {} in region: {}".format(arcade_name, region))
        # Build rich info,
        clusters_light = get_account_eks_clusters(region)
        rich_cluster = {}
        for clustername in clusters_light:
            rich_eks = clusters_light.get(clustername, {})
            rich_cluster[clustername] = get_eks_cluster_rich_info(
                                        clusterdict=rich_eks)
        # strip ARCADE tagged,
        for _each_cluster in rich_cluster:
            _cluster_tags = rich_cluster[_each_cluster]['tags']
            grv_name_tag = _cluster_tags.get('grv_name', '')
            if grv_name_tag == arcade_name:
                return_rich_cluster[clustername] = rich_cluster[_each_cluster]
    elif region:
        cli.vprint("Searching single region: {}".format(region))
        clusters_light = get_account_eks_clusters(region)
        for clustername in clusters_light:
            rich_eks = clusters_light.get(clustername, {})
            return_rich_cluster[clustername] = get_eks_cluster_rich_info(
                                               clusterdict=rich_eks)
    else:
        regions = grv.region_resolver()
        cli.vprint("Walking available regions: {}".format(regions))
        for one_region in regions:
            cli.vprint("Searching: {}".format(one_region))
            grv.set_region(one_region)
            clusters_light = get_account_eks_clusters(one_region)
            for clustername in clusters_light:
                rich_eks = clusters_light.get(clustername, {})
                return_rich_cluster[clustername] = get_eks_cluster_rich_info(
                                                   clusterdict=rich_eks)

    os.environ['AWS_DEFAULT_REGION'] = region_breadcrumb
    return return_rich_cluster

# --------------------------------------------------------------------
#
# get_account_eks_clusters
#
# --------------------------------------------------------------------
def get_account_eks_clusters(region=None) -> dict:
    """
    Account scoped, (returns more than ARCADEs),
    A convienence function to list all EKS clusters in an account.

    Fast, this walks all regions to provide a light dict of EKS
    clusters available information.

    Args:
        region - optional resolver to isolate to a single region.
        arcade_name - optional resolver isolating to single ARCADE.

    Returns:
        Dict of individual EKS clusters, keyed by EKS UID.

    See Also:
        get_eks_clusters_detail() provides much more detailed
        information for each cluster
    """
    return_eks = {}
    region_breadcrumb = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')
    vpc_id = ''

    if region:
        regions = [region]
    else:
        regions = grv.region_resolver()

    aws_response = {'clusters': []}
    for region in regions:
        grv.set_region(region)
        eksclient = boto3.client('eks', region_name=region)
        paginator = eksclient.get_paginator('list_clusters')
        aws_response = paginator.paginate().build_full_result()

        for clustername in aws_response.get('clusters', []):
            return_eks[clustername] = {'cluster_name': clustername}
            return_eks[clustername]['region'] = region

    os.environ['AWS_DEFAULT_REGION'] = region_breadcrumb
    return return_eks


# list_eks
#
# --------------------------------------------------------------------
def list_eks(gravitar='') -> list:
    """
    Return the cluster info as list

    Args:
        gravitar: the name of gravitar

    Returns:
        List of EKS clusters, or empty list if there is no cluster.
    """
    eks_client = boto3.client('eks')
    response = eks_client.list_clusters()

    if not gravitar:
        return response['clusters']

    suffix = gravitar.replace('.', '-')
    gravitar_clusters = []
    for cluster in response['clusters']:
        if cluster.endswith(suffix):
            gravitar_clusters.append(cluster)

    return gravitar_clusters


# --------------------------------------------------------------------
#
# get_eks_info
#
# --------------------------------------------------------------------
def get_eks_info(cluster_name: str) -> dict:
    """
    Return the info of an EKS cluster as a dict.

    Args:
        cluster_name: cluster name

    Returns:
        eks dict (with nodegroups) or empty dict
    """
    arcade_name = cluster_to_arcade_name(cluster_name)
    arcade_session = common.setup_arcade_session(arcade_name)
    eks_client = arcade_session.client('eks')
    try:
        response = eks_client.describe_cluster(name=cluster_name)
    except ClientError as c_e:
        return {}

    eks_info = response['cluster']

    res = eks_client.list_nodegroups(clusterName=cluster_name)
    eks_info['nodegroups'] = res['nodegroups']

    return eks_info


# --------------------------------------------------------------------
#
# get_eks_nodegroup_info
#
# --------------------------------------------------------------------
def get_eks_nodegroup_info(cluster_name: str,
                           nodegroup: str) -> dict:
    """
    Return the info of an EKS nodegroup as a dict.

    Args:
        cluster_name: the name of the cluster
        nodegroup: The name of the nodegroup

    Returns:
        nodegroup dict or empty dict
    """
    if not cluster_name or not nodegroup:
        return {}

    arcade_name = cluster_to_arcade_name(cluster_name)
    arcade_session = common.setup_arcade_session(arcade_name)
    eks_client = arcade_session.client('eks')
    response = eks_client.list_nodegroups(clusterName=cluster_name)

    if nodegroup not in response['nodegroups']:
        return {}

    response = eks_client.describe_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup,
    )

    return response['nodegroup']


# --------------------------------------------------------------------
#
# apply_awsauth_configmap
#
# --------------------------------------------------------------------
def apply_awsauth_configmap(cluster_prefix: str,
                            gravitar: str):
    """
    Apply AWS auth configmap to the EKS context.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name

    Returns:
        bool
    """
    if not cluster_prefix or not gravitar:
        return False

    cluster_name = f'{cluster_prefix}-{gravitar.replace(".", "-")}'
    arcade_session = common.setup_arcade_session(arcade_name=gravitar)
    eks_admin_role = 'EKSAdminRole'
    tmp_dir = os.getenv("ATMP", '/tmp')

    # This is used when the EKS cluster is initially Created
    # use load_arcade_k8s_config for all other k8s configuration
    eks = arcade_session.client('eks')
    try:
        response = eks.describe_cluster(name=cluster_name)
    except ClientError as c_e:
        logging.warning(f"Cluster error: {c_e}")
        return False
    context_cert_data = response["cluster"]["certificateAuthority"]["data"]
    context_server = response["cluster"]["endpoint"]
    context_arn = response["cluster"]["arn"]
    context_name = response["cluster"]["name"]
    context_region = context_arn.split(":")[3]

    iam_client = arcade_session.client('iam')
    role_res = iam_client.get_role(RoleName=eks_admin_role)
    eksadminrolearn = role_res['Role']['Arn']

    context_dict_yaml = f"""
apiVersion: v1
kind: Config
preferences: {{}}
current-context: {context_name}
clusters:
- cluster:
    certificate-authority-data: {context_cert_data}
    server: {context_server}
  name: {context_arn}
contexts:
- context:
    cluster: {context_arn}
    user: {context_arn}
  name: {context_name}
users:
- name: {context_arn}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      args:
      - --region
      - {context_region}
      - eks
      - get-token
      - --cluster-name
      - {context_name}
      command: aws
"""

    contexts = {}
    contexts['creator'] = yaml.safe_load(context_dict_yaml)
    contexts['role'] = yaml.safe_load(context_dict_yaml)
    contexts['role']['users'][0]['user']['exec']['args'].append('--role-arn')
    contexts['role']['users'][0]['user']['exec']['args'].append(eksadminrolearn)

    grv_info = grv.get_gravitar_info(gravitar)
    vpc_id = list(grv_info['vpc'].keys())[0]
    owner_id = grv_info['vpc'][vpc_id]['OwnerId']

    eks_node_instance_role = 'EKSNodeInstanceRole'

    # 4 braces are necessary to escape formatted text braces.
    awsauth_configmap_yaml = f"""
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: arn:aws:iam::{owner_id}:role/{eks_node_instance_role}
      username: system:node:{{{{EC2PrivateDNSName}}}}
      groups:
        - system:bootstrappers
        - system:nodes
    - rolearn: arn:aws:iam::{owner_id}:role/Amazon{eks_admin_role}
      username: Amazon{eks_admin_role}:{{{{SessionName}}}}
      groups:
        - system:masters
    - rolearn: arn:aws:iam::{owner_id}:role/{eks_admin_role}
      username: {eks_admin_role}:{{{{SessionName}}}}
      groups:
        - system:masters
"""

    awsauth_configmap = yaml.safe_load(awsauth_configmap_yaml)

    for entity in ['role', 'creator']:
        context_file_name = f"{tmp_dir}/{entity}-context.yaml"
        with open(context_file_name, "w") as context_file:
            yaml.dump(contexts[entity], context_file, default_flow_style=False)
        config.load_kube_config(config_file=context_file_name)
        core_v1 = client.CoreV1Api()

        try:
            response = core_v1.create_namespaced_config_map(
                namespace="kube-system",
                body=awsauth_configmap,
            )
            logging.info(f"Created aws-auth ConfigMap by {entity}")
            return True
        except ApiException as api_error:
            if api_error.status == 409:
                api_response = core_v1.replace_namespaced_config_map(
                    name=awsauth_configmap['metadata']['name'],
                    namespace=awsauth_configmap['metadata']['namespace'],
                    body=awsauth_configmap,
                )
                logging.info(f"Replaced aws-auth ConfigMap by {entity}")
                return True
            if api_error.status == 401:
                print(api_error)
                continue
            logging.warning(api_error)
            raise api_error

    return False


# --------------------------------------------------------------------
#
# cluster_to_arcade_name
#
# --------------------------------------------------------------------
def cluster_to_arcade_name(cluster_name: str) -> str:
    """
    Generate arcade_name from cluster_name.

    Args:
        cluster_name: name of a cluster

    Returns:
        str
    """
    cluster_split = cluster_name.split('-')
    name = cluster_split[1]
    tld = cluster_split[2]
    return f"{name}.{tld}"


def arcade_to_cluster_name(arcade_name: str):
    """Converts arcade name to EKS cluster name

    Args:
        arcade_name (str): name of the arcade

    Returns:
        _str_: string rep of the cluster name
    """
    return f"asteroids-{arcade_name.replace('.', '-')}"
