# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
dns --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


from datetime import datetime
import logging
import boto3
from botocore.exceptions import ClientError
from arclib import grv

# --------------------------------------------------------------------
#
# create_arcade_zone
#
# --------------------------------------------------------------------
def create_arcade_zone(arcade_name: str, domain_name: str) -> bool:
    """
    Args:
        arcade_name (str): name of the associated ARCADE.
        domain_name (str): name of zone to create.
    """
    zone_id = grv.tld_to_zone_id(domain_name)
    if not zone_id:
        try:
            session = boto3.session.Session()
            r53_client = session.client('route53')
            region_name = session.region_name
            vpc_id = grv.get_vpc_id(grv_name=arcade_name)
            chz_response = r53_client.create_hosted_zone(
                Name=domain_name,
                VPC={
                    'VPCRegion': region_name,
                    'VPCId': vpc_id
                },
                CallerReference=str(datetime.utcnow()),
                HostedZoneConfig={
                    'Comment': arcade_name,
                    'PrivateZone': True
                }
            )
        except ClientError as c_e:
            raise c_e

    return associate_arcade_to_zone(arcade_name, domain_name)


# --------------------------------------------------------------------
#
# associate_arcade_to_zone
#
# --------------------------------------------------------------------
def associate_arcade_to_zone(arcade_name: str, domain_name: str) -> bool:
    """
    Args:
        arcade_name (str): name of the arcade_name
        domain_name (str): name of the domain_name
    Returns:
        bool: for success
    """
    session = boto3.session.Session()
    r53_client = session.client('route53')
    vpc_id = grv.get_vpc_id(grv_name=arcade_name)
    region_name = session.region_name
    zone_id = grv.tld_to_zone_id(domain_name)
    try:
        response = r53_client.associate_vpc_with_hosted_zone(
            HostedZoneId=zone_id,
            VPC={
                'VPCRegion': region_name,
                'VPCId': vpc_id
            },
            Comment=arcade_name
        )
    except ClientError as c_e:
        if c_e.response['Error']['Code'] == 'ConflictingDomainExists':
            return True
        if c_e.response['Error']['Code'] == 'PublicZoneVPCAssociation':
            return True
        raise c_e

    return False


# --------------------------------------------------------------------
#
# add_arcade_cname
#
# --------------------------------------------------------------------
def add_arcade_cname(arcade: str,
                     source: str,
                     target: str) -> bool:
    """
    Add source -> target cname record to arcade

    Args:
        arcade: The name of arcade
        source: Source string
        target: Target string

    Returns:
        True/False

    """
    r53 = boto3.client('route53')
    arcade_domain = arcade.replace('_', '-')
    dns_source = source.replace('_', '-')
    dns_target = target.replace('_', '-')
    zones = r53.list_hosted_zones_by_name(DNSName=arcade_domain)
    zone_id = zones['HostedZones'][0]['Id']
    try:
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': f'add {dns_source} -> {dns_target}',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': dns_source,
                            'Type': 'CNAME',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': dns_target}]
                        }
                    }]
            })
        return True
    except Exception as e:
        logging.error(e)
        return False
    # End of add_arcade_cname


# --------------------------------------------------------------------
#
# delete_arcade_cname
#
# --------------------------------------------------------------------
def delete_arcade_cname(arcade: str,
                        source: str) -> None:
    """
    Delete cname start with source for an arcade

    Args:
        arcade: The name of arcade
        source: Source string

    Returns:
        None

    """
    r53 = boto3.client('route53')
    arcade_domain = arcade.replace('_', '-')
    dns_source = source.replace('_', '-')
    zones = r53.list_hosted_zones_by_name(DNSName=arcade_domain)
    zone_id = zones['HostedZones'][0]['Id']
    response = r53.list_resource_record_sets(HostedZoneId=zone_id,
                                             StartRecordName=dns_source, MaxItems='1')

    if dns_source in response['ResourceRecordSets'][0]['Name']:
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': f'delete {dns_source}',
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': response['ResourceRecordSets'][0]
                    }]
            })
    # End of delete_arcade_cname


# --------------------------------------------------------------------
#
# get_arcade_dns_record
#
# --------------------------------------------------------------------
def get_arcade_dns_record(arcade_name: str,
                          source: str) -> dict:
    """
    Get the DNS record.

    Args:
        arcade_name: The name of arcade
        source: FQDN

    Returns:
        dict

    """
    r53 = boto3.client('route53')
    arcade_domain = arcade_name.replace('_', '-')
    dns_source = source.replace('_', '-')
    zones = r53.list_hosted_zones_by_name(DNSName=arcade_domain)
    zone_id = zones['HostedZones'][0]['Id']
    response = r53.list_resource_record_sets(HostedZoneId=zone_id,
                                             StartRecordName=dns_source, MaxItems='1')

    if dns_source in response['ResourceRecordSets'][0]['Name']:
        return response['ResourceRecordSets'][0]

    return {}
    # End of get_arcade_dns_record
