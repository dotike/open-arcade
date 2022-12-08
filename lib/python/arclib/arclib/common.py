# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
common --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.3'

from copy import deepcopy
import hashlib
import json
import logging
import os
import re
import sys
import boto3

from botocore.exceptions import ClientError

from arclib import storage
from arclib import grv as GRV
from datetime import date, datetime, timedelta, timezone


# --------------------------------------------------------------------
#
# gen_return_dict
#
# --------------------------------------------------------------------
def gen_return_dict(msg = "") -> dict:
    """
    This sets up a dictonary that is intented to be returned from
    a function call. The real value here is that this dictonary
    contains information, like the function name and line number,
    about the function. This is handy when debugging a mis-behaving
    function.

    Args:
        msg: A text string containg a simple, short message

    Returns:
        r_dict: a dictonary that is returned from a function call

    """
    RS = ReturnStatus()

    r_dict = {}

    # These values come from the previous stack frame ie. the
    # calling function.
    r_dict['line_number']   = sys._getframe(1).f_lineno
    r_dict['filename']      = sys._getframe(1).f_code.co_filename
    r_dict['function_name'] = sys._getframe(1).f_code.co_name

    r_dict['status']   = RS.OK # See the class ReturnStatus
    r_dict['msg']      = msg   # The passed in string
    r_dict['data']     = ''    # The data/json returned from func call
    r_dict['path']     = ''    # FQPath to file created by func (optional)
    r_dict['resource'] = ''    # What resource is being used (optional)

    return r_dict
    # End of gen_return_dict


# --------------------------------------------------------------------
#
# class ReturnStatus
#
# --------------------------------------------------------------------
class ReturnStatus:
    """
    Since we can't have nice things, like #define, this is
    a stand in.

    These values are intended to be returned from a function
    call. For example

    def bar():
        RS = ReturnStatus()
        r_dict = gen_return_dict('Demo program bar')

        i = 1 + 1

        if i == 2:
            r_dict['status'] = RS.OK
        else:
            r_dict['status'] = RS.NOT_OK
            r_dict['msg'] = 'Basic math is broken'

        return r_dict

    def foo():
        RS = ReturnStatus()

        r_dist = bar()
        if r_dict['status'] = RS.OK:
            print('All is right with the world')
        else:
            print('We're doomed!')
            print(r_dict['msg'])
            sys.exit(RS.NOT_OK)

        return RS.OK

    """

    OK         = 0 # It all worked out
    NOT_OK     = 1 # Not so much
    SKIP       = 2 # We are skipping this block/func
    NOT_YET    = 3 # This block/func is not ready
    FAIL       = 4 # It all went to hell in a handbasket
    NOT_FOUND  = 5 # Could not find what we were looking for
    FOUND      = 6 # Found my keys
    YES        = 7 # Cant believe I missed these
    NO         = 8 #
    RESTRICTED = 9 #
    # End of class ReturnStatus


# --------------------------------------------------------------------
#
# columnate
#
# --------------------------------------------------------------------
def columnate(instring):
    '''
    Use UNIX column(1) to format columnar text output.

    Intended for common use to enable tool output to taste the same.
    It would be nice to do this in native python, but that\'s
    nontrivial- in the meantime see the man page for column(1) for
    more info.

    Args: instring - a string, typically multi-line text.

    Returns: column-formatted version of instring.

    Example Usage:
       columnate(multiline_text_block)
       columnate('foo       bar baz\n1 2 3')
    '''
    try:
        from subprocess import Popen, PIPE, STDOUT

        if not instring.endswith('\n'):
            instring = instring + '\n'

        col = Popen(['column', '-t'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        col_stdout = col.communicate(input=instring.encode())[0]
        return col_stdout.decode().strip('\n')

    except Exception as err:
        raise type(err)('column() error: {}'.format(err))
    # End of columnate

    
# --------------------------------------------------------------------
#
# aws_tags_to_dict
#
# --------------------------------------------------------------------
def aws_tags_to_dict(taglist: list) -> dict:
    """
    This wrapper exists just give a legacy function a
    more discriptive name

    Args:
        taglist: A list of tags
        
    Returns:
        r_dist: The passed in list of tags mutated into a dict
    """
    return grv.aws_tags_dict(taglist)
    # End of aws_tags_to_dict


# --------------------------------------------------------------------
#
# aws_tags_dict
#
# --------------------------------------------------------------------
def aws_tags_dict(tag_list: list) -> dict:
    """
    Convenience function to relieve fumbling around with AWS tag lists.

    Given a list of AWS tags, (common to most AWS object types), converts
    the list into a dict keyed by tag:Key.

    Args:
        tag_list - list of dicts from AWS API tag.

    Returns:
        dict of Key, Value pairs.  If supplied tag list contains
        no values, returns an empty dict.
    """
    if tag_list is None or not isinstance(tag_list, list):
        raise ValueError(f"tag_list should be a list of dicts, got: {tag_list}")

    return_dict = {}
    for tagd in tag_list:
        if 'Key' not in tagd or 'Value' not in tagd:
            raise ValueError(f"element of tag_list should be a tag dict, got {tagd}")
        return_dict[tagd['Key']] = tagd['Value']

    return return_dict
    # End of aws_tags_dict


# --------------------------------------------------------------------
#
# check_dryrun
#
# --------------------------------------------------------------------
def check_dryrun(filename: str) -> bool:
    """
    Check dryrun option from os environ (GALAGA_DRYRUN)
    This function needs to be invoked by installer at
    the beginning of the main function

    Args:
        filename - the filename of the installer

    Returns:
        True if dryrun is set, else False
    """
    dryrun = os.environ.get('GALAGA_DRYRUN')

    if "1" == dryrun:
        print(f"Invoke installer {filename} with dryrun option.")
        return True
    else:
        print(f"Invoking installer {filename}.")
        return False
    # End of check_dryrun


# --------------------------------------------------------------------
#
# print_status
#
# --------------------------------------------------------------------
def print_status(status: dict) -> None:
    """
    Print status dictionary to json object
    The purpose of this function is to resolve following error
    when loading json object from json string:
    TypeError: Object of type datetime is not JSON serializable

    Args:
        status: status dictionary to print

    Returns:
        None
    """
    # Comment out the print statment below due to extream output on -verbose output
    # print(json.dumps(status, sort_keys=False, indent=2, default=str))

    return status
    # End of print_status


# --------------------------------------------------------------------
#
# setup_arcade_session
#
# --------------------------------------------------------------------
def setup_arcade_session(arcade_name: str) -> boto3.session.Session:
    """
    Create AWS session with arcade region set.

    Args:
        arcade_name:

    Returns:
        session
    """
    # figure out what region cluster/arcade lives in
    # getting location from arcade scoped bucket is faster than looking for vpc
    arcade_region = get_arcade_region(arcade_name)
    # print("----Arcade region----")
    # print(arcade_region)
    if not arcade_region:
        # No buckets found for this arcade!
        print(f"The Arcade {arcade_name} was not found")
        exit(1)

    return boto3.session.Session(region_name=arcade_region)
    # End of setup_arcade_session


# --------------------------------------------------------------------
#
# get_arcade_region
#
# --------------------------------------------------------------------
def get_arcade_region(arcade_name: str) -> str:
    """
    Get the region that the ARCADE lives in.

    Args:
        arcade_name:

    Returns:
        str
    """
    # figure out what region cluster/arcade lives in
    # getting location from arcade scoped bucket is faster than looking for vpc
    bucket_session = boto3.session.Session(region_name='us-east-2')
    s3_client = bucket_session.client('s3')
    buckets = storage.get_arcade_buckets(bucket_session, arcade_name)
    if not buckets:
        return ""
    try:
        arcade_region = s3_client.get_bucket_location(Bucket=buckets['infrastructure'])['LocationConstraint']
        # print("----Arcade region----")
        # print(arcade_region)
        return arcade_region
    except Exception as e:
        # print(arcade_name)
        # print(e)
        return ""

    # End of get_arcade_region


# --------------------------------------------------------------------
#
# get_short_narc_id
#
# --------------------------------------------------------------------
def get_short_narc_id(narcid: str) -> str:
    """
    Get the short narc id by using first 8 characters of asd/asteroid name

    Args:
        narcid: the original narc id

    Returns:
        the short narc id in string format
    """
    groups = narcid.split('-')
    groups[1] = groups[1][:8]
    groups[2] = groups[2][:8]

    return "-".join(groups)
    # End of get_short_narc_id


# --------------------------------------------------------------------
#
# is_number
#
# --------------------------------------------------------------------
def is_number(self, num):
    """
    Helper function to determine if string is numeric or not (handles int, float, pos/neg
    """
    try:
        float(num)
    except ValueError:
        return False
    return True
    # End of is_number


# --------------------------------------------------------------------
#
# check_if_sg
#
# --------------------------------------------------------------------
def check_if_sg(sg_name: str) -> str:
    """
    Check to see if a SG is present.

    Args:
        sg_name: security group name

    Returns:
        security group id if the sg is there, empty string if not
    """
    client = boto3.client('ec2')
    response = client.describe_security_groups(
        Filters=[
            {
                'Name': 'tag:Name',
                'Values': [f"{sg_name}*"]
            }
        ]
    )

    if len(response['SecurityGroups']) != 1:
        return ""
    return response['SecurityGroups'][0]['GroupId']
    # End of check_if_sg


# --------------------------------------------------------------------
#
# str_to_bool
#
# --------------------------------------------------------------------
def str_to_bool(stringrep):
    """
    Convert a string representation of a boolean value to a real boolean.

    Args:
        stringrep: The string to convert

    Return True unless:
      The string is empty, like [], (), {}
      The string is False
      The string is None
      The string is 0
      The string is a string 'false'
      The string is a string 'no'
      The string is a string 'off'
    Character case is ignored.
    Leading and trailing whitespace is ignored.
    """
    if not stringrep or re.search('^\s*(0|false|no|off)\s*$', stringrep, re.IGNORECASE):
        # Anything matching the above is considered False.
        return False

    # Everything else is True.
    return True
    # End of str_to_bool


# --------------------------------------------------------------------
#
# get_wallclock
#
# --------------------------------------------------------------------
def get_wallclock(time_zone_name='utc') -> str:
    """
    Get the current wall time, human time, formatted in a quasi RFC-3339
    format, we drop the fractional parts of the seconds. If this function
    is called without specifying a time zone name, the time zone defaults
    to UTC (Coordinated Universal Time). This function can be called with
    one of the three character time zone abbreviation listed below.

    EST  - America/New_York    : -0400
    CST  - America/Chicago     : -0500
    MST  - America/Denver      : -0600
    PST  - America/Los_Angeles : -0700
    UTC  - UTC                 : +0000
    ZULU - UTC                 : +0000
    Args:
        time_zone_name - The common (and confusing) time
        zone abbreviations

    Returns:
        time_string - the current wall clock time in a specified
        North American time zone as specified in RFC-3339
    """

    time_zone_offsets = {
        "est"  : -4,
        "cst"  : -5,
        "mst"  : -6,
        "pst"  : -7,
        "utc"  : 0,
        "zulu" : 0
        }

    time_zone_name = time_zone_name.lower()
    if time_zone_name not in time_zone_offsets:
        time_zone_name = 'utc'

    time_zone = time_zone_offsets[time_zone_name]

    zone = timezone(offset=timedelta(hours=time_zone))
    date_str = datetime.now(tz=zone)

    time_string = date_str.strftime('%Y-%m-%dT%H:%M:%S%z')

    return time_string
    # End of get_wallclock


# ---------------------------------------------------------
#
# Convert wallclock
#
# ---------------------------------------------------------
def convert_wallclock(time_string) -> str:
    """
       Get the current human time (as that given by the AWS boto3), and convert it to RC-3339 format using the python datetime library.
    Args:
        time_string - Time stamp given by the AWS in human readable format.

    Returns:
        rc3339_time - timestamp converted to RC-3999 format.
    """

    datetime_object=datetime.strptime(time_string,'%a, %d %b %Y %H:%M:%S %Z')

    rc3339_time = datetime_object.isoformat("%Y-%m-%dT%T%z")

    return rc3339_time
    # End of convert_wallclock

    
# ---------------------------------------------------------
#
# Convert DateTime
#
# ---------------------------------------------------------
def convert_date_time(time_value):
    """
    This function takes a datetime object and returns the
    date and time as a string. This is neccessary because
    some dict returned by an AWS call contain a datetime
    object that can not be outputed as a string

    Args:
        time_value: a datetime object

    Returns:
        date_time: A string representing a date and time
    """
    if isinstance(time_value, date):
        date_time = time_value.strftime("%d-%b-%Y %H:%M:%S")
        return date_time
    else:
        return time_value
    # End of convert_date_time


# ---------------------------------------------------------
#
# override_service_description
#
# ---------------------------------------------------------
def override_service_description(n_data: dict, overrides: dict) -> dict:
    """
    Override dict with a dictionary of pathed variables.

    Args:
        n_data: dictionary to be overridden.
        overrides: dictionary of overrides in the form, path: value.
            {"services/eks/service_options/eks_version": "1.21"}
    Returns:
        overridden dictionary.
    """
    # TODO: Deal with value being boolean and key not existing.
    data = deepcopy(n_data)

    for key, value in overrides.items():
        node = data
        path = key.split('/')

        logging.debug(f"---{key}---")
        logging.debug(node)
        for step in path[:-1]:
            # pprint(step)
            if step.isnumeric():
                node = node[int(step)]
                # pprint(node)
            else:
                if step not in node:
                    node[step] = {}
                node = node[step]
                # pprint(node)

        logging.debug(f"{path[-1]} - {node}")
        try:
            if path[-1] not in node:
                node[path[-1]] = {}

            if isinstance(node[path[-1]], bool):
                val = bool(value.lower() == "true")
                node[path[-1]] = val
            elif isinstance(node[path[-1]], int):
                node[path[-1]] = int(value)
            else:
                node[path[-1]] = value
        except Exception as error:
            logging.error(error)

    # logging.debug(node)
    return data
    # End of overriding_service_description


# --------------------------------------------------------------------
#
# get_account_info
#
# --------------------------------------------------------------------
def get_account_info():
    """
    """
    is_restricted = False

    grv_config = GRV.grvs_loadconfig()
    p_dict = get_user_info()
    user_account_number = p_dict['AccountNumber']
    cleaned_list, restricted = find_restricted_regions()
    p_dict['RegionList'] = cleaned_list
    p_dict['IsRestricted'] = restricted

    aws_region = os.getenv('AWS_REGION')
    aws_default_region = os.getenv('AWS_DEFAULT_REGION')

    if aws_default_region is None:
        if aws_region is None:
            aws_default_region = grv_config['aws_default_region']
            if aws_default_region is None:
                print('ERROR: default AWS region not set in environment')
                sys.exit(1)

    p_dict['DefaultRegion'] = aws_default_region

    return p_dict
    # End of get_account_info


# --------------------------------------------------------------------
#
# get_user_info
#
# --------------------------------------------------------------------
def get_user_info():
    p_dict = {}

    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()

    p_dict['UserId'] = response['UserId']
    p_dict['AccountNumber'] = response['Account']
    p_dict['Arn'] = response['Arn']

    return p_dict
    # End of get_user_info

    
# --------------------------------------------------------------------
#
# find_restricted_regions
#
# --------------------------------------------------------------------
def find_restricted_regions():
    restricted = False
    reg_list = GRV.region_resolver(allregions=True)

    cleaned_list = reg_list.copy()
    genuine_grv = [{'Name': 'tag-key', 'Values': ['grv_create_session_id']}]

    for entry in reg_list:
        try:
            ec2 = boto3.client('ec2', region_name=entry)
            vpcs = ec2.describe_vpcs(
                DryRun=False, Filters=genuine_grv)['Vpcs']
        except Exception as ex:
            cleaned_list.remove(entry)
            restricted = True

    return cleaned_list, restricted
    # End of find_restricted_regions


# --------------------------------------------------------------------
#
# handle_boto_error
#
# --------------------------------------------------------------------
def handle_boto_error(ex):
    """
    Args:
        ex - error dict from ClientError

    Returns:
        r_dict - dict with error information
    """
    RS = ReturnStatus()
    r_dict = gen_return_dict("In handle_boto_error")

    e_dict = {}

    e_dict['ErrorCode']    = ex.response['Error']['Code']
    e_dict['ErrorMessage'] = ex.response['Error']['Message']
    e_dict['ErrorType']    = ex.response['Error']['Type']
    e_dict['HttpStatus']   = ex.response['ResponseMetadata']['HTTPStatusCode']
    e_dict['RequestId']    = ex.response['ResponseMetadata']['RequestId']
    e_dict['RawError']     = ex.response

    r_dict['status'] = RS.FAIL
    r_dict['msg']    = e_dict['ErrorMessage']
    r_dict['data']   = e_dict

    return r_dict
    # End of handle_boto_error


# --------------------------------------------------------------------
#
# shallow_dict_copy
#
# --------------------------------------------------------------------
def shallow_dict_copy(source_dict: dict, target_dict: dict):
    """
    This function copies the contents of a source dict to a
    target dict.

    Args:
        Source_dict: the source of the key/value pairs
        Target_dict: the target of the key/value pairs

    Returns:
        None
    """
    source_keys = source_dict.keys()
    for key in source_keys:
        target_dict[key] = source_dict[key]

    return
    # End of shallow_dict_copy


# --------------------------------------------------------------------
#
# which_region
#
# --------------------------------------------------------------------
def which_region() -> str:
    """
    This function return the name of the current region based on
    the return values of environment variables

    Args:
        None

    Returns:
        the current region
    """

    region = ''
    this_region = 'us-east-1'

    aws_region = os.getenv('AWS_REGION')
    aws_default_region = os.getenv('AWS_DEFAULT_REGION')

    if not aws_region and not aws_default_region:
        # Region not defined in env, use us-east-1
        region = this_region
    elif aws_region and not aws_default_region:
        region = aws_region        
    elif not aws_region and aws_default_region:
        region = aws_default_region
    else:
        # Both are defined
        if aws_default_region.lower() == aws_region.lower():
            region = aws_default_region
        else:
            region = aws_default_region

    return region
    # End of which_region


# --------------------------------------------------------------------
#
# verify_arcade_name
#
# --------------------------------------------------------------------
def verify_arcade_name(arcade_name:str) -> dict:
    """
    This function takes the name of an arcade and checks to see if
    the name is a proper DNS name and looks for the arcade (AKA VPC)
    is found in the current region. If not found in the current region
    a search is performed across all the AWS regions. WARING: A search
    across all the AWS regions can be VERY expensive, up to 60 seconds.

    You have been warned.
    
    Args:
        arcade_name: The name of the arcade to be verified.
        
    Returns:
        r_dict: A dict containing the status, data, and msg
        
    """
    RS = ReturnStatus()
    r_dict = gen_return_dict("In verify_arcade_name")

    debug = False
    if debug:
        print("In which region.")

    p_dict = {}
    p_dict['ArcadeName'] = arcade_name

    arcade_found = False
    first_time = True
    debug = False

    if not arcade_name.endswith('.arc'):
        arcade_name = f"{arcade_name}.arc"

    #'^[a-z0-9][._a-z0-9]*\.[a-z]+$'
    name_regex_inspect = re.search('^[a-z0-9][._a-z0-9]*\.[a-z]+$', arcade_name)
    if name_regex_inspect is None:
        r_dict['status'] = RS.FAIL
        r_dict['msg'] = f"{arcade_name} is NOT a well formed Arcade name."
        r_dict['data'] = ''
    else:
        default_region = which_region()
        
        r_dict = search_by_region(arcade_name, default_region)
        if r_dict['status'] == RS.FOUND:
            arcade_found = True
        else:
            region_list, restricted = find_restricted_regions()
            region_list.remove(default_region)
            r_dict = get_account_info()
            shallow_dict_copy(r_dict, p_dict)

            debug = True
            while not arcade_found and len(region_list) > 0:
                region = region_list[0]
                if debug:
                    print(f"Region: {region}")
                region_list.remove(region)
                r_dict = search_by_region(arcade_name, region)
                if r_dict['status'] == RS.FOUND:
                    arcade_found = True

        if r_dict['status'] == RS.FOUND:
            r_dict['status'] = RS.OK
        else:
            r_dict['msg'] = f"Arcade, {arcade_name}, was NOT found in any region."
            r_dict['status'] = RS.NOT_OK
        
    return r_dict
    # End of verify_arcade_name


# --------------------------------------------------------------------
#
# search_by_region
#
# --------------------------------------------------------------------
def search_by_region(arcade_name: str, region: str) -> dict:
    """
    This function searches for a given arcade (AKA VPC) in a
    given region. The return is a standard r_dict structure.
    
    Args:
        arcade_name: The arcade/VPC to seach for
        region: The region to seach in
        
    Returns:
        r_dict: A dict containing status, data, and msg
    """
    RS = ReturnStatus()
    r_dict = gen_return_dict("In search_by_region")

    debug = False
    if debug:
        print("In which region.")

    arcade_found = False
    loop_count = 0
    r_dict['status'] = RS.NOT_FOUND
    r_dict['msg'] = f"Arcade, {arcade_name}, was NOT found in region {region}."

    try:
        ec2_client = boto3.client("ec2", region_name=region)
        response = ec2_client.describe_vpcs()
        vpcs = response['Vpcs']
        vpc_count = len(vpcs)
        
        while loop_count <= vpc_count:
            for entry in vpcs:
                loop_count += 1
                if arcade_found:
                    break

                if 'Tags' in entry:
                    tags = entry['Tags']
                    for tag in tags:
                        key   = tag['Key']
                        value = tag['Value']
                        if 'Name' in key:
                            if debug:
                                print(f"Region: {region} - Key: {key} - Value: {value}")

                        if arcade_name in value:
                            arcade_found = True
                            r_dict['status'] = RS.FOUND
                            r_dict['msg'] = f"Arcade, {arcade_name}, was found in region {region}."
                            break
                        # End of if
                    # End of for loop
                # End of if
            # End of for loop
        # End of while

    except ClientError as c_e:
        r_dict = handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        r_dict['status'] = RS.FAIL

    return r_dict
    # End of search_by_region


# --------------------------------------------------------------------
#
# get_account_dict
#
# --------------------------------------------------------------------
def get_account_dict() -> dict:
    """
    This function returns the basic info about the currently used
    AWS account.

    Args:
        None

    Returns:
        Respose: the dict from the boto call
    """

    client = boto3.client('sts')
    response = client.get_caller_identity()

    return response
    # End of get_account_dict


# --------------------------------------------------------------------
#
# get_account_id
#
# --------------------------------------------------------------------
def get_account_id() -> dict:
    """
    This function returns the AWS account number.

    Args:
        None

    Returns:
        account number: the account number of currently used AWS account
    """

    return get_account_dict()['Account']
    # End of get_account_id


# --------------------------------------------------------------------
#
# validate_aws_creds
#
# --------------------------------------------------------------------
def validate_aws_creds():
    try:
        client = boto3.client('s3')
        response = client.list_buckets()
        return True

    except Exception as e:
        print("The credentials provided were rejected by AWS.  Check the key and secret or if using SSO ensure the session is not expired.")
        sys.exit(1)
    # End of validate_aws_creds
