# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
ecr --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import base64
import logging

import docker
import boto3
from botocore.exceptions import ClientError

# --------------------------------------------------------------------
#
# pull_image
#
# --------------------------------------------------------------------
def pull_image(docker_client: docker.client.DockerClient,
               auth_token: dict,
               image_name: str) -> docker.models.images.Image:
    """
    Pull docker image from ecr to local.

    Args:
        docker_client: docker client
        auth_token: ecr authorization token
        image_name: the name of the docker image (for example batu:latest)

    Returns:
        an instance of docker.models.images.Image

    """
    username, password = base64.b64decode(
        auth_token['authorizationData'][0]['authorizationToken']
    ).decode().split(':')

    auth_config = {'username': username, 'password': password}
    registry = auth_token['authorizationData'][0]['proxyEndpoint']
    docker_client.login(username=username, password=password, registry=registry)
    pull_name = f"{registry.replace('https://', '')}/{image_name}"
    logging.info(f"Pulling docker image {pull_name}...")
    image = docker_client.images.pull(pull_name, auth_config=auth_config)

    return image


# --------------------------------------------------------------------
#
# push_image
#
# --------------------------------------------------------------------
def push_image(docker_client: docker.client.DockerClient,
               auth_token: dict,
               image: docker.models.images.Image,
               image_name: str) -> str:
    """
    Push a local image to target ecr.

    Args:
        docker_client: docker client
        auth_token: target ecr authorization token
        image: a docker image from local
        image_name: the name of the docker image (for example batu:latest)

    Returns:
        The full name of the image in target ecr.

    """
    username, password = base64.b64decode(
        auth_token['authorizationData'][0]['authorizationToken']
    ).decode().split(':')
    auth_config = {'username': username, 'password': password}
    registry = auth_token['authorizationData'][0]['proxyEndpoint']
    push_name = f"{registry.replace('https://', '')}/{image_name}"
    image.tag(push_name)

    logging.info(f"Pushing docker image {push_name}...")
    docker_client.images.push(push_name, auth_config=auth_config)

    return push_name


# --------------------------------------------------------------------
#
# copy_image
#
# --------------------------------------------------------------------
def copy_image(source_session: boto3.session.Session,
               target_session: boto3.session.Session,
               image_name: str,
               repository: str = '') -> str:
    """
    Copy a docker image from source ecr to target ecr.

    Args:
        source_session: the boto3 session for accessing source ecr
        target_session: the boto3 session for accessing target ecr
        image_name: the name of the docker image (for example batu:latest)
        repository: the repository needs to be created

    Returns:
        The full name of the image in target ecr.

    """
    source_client = source_session.client('ecr')
    source_token = source_client.get_authorization_token()

    docker_client = docker.from_env()

    image = pull_image(docker_client, source_token, image_name)

    target_client = target_session.client('ecr')
    target_token = target_client.get_authorization_token()
    target_registry = target_token['authorizationData'][0]['proxyEndpoint']

    image.tag(f"{target_registry.replace('https://', '')}/{image_name}")

    if repository:
        target_client.create_repository(repositoryName=repository)

    return push_image(docker_client, target_token, image, image_name)


# --------------------------------------------------------------------
#
# upload container to ecr
#
# --------------------------------------------------------------------

def upload_container(arcade_name: str, local_container: str, _tag='latest'):
    """Uploads a image to ECR. This will find the container locally on your computer,
    and do a docker login, then finally it will tag the container to ECR and upload to ECR.
    This is arcade scoped.

    Args:
        arcade_name (str): name of the arcade
        local_container (str): The name of the image
        tag (str, optional): The tag. Defaults to 'latest'.

    Returns:
        bool: Returns True if upload was successfully uploaded. False if there was a failure.
    """
    docker_client = docker.from_env()
    ecr_client = boto3.client('ecr')

    try:
        create_repo = ecr_client.create_repository(repositoryName=f"{arcade_name}/{local_container}")
    except ecr_client.exceptions.RepositoryAlreadyExistsException as e:
        pass

    ecr_credentials = (ecr_client.get_authorization_token()['authorizationData'][0])
    ecr_username = 'AWS'
    ecr_password = (base64.b64decode(ecr_credentials['authorizationToken']).replace(b'AWS:', b'').decode('utf-8'))
    ecr_url = ecr_credentials['proxyEndpoint'].replace('https://', '')
    docker_login = docker_client.login(username=ecr_username, password=ecr_password, registry=ecr_url)

    if docker_login['Status'] == 'Login Succeeded':
        ecr_repo_name = f"{ecr_url.replace('https://', '')}/{arcade_name}/{local_container}"
        image = docker_client.images.get(name=f"{local_container}")
        tag = image.tag(repository=ecr_repo_name, tag=_tag)
        upload = docker_client.images.push(ecr_repo_name, tag=_tag)
        logging.info(upload)
        return True, ecr_repo_name

    else:
        return False


# --------------------------------------------------------------------
#
# get_container_uri
#
# --------------------------------------------------------------------

def get_container_uri(repository_name: str) -> str:
    """
    Returns the AWS ECR URI for the named repository(container)

    Args:
        repository_name (str): name of the repository(container)

    Returns:
        str: The URI of the repository(container)
    """

    ecr_client = boto3.client('ecr')
    try:
        response = ecr_client.describe_repositories(repositoryNames=[repository_name])
    except ClientError:
        return ""

    return response['repositories'][0]['repositoryUri']
