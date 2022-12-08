# Setup for AWS and Kubernetes

## Before creating an ARCADE

### AWS user must have admin access and AWS cli setup

#### Using Brew to install aws cli and kubectl

Brew is installed on most Macs.

> `% brew upgrade`

> `% brew install awscli kubernetes-cli`

#### Configure aws cli

> `% aws configure`

```bash
AWS Access Key ID [None]: aldsfkjasdlfkadsf
AWS Secret Access Key [None]: alsdkfjalskdfj823aosdfjlsd
Default region name [None]: us-east-2
Default output format [None]:
```

This created 2 files.

~/.aws/config and ~/.aws/credentials

> `% cat ~/.aws/config`

```bash
[default]
region = us-east-2
```

> `% cat ~/.aws/credentials`

```bash
[default]
aws_access_key_id = aldsfkjasdlfkadsf
aws_secret_access_key = alsdkfjalskdfj823aosdfjlsd
```

### AWS user must be able to assume the "EKSAdminRole".

The policy for assuming "EKSAdminRole" should have been setup with the first EKS ARCADE cluster in an AWS account.


### Source asteroid-set to create Kubernetes context

The script asteroid-set is part of the asteroids repo.

It will setup the kubectl context and AWS environment variables.

> `% source asteroid-set <arcade name>`

```bash
current-context:
asteroids-icy_lake-grv
```
