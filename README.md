# ARCADE 2022

This repository contains the complete ARCADE toolkit.  This README covers:

- [Local tool setup](#tool-setup-in-detail)
- [How to light an ARCADE](#building-an-arcade)



---

# Tool Setup in Detail

## Fetching the ARCADE Tools for Use

### Step 1) Download the current ARCADE software release, zip or tbz.

> NOTE: Alternatively, you may clone this repository (instead of using the packaged software):

> `% cd /path/of/your/choice`
>
> `% git clone <THIS REPO>`

> The master branch will always track the latest release.

You may set the tools to live in your $PATH for use.  There is a helper program here which shows you what to configure on your system:[^1],

```
% ./bin/arcade-tools-setup
```


### Step 2) Pre-requisite Tools and Setup

This document assumes your AWS environment is already set up and working:

- [aws-cli installed on your computer](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [AWS API credentials configured for your IAM user in an AWS account](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html)
- ARCADE tooling operates on one AWS account at a time, based on your AWS credentials[^okta] configured for [aws-cli](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
- ASTEROIDS operations require users have [Kubernetes command line tools installed](https://kubernetes.io/docs/tasks/tools/install-kubectl-macos/).[^kubectl]

### Step 3) Setting up the tool and environment.

- ARCADE tooling has a small list of python dependendcies, (particularly boto3), listed in [requirements.txt](./requirements.txt) in this repository.  Installation via pip is simple, but you may install them however you wish:

```
% pip3 install -r requirements.txt
```

Once prerequeites are installed, you can test if your AWS environment is working:

> `% arcade test aws -v`


> NOTE: ARCADE build, scratch, and temporary files are written to a tmp/ directory, the default location is `${HOME}/tmp/arcade`.
>
> If you prefer to change this location, you may set an ENV var in your profile,
>
> `% for ~/.bashrc ~/.zshrc or ~/.profile`
>
> `% export ATMP=$HOME/any/path/your_user_can_write_to`

> The examples which follow assume you have unpacked or cloned the `arcade/` software directory in your home directory.  Adjust the following setup, to wherever you have put this software[^atmp].

```
% arcade
```

To list every available subcommand, and usage reference:

```
% arcade help
```

Every `arcade` subcommand should have an `-h` option, e.g. `arcade <command> -h' provides use information for that specific command.
```
% arcade test aws -h
```

The `arcade` script will honor a number of environment variables. To view a list of those that are currently set in your environment, run this command.
```
% arcade env
```


# **Building an ARCADE**

# GRAVITAR

### Gravitar Quickstart

>Gravitar is the only layer which can be used standalone, these tools can build base ARCADE plumbing in your account on-demand, from one command.
>
> In it's shortest form, the following command will create an ARCADE VPC and base components:
> `% arcade grv create -y`
>
> You may use this base ARCADE to build anything else on top of it, using your own cloud tooling or move on to using the subseqent GALAGA and ASTEROIDS tools.

The following will create the initial arcade, which in AWS parlance is a
VPC. This command takes about 10-15 minute to complete.

NOTE: *If this is the first time running this `Arcade` tool set on a fresh aws account then you will need to run :*

```
% arcade grv init
% ./libexec/galaga-modules/asteroids-eks/asteroids-eks-init -v
```


> `% arcade grv create -r ${AWS_REGION}`

Detailed interactive questions follow before proceeding to create an ARCADE.  These questions write a JSON manifest to a temp directory, and do not write anything to AWS until a user is prompted to begin.

An ARCADE create operation may safely be stopped or killed at any time, and can be safely be re-started any time.  See the `arcade grv -h` for information on using the `-i` command, (the retry command is also printed to screen just before the create operation starts).

ARCADE creation at the GALAGA layer typically takes between 10-30 minutes.  When create completes, you will have a uniquely named VPC and base components.

__Note__: For convenience, we recommend setting the ARCADE_NAME environment variable so you can copy/paste commands.

> `% export ARCADE_NAME=<ArcadeNameHere>`

# **GALAGA**

Galaga installs infrastructure service modules operate on top of the GRAVITAR layer, providing infrastructure services which operate on top of the GRAVITAR layer.
You may build on top of any of the GALAGA services inside your ARCADE VPC, most notably you may use the EKS cluster as-is.

## Run Galaga to create infrastructure for Asteroids.

> `% arcade galaga create -A $ARCADE_NAME -p galaga/asteroids/default.json`

Note: This will take a while... 20-50 minutes depending on what all is in your galaga description.

___

A one-time GALAGA setup for a new AWS account.

## **GSD documents**

A GSD is a JSON document that describes one Galaga service. These documents will get uploaded to the Galaga Service Directory, a repository that maintains versioned copies of GSDs that can be referenced when creating a Galaga layer.
___

### **List your available GSDs from the Galaga Service Directory**


```
% arcade galaga find  --gsd
```

```bash
gsd/alb/1/2022/04/25/18/34/f3c495fb01fef6bbd1aa614d6f00344e.json
gsd/alb/default.json
gsd/alb/latest/latest.json
gsd/eks/1/2022/04/25/18/34/0b6df0cee465986c245ed7ed3acd3823.json
gsd/eks/default.json
gsd/eks/latest/latest.json
gsd/nodegroup/3/2022/04/25/18/34/9993e77453a68393f61a5e89a9452339.json
gsd/nodegroup/default.json
gsd/nodegroup/latest/latest.json
gsd/parameterstore/1/2022/04/25/18/38/4ba78fe23722b8c369ff19ff65835e24.json
gsd/parameterstore/latest/latest.json
gsd/secretsmanager/1/2022/04/25/18/35/538de7a6433a9f5e821408c88abbf648.json
gsd/secretsmanager/default.json
gsd/secretsmanager/latest/latest.json
```

## **GALAGA documents**
A Galaga document is a JSON description of an infrastructure to be installed. It contains references to all the GSDs to be included as well as provides overrides for some of the settings defined within the GSD. This allows the Galaga creator to override default values defined in the GSD with new values (ex. EKS version number).

___

### You can see the currently uploaded Galaga JSON documents


```
% arcade galaga find --galaga
```

```bash
galaga/default/1/2022/04/26/20/02/d77dd938cc93258c4940d4df1aea70d4.json
galaga/default/default.json
galaga/default/latest/latest.json
```
___
# Asteroids

## Pre-requisites
You must have created an ARCADE with both the GRAVITAR and GALAGA layers, including the GALAGA EKS and Nodegroup modules.

This demo will walk you through configuring and running a simple asteroid with a frontend and a backend.

__Note__: For convenience, we recommend setting the ARCADE_NAME environment variable so you can copy/paste commands.

> `% export ARCADE_NAME=<ArcadeNameHere>`

Additoinally, this demo operates under the assumption that you are inside the `./misc/asteroids/webapp-demo` directory.

## Upload ASDs

Before you can create an Asteroid, you have to upload the ASDs (Asteroid Service Descriptions) you plan to add to said asteroid. An "Asteroid Service" can be any service which is deployable as a container artifact, or an Asteroid-supported AWS managed service like RDS. In this demo, each ASD will become a k8s deployment. Keep track of the S3 paths that these commands spit out; you'll need them later. The schemas for ASDs and Asteroids can be found in "misc/asteroids/schema" in the arcade repo.

> `% arcade asd upload -f misc/asteroids/webapp-demo/backend/demo-woof.json`
>
> `% arcade asd upload -f misc/asteroids/webapp-demo/frontend/demo-aarf.json`

## List ASDs

If you want to see which ASDs are already available, or lost track of one you uploaded, you can use

```
% arcade asteroid find --asd
```

To see the contents, you can do

```
% arcade asteroid cat -p <path to asd file>
```

## Create Asteroid

An Asteroid is a collection of services. These services are co-located in the same namespace/security group and it can be assumed that network connectivity between all the defined components are allowed.

> `% export ASTEROID_NAME=<AsteroidNameHere>`

> `% arcade asteroid create -a $ASTEROID_NAME`

Now add the ASD files to your Asteroid:

> `% arcade asteroid add -a $ASTEROID_NAME -p <backend_path_from_earlier>`
>
> `% arcade asteroid add -a $ASTEROID_NAME -p <frontend_path_from_earlier>`

### Side Note on Customization

Options defined in the ASD in the "service_options" section can be overridden in the Asteroid json to further customize the Asteroid. This example will override "desired_count" to make the Asteroid run 2 instances of the service instead of the default 1.

```
% arcade asteroid add -a ${ASTEROID_NAME} -p <s3_path_to_either_asd> -o service_options/desired_count=2
```

You can also set environement variables as follows:

```
% arcade asteroid add -a $ASTEROID_NAME -p <backend_path_from_earlier> -c my_custom_env=iptoolsftw
```

Key/val pairs defined will be created as a configmap in kubernetes and mounted as environment variables within the pods that are created.

Additionally, if you wanted to specify environement variables that are going to be used a lot, you can edit the ASD itself (just be sure to update your Asteroids to use the new one). Simply edit the `application_config` section of the ASD.

### Uploading

Now upload the asteroid to S3. Once again, pay attention to the S3 path:

> `% arcade asteroid upload -a $ASTEROID_NAME`

Enabling the asteroid doesn't turn another on; it generates the files that will be needed when we run `narc reconcile` later.

> `% arcade asteroid enable -p <pathFromUpload>`

## Upload Secrets

Before we can run our asteroid, we need to upload a few files for it to use. Normally you would focus on config files here and leave application files baked into the image, but since we wanted to use a publicly available image we have application files that need to be mounted when we spin up out asteroids. Configuration file are stored in secretesmanager using the following format:

- key = filename:/path/where/you/want/it
- value = base64 value of the data

If you don't specify a path for the file, it will be mounted to `/etc/arcade/configs`. Note that all the paths are treated as mountpoints, so if the image contains files in the same path they will be overwritten.

For the arcade tooling to be able to find the secrets, they need to be stored in the correct format. Namely, the secret name should be of the form `<ArcadeName>/<AsteroidName>/<ServiceNameFromASD>/configs/`. There is some tooling included in this demo to speed up the process of generating the base64-encoded secrets and uploading them (see below).

> `% python3 misc/asteroids/webapp-demo/backend/configs.py`

> `% aws secretsmanager create-secret --name ${ARCADE_NAME}/${ASTEROID_NAME}/backendwoof/configs/ --secret-string file://misc/asteroids/webapp-demo/backend/configs.json`

> `% python3 misc/asteroids/webapp-demo/frontend/configs.py`

> `% aws secretsmanager create-secret --name ${ARCADE_NAME}/${ASTEROID_NAME}/frontendaarf/configs/ --secret-string file://misc/asteroids/webapp-demo/frontend/configs.json`


Feel free to log in to secretsmanager and confirm that everything is there. Note that if you make changes to these files, you will need to change `create-secret` to `update-secret` and `--name` to `--secret-id`.

## Reconcile

NARC is the backend tooling that turns on and off computers. It functions as a reconcile loop (similar to kubernetes). When reconcile is ran it will look to both the orchestration system (kubernetes) as well as AWS (for managed services like RDS) to determine what is and isn't running and will make the real world look like what the configuration defines. It will turn on services that are not currently running, and it will destroy services that are running and shouldn't be.

> `% arcade narc reconcile`

> `% arcade config kubectl -A $ARCADE_NAME`

> `% kubectl edit svc frontendaarf -n $ASTEROID_NAME`

Change "NodePort" to "LoadBalancer"

## Try it out
The Asteroid List command will give the user a view of the currently running Asteroids and the services contained within them.

> `% arcade asteroid list -A ${ARCADE_NAME}`

> `% kubectl get deployments --all-namespaces`

> `% kubectl describe svc frontendaarf -n $ASTEROID_NAME`

Grab the "LoadBalancer Ingress" url. It will take a few minutes for the DNS records to update.

Visit `http:<url>:5000/index.html` in your browser (the `/index.html` _is_ required). If you added a custom backend configuration variable earlier, it should show up in the ENV section of the page.

## Tear it down

> `% arcade asteroid disable -a $ASTEROID_NAME`

> `% arcade narc reconcile`

> `% kubectl get deployments --all-namespaces`

## Additonal Services

Vault Enterprise - not currently maintained

SuperService - not currently maintained


## Additional Reading

- `% arcade help` - this is the reference manual for the arcade tool.
- `% arcade -h` - basic usage output for the arcade tool
- `% arcade <subcommand> -h` - basic usage output for any subcommand
- [ARCADE FAQ](docs/README.FAQ.md)


[^1]: A proper software installer in underway which will allow ARCADE users to install the software wherever they wish on their system, and most importantly, will ensure the arcade commands are in a user's $PATH.

[^okta]: ARCADE can operate with IAM users under AWS SSO, simply by using the credeitials configured in AWS-CLI.

[^kubectl]: Kubernetes tools are currently very useful for container based ASTEROIDS, but future tooling will not require Kubernetes tools to be installed or used to perform ARCADE operations.
