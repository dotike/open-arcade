# ASTEROIDS

Documentation on how to complete common tasks within Asteroids.

# System Architecture
______________

## Reconcile

The NARC (name of project) Reconcile process was designed to run as an independent application that will continuously loop and perform any required operations to the Arcade(s).  All direct system operations (turning on/off services or machines) is handed by Reconcile.  Working as a loop Reconcile will handle operations in a certain order.

1. CREATE - Any service that needs to be created
2. DELETE - Any service to be terminated
3. UPDATE - Check every live service for a diff between what's running and what's defined and modify service to make changes
4. RESTART - If a service(s) is flagged for restart one will be performed using the rollout restart functionality in Kubernetes

Within each operation stage all services requiring that operation will have it performed in parallel to cut down on wait time.  This is unless the parallelization is disabled through use of an "Order:" directive within the Asteroid JSON document (which is discouraged but there to facilitate software that cannot run in parallel like AMP components).

# JSON Anatomy
______________

## Structure of an Asteroid Service Description (ASD)
An Asteroid Service Description (ASD) is a json document defining a specific Asteroid service.
An "Asteroid Service" can be any service that is deployable as a container artifact, or a supported 
AWS managed service like RDS.

Example ASD for a K8s based service:
```json
{
   "service": "service1",
   "description": "Build of service1 to use with Asteroids",
   "version": 1,
   "component_type": "k8s",
   "containers": [
      {
         "name": "service1",
         "image": "023960176222.dkr.ecr.us-east-2.amazonaws.com/service1:latest",
         "readiness_check_path": "/overall-health/readiness",
         "readiness_check_port": 5463,
         "cpu": 1,
         "cpu_limit": 2,
         "mem": 3096,
         "mem_limit": 3096,
         "port_mappings": [
            {
              "port": 5463,
              "port_name": "healthcheck"
            },
            {
              "port": 5464,
              "port_name": "communication"
            }
         ]
      }
   ],
   "service_options": {
      "alerting": true,
      "desired_count": 1,
      "load_balanced": {
          "public": false,
          "private": false
      }
   },
    "application_config": {
        "project": "demo",
        "JVM_OPTS": "-XX:+UseG1GC -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=localhost:5005 -Xlog:gc=info,gc+cpu=info:stdout:time,uptime,level,tags -Dlog4j2.formatMsgNoLookups=true",
        "CUSTOM_HEAP_PERCENT": "80",
        "MYSQL_HOST": "aoaxtestdb",
        "KAFKA_HOSTS": "kafka:9094",
        "ZOOKEEPER_HOSTS": "zookeeper:2181"
    },
    "tags": {
        "tag1": "value1",
        "tag2": "value2"
    },
    "metadata": {
        "Service Name": "service1",
        "Description": "Generic service to be used with Asteroids",
        "Owner": "IP ENG"
    }
}
```

| FIELD                  | USER DEFINED? | DESCRIPTION                                                                                           |
|------------------------|---------------|-------------------------------------------------------------------------------------------------------|
| **service**            | YES           | Name of the service                                                                                   |
| **description**        | YES           | Description of the service defined in this ASD                                                        |
| version                | NO            | Document structure version                                                                            |
| **component_type**     | YES           | Type of service (k8s or rds currently)                                                                |
| **containers**         | YES           | Defines N number of containers that are part of the service                                           |
| **service_options**    | YES           | Service specific config options                                                                       |
| **application_config** | YES           | Key/value pairs of data that will be published into the service's containers as environment variables |
| **tags**               | YES           | Key/value data that will be serialized as AWS tags or K8s labels on created resources                 |
| **metadata**           | YES           | Key/value pairs of data that will remain in the ASD and can be used by external scripts               |

Containers Section (Can have N number of containers in a service)

| FIELD                       | USER DEFINED? | DESCRIPTION                                                     |
|-----------------------------|---------------|-----------------------------------------------------------------|
| **name**                    | YES           | Name of the container inside K8s                                |
| **image**                   | YES           | Docker image path (within ECR)                                  |
| **readiness_check_path**    | YES           | HTTP endpoint for healthchecking the service                    |
| **readiness_check_port**    | YES           | The port the healthcheck endpoint is running on                 |
| **cpu**                     | YES           | Required number of CPU shares                                   |
| **cpu_limit**               | YES           | Max amount of CPU shares desired if available                   |
| **mem**                     | YES           | Required amount of memory in MB                                 |
| **mem_limit**               | YES           | Max amount of memory desired if available                       |
| **port_mappings**           | YES           | N number of port mappings to create within K8s to the container |
| **port_mappings:port**      | YES           | The port number desired                                         |
| **port_mappings:port_name** | YES           | The name for the port mapping within K8s                        |

Service_options Section

| FIELD                     | USER DEFINED? | DESCRIPTION                                                                                   |
|---------------------------|---------------|-----------------------------------------------------------------------------------------------|
| **alerting**              | YES           | Boolean defining whather or not the service should have alerting enabled (currently not used) |
| **desired_count**         | YES           | The number of instances for the service desired                                               |
| **load_balanced:public**  | YES           | Boolean for whether or not to provision a PUBLIC (inet) facing ALB endpoint                   |
| **load_balanced:private** | YES           | Boolean for whether or not to provision a PRIVATE (within AWS only) facing ALB endpoint       |

Example ASD for an RDS based service:
```json
{
    "service": "rdsservice",
    "description": "RDS database",
    "version": 1,
    "component_type": "rds",
    "containers": [
       {
           "name": "rdservicetest",
           "instance_type": "db.m4.large",
           "storage": 25,
           "engine": "mysql",
           "engine_version": "8.0.23",
           "username": "admin",
           "multiAZ": false
       }
    ],
    "service_options": {
       "alerting": true
    }
}
```

## Structure of an Asteroid Document (Asteroid)

An Asteroid is a collection of Asteroid services. These services are co-located in the same namespace/security group and 
it can be assumed that network connectivity between all the defined components are allowed.

```json
{
    "user": "snake.plissken",
    "createTime": "2021/11/12/21/41",
    "name": "myasteroid",
    "version": 1,
    "metadata": {},
    "tags": {},
    "services": {
        "service1": {
            "location": "asd/service1/1/2022/08/19/20/15/990bd7997c5c470486eeb7024f9d3d52.json",
            "overrides": {},
            "config_overrides": {}
        },
        "service2": {
            "location": "asd/service2/1/2022/08/19/20/14/0e70c76f93fbc26610768826968d6f73.json",
            "overrides": {},
            "config_overrides": {}
        }
    },
    "namespace": "myasteroid",
    "environment": "dev",
    "desired_state": "",
    "narc_dict": {}
}
```


| FIELD         | USER DEFINED? | DESCRIPTION                                                                                 |
|---------------|---------------|---------------------------------------------------------------------------------------------|
| user          | NO            | The username of the user creating the document                                              |
| createTime    | NO            | Timestamp of document creation                                                              |
| **name**      | YES           | Name of asteroid                                                                            |
| version       | NO            | Document structure version                                                                  |
| **metadata**  | YES           | Key/value data associated with an Asteroid that can be consumed by third party scripts      |
| **tags**      | YES           | Key/value data that will be serialized as AWS tags or K8s labels on created resources       |
| **services**  | YES           | Defines N number of services that are part of the Asteroid                                  |
| namespace     | NO            | Kubernetes namespace the Asteroid k8s services will exist within                            |
| environment   | NO            | Short name designating what environment this Asteroid is a part of (not currently used)     |
| desired_state | NO            | Control field used by the Arcade tooling to express changes in state (enable, disable, etc) |
| narc_dict     | NO            | Control field for reconcile operations                                                      |

Services Section, each section named by service name:

| FIELD                | USER DEFINED? | DESCRIPTION                                                                                     |
|----------------------|---------------|-------------------------------------------------------------------------------------------------|
| **location**         | YES           | S3 location where the ASD definining the service could be found                                 |
| **overrides**        | YES           | Parameter overrides for ASD defined service options                                             |
| **config_overrides** | YES           | Overrides for the application_config section of an ASD.  Can append or override key/value pairs |


# Common Setup Operations
_________________________

## Getting images into ECR

EKS clusters deployed by Galaga for use by Asteroids use images stored in Elastic Container Repository (ECR) and not Docker Hub.
Any Docker images that are to be deployed as Asteroids can be pulled from Docker Hub or built on your workstation.  You 
then can upload them to ECR and those images can be accessed by EKS.

The steps to tag and upload an image to ECR (taken from AWS ECR console):

1. Login to ECR with Docker

   `aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ACCOUNT_NUMBER}.dkr.ecr.us-east-2.amazonaws.com`
2. Tag image with desired tag name

   `docker tag docker-container:tagname ${ACCOUNT_NUMBER}.dkr.ecr.us-east-2.amazonaws.com/docker-container:tagname`

3. Push image into ECR

   `docker push ${ACCOUNT_NUMBER}.dkr.ecr.us-east-2.amazonaws.com/docker-container:tagname` 


## Getting secrets and config data into containers

One thing common with all services are that they require secrets and configs to function.  While there are many ways to 
accomplish this task, Asteroids has three mechanisms to push data into containerized services.  

### Application Config (non-secret configuration data)
The simplest way to get data into a container in a manor that is referencable by an application is by using the 
"application_config" section of the ASD/Asteroid JSON.  This section holds user defined key/value pairs of data that will 
be published into containers as Environment Variables.  The key will become an all uppercase variable name and the value 
will be the value.  This is performed by the reconcile process where a configmap will be created within Kubernetes and 
populated.  That configmap will be mounted as Environment Variables in the relevant containers.  The ASD can define some 
key/value pairs that can be appended to or overwritten by the config_overrides section of the Asteroid document.  This 
enables the creator of the ASD to provide some sane defaults that can be overwritten by the user of the ASD in the Asteroid document.
This data should not be considered "secret" as the data will exist in S3, passed around in github, and pushed as Environment Variables.

Example application_config section in ASD json:
```json
    "application_config": {
        "project": "demo",
        "JVM_OPTS": "-XX:+UseG1GC -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=localhost:5005 -Xlog:gc=info,gc+cpu=info:stdout:time,uptime,level,tags -Dlog4j2.formatMsgNoLookups=true",
        "CUSTOM_HEAP_PERCENT": "80",
        "MYSQL_HOST": "aoaxtestdb",
        "KAFKA_HOSTS": "kafka:9094",
        "ZOOKEEPER_HOSTS": "zookeeper:2181"
    },
```

### Secrets Manager Secrets (secret or non-secret configuration data)
To store sensitive data we use Amazon Secrets Manager.  You can upload key/value pairs of data to secrets manager and 
the reconcile process will build a secrets object in Kubernetes and mount it into the appropriate containers as 
Environment Variables.

**When uploading to Amazon Secrets Manager use whatever REGION your Arcade is running in and use the path:**

`${ARCADE_NAME}/${ASTEROID_NAME}/${SERVICE_NAME}`

### Secrets Manager Files (secret or non-secret data residing on filesystem)
Sometimes you will prefer to have files on the filesystems (config files, ssl certificates, etc) instead of Environment Variables.  
To do this you will also use Amazon Secrets Manager.  You can specify the path that a file should reside within, or if 
no path is specified the default location is `/etc/arcade/configs/`.

The path within Secrets Manager that you will place config files is:
`${ARCADE_NAME}/${ASTEROID_NAME}/${SERVICE_NAME}/configs/${FILENAME}`

**Important:** The data uploaded to Secrets Manager MUST be Base64 encoded!

Uploading to Amazon Secrets Manager where the file will deploy in a custom path `/my/custom/path` append the path to the filename:

`FILENAME = config_file_name:/my/custom/path`

# Common Workflows
__________________

## Create and deploy a new Asteroid

These are the basic steps to create and deploy your own Asteroid

1. Build a new ASD json document.  This can be done manually in a text editor or in an automated fashion like from a Jenkins job.
   The section on ASD Anatomy can help with the structure of this document.


2. Upload the ASD(s) to the Asteroid Service Directory

   `$ arcade asd upload -f servicename.json`

    >`asd-7737cbfb8a57f71c43d41dfac2a2631e asd/servicename/4/2022/09/06/20/10/cb9b980d4a3cac8e7afaedef2815fa90.json`
 
3. Build a new Asteroid json document.  The following tools (asteroid-create, asteroid-add) will help to construct an 
   Asteroid JSON document. In this document you can specify which versions of the services defined via ASD you wish to 
   include and also this is where you can override values defined within the ASD (set custom memory, cpu, configuration settings).

   `$ arcade asteroid create -a asteroid-name`

    > `Asteroid asteroid-name is created under /Users/snake.plissken/tmp/arcade/asteroid-name.json`

4. Add the desired services to the Asteroid by referencing the ASD(s).  Use the reference to the uploaded file in S3 
   from the previous step.

   `arcade asteroid add -a asteroid-name -p asd/servicename/4/2022/09/06/20/10/cb9b980d4a3cac8e7afaedef2815fa90.json`

   > `Asteroid asteroid-name is modified under /Users/snake.plissken/tmp/arcade/asteroid-name.json`


5. Cat the constructed Asteroid document to verify the contents
    `$ cat /Users/snake.plissken/tmp/arcade/arcade-name.json`
    ```json
    {
        "user": "snake.plissken",
        "createTime": "2022/09/06/20/15",
        "name": "asteroid-name",
        "version": 1,
        "metadata": {},
        "tags": {},
        "services": {
            "servicename": {
                "location": "asd/servicename/4/2022/09/06/20/10/cb9b980d4a3cac8e7afaedef2815fa90.json",
                "overrides": {},
                "config_overrides": {}
            }
        },
        "namespace": "asteroid-name",
        "environment": "dev",
        "desired_state": "",
        "narc_dict": {}
    }
    ```
6. Upload the Asteroid json document to the S3 bucket

    `$ arcade asteroid upload -f /Users/snake.plissken/tmp/arcade/asteroid-name.json`

    > `asd-7737cbfb8a57f71c43d41dfac2a2631e asteroid/asteroid-name/1/2022/09/06/20/23/29f2371dad30835b344a6ca05b473eae.json`

7. Enable your Asteroid:

   This process will perform an operation where the Asteroid document and all referenced ASD documents are combined to make up 
   what we call "Hydrated ASDs".  These files look like an ASD but take into account any and all override data provided 
   in the Asteroid document.

   `$ arcade asteroid enable -a asteroid-name`


8. Reconcile your Arcade
   This process will go through all Asteroids looking for Asteroids that have updates to apply, new Asteroids that need 
   to be created, and old Asteroids that need to be deleted.

   `$ arcade narc reconcile`

## Disable/Delete a running Asteroid

To delete a running Asteroid you will have to disable it.  Disabling removes all running resources associated with an Asteroid 
but the Asteroid and ASD documents remain in S3 so it can be re-enabled at a later time.

1. Disable the Asteroid

   `$ arcade asteroid enable -a asteroid-name`


2. Reconcile

   `$ arcade narc reconcile`

## How to create an Alias

When referencing Asteroid documents and ASD documents when building an Asteroid it can be a bit tedious to use the full 
path to the file within S3 as a reference to it.  An Alias is a named pointer to a specific ASD or Asteroid document that 
you can reference when building an Asteroid by adding ASDs or enabling an Asteroid.

To create/edit an Alias for an ASD or Asteroid document use the arcade asteroid alias command:

`arcade asteroid alias -a ${ASTEROID_NAME} -t ${ALIAS_NAME}`

>`arcade asteroid alias -p asd/nginxwoof/4/2022/09/06/20/10/cb9b980d4a3cac8e7afaedef2815fa90.json -t aliastest`

To find the document an alias points to use the command arcade asteroid show-alias command:

`arcade asteroid show-alias -a ${ASTEROID_NAME} -t ${ALIAS_NAME}`
`arcade asteroid show-alias -s ${SERVICE_NAME} -t ${ALIAS_NAME}`

```
$ arcade asteroid show-alias -a test -t prodasteroid
Alias prodasteroid (asteroid/test/prodasteroid.json) associated with Asteroid asteroid/test/1/2022/09/06/20/23/29f2371dad30835b344a6ca05b473eae.json
```

To find aliases that are created you can use the arcade asteroid find-alias command:

```
$ arcade asteroid find-alias -a ${ASTEROID_NAME}
$ arcade asteroid find-alias -s ${SERVICE_NAME}
```

```
$ arcade asteroid find-alias -a test
Available aliases for asteroid test:
prodasteroid (s3://asteroid/test/prodasteroid.json)
```

## Inspect Asteroids

To inspect the contents of an ASD or Asteroid document use the `arcade asteroid cat` command:

`$ arcade asteroid cat -p asteroid/test/1/2022/09/06/20/23/29f2371dad30835b344a6ca05b473eae.json`

To list all the currently running Asteroids (and all the services within them) in an Arcade use the `arcade asteroid list` command:

```
$ arcade asteroid list -A huge_hot.arc

ASTEROID:  aoax
NARC ID                             STATUS TYPE READY CREATED               MODIFIED
narc-aoax-servicename               ACTIVE K8s   1/1  2022-08-29T18:30:22Z  2022-08-29T18:30:42Z
```

How to find the Asteroid documents of the currently running Asteroid(s):

`arcade asteroid find --enabled_asteroid`

```
arcade asteroid find --enabled_asteroid
asteroid/aoax/1/2022/10/04/22/42/27ca0cd1243e4c6c6e5904d23c6aaad1.json
```

The contents of that document can be viewed with arcade asteroid cat:

`arcade asteroid cat -p asteroid/aoax/1/2022/10/04/22/42/27ca0cd1243e4c6c6e5904d23c6aaad1.json`

## Update a running Asteroid

If you want to make changes to an existing live Asteroid you can do so by re-deploying a new Asteroid of the same name as the existing asteroid with whatever changes you need included.  This process will overwrite the existing asteroid with new parameters that reconcile will detect and deploy.

Example for running Asteroid named "myasteroid":

1. Either make a new ASD for the desired changes to a service or make changes to an Asteroid document's "config_overrides" section
2. Upload the modified documents using the Asteroid name "myasteroid" (ASD and Asteroid if ASD has changed or just Asteroid if only the Asteroid has changed)
3. Run reconcile `arcade narc reconcile`. The modifications should be detected and updates attempted.

Note: To find the current running Asteroid document run `arcade asteroid find -E`

## Reload a running Asteroid

When you make configuration or secrets changes the new values will be available on the running container's disk or environment 
variables.  If a service is built to check for changes to data it depends on these changes should be reflected in the 
live service.  For most services (and all legacy services) they won't pickup new changes until the service has been bounced.
A reload will bounce all services within an asteroid in a rolling fashion.

To perform this task you use the tool `arcade asteroid restart` to mark a service for restart.  This restart operation 
will be completed the next time reconcile is ran.

Restart one service within an asteroid:
`arcade asteroid restart -p asteroid/aoax/1/2022/08/19/20/20/27ca0cd1243e4c6c6e5904d23c6aaad1.json -s aoax-servicename`

Restart all services within an asteroid:
`arcade asteroid restart -A huge_hot.arc -p asteroid/aoax/1/2022/08/19/20/20/27ca0cd1243e4c6c6e5904d23c6aaad1.json`

## Addressing Asteroid Services

If you have an Asteroid with more than one service you likely will have the need to have services talk to each other which facilitates the need for CNAMES for DNS name resolution.  Fortunately Arcade will take care of this for you.  When a service is created (either a K8s service or RDS service) a k8s service record will be created to point at it.  In config referencing the service shortname is all you need to do to have working name resolution.
The K8s service records can be seen with the command: `kubectl get svc -n NAMESPACE`
