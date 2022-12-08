# Galaga Module
---
## EKS Sumologic

### Description
_This installer will create the component infrastructure necessary for logs to get shipped to Sumologic._

* This will deploy Kubernetes Manifest that stands up fluentd/prometheus and ships logs to sumologic with a provided API key.

### Overview

* eks-sumologic-create > Stands up logging for EKS
* eks-sumologic-destroy > Destroys logging for EKS
* eks-sumologic-read > Gets the status of this module
* ~~eks-sumologic-update~~ > ___Not ready yet___

#### Imortant notes:
Sumologic API keys need to be in SecretsManger of the AWS account being used.

__format:__ `{account_name}/{secret_name}` 

We define this is the GSD like so

```json
{
    "name": "eks-sumologic",
    "component_type": "eks-sumologic",
    "version": 2,
    "description": "GSD for eks-sumologic",
    "services": {
        "sumologic": {
            "service_options": {
                "account_name": "ConeyIsland",
                "repo_name": "arcade/fluentd-kubernetes-sumologic",
                "container_name": "public.ecr.aws/sumologic/kubernetes-fluentd:latest-amd64",
                "eks_namespace_name": "fluentd",
                "sumoapi_secrets_manager_name": "sumo_keys" 
            }
        }
    }
}

```

The format would come from the `services.sumologic.service_options.account_name` for the `account_name` and `services.sumologic.service_options.sumoapi_secrets_manager_name` for the `secret_name`

Would looks somthing like this pulling from the GSD:

```python
# GSD DATA
gsd_data = storage.load_arcade_json_to_dict(bucket, args.path)
# Cut down path to JSON
service_options = gsd_data['services']['sumologic']['service_options']
# Get the account name
account_name = service_options['account_name']
# Get the Secret Name
secretsmanager_name = service_options['sumoapi_secrets_manager_name']
# Secrets Manager Call
sumo_access_id, sumo_access_key = get_sumologic_secrets(account_name, secretsmanager_name)

# Pass in the keys to the Secret Function

# --------------------------------------------------------------------
# Create Secrets
# --------------------------------------------------------------------
if not eks_sumologic_fluentd.deploy_secret(namespace=sumo_fluent_namespace, arcade_name=arcade_name, eks_cluster=eks_cluster, sumo_id=sumo_access_id, sumo_key=sumo_access_key):
    pprint(f'ERROR: Secrets failed to be created.')
    logging.info('ERROR: Secrets failed to be created.')
    sys.exit(RS.NOT_OK)
```
### Kubernetes Kind that get deployed
```
CRD
ClusterRole
ClusterRoleBinding
ConfigMap
DaemonSet
Deployment
Job
Pod
PodDisruptionBudget
PodSecurityPolicy
PriorityClass
Prometheus
Secret
Service
ServiceAccount
StatefulSet
```

### Steps to Deploy

1. Upload GSD with `arcade gsd upload` and give it a default tag with `-t`
   1. `arcade gsd upload -f libexec/galaga-modules/eks-sumologic/eks-sumologic.json -t default`
2. Create your Galaga document and add in at a minimal add in eks cluster. 
   1. `arcade galaga setup -C -p gsd/asteroids-eks/default.json -p gsd/eks-sumologic/default.json`
   2. Take a look at your document.
    ```json
     cat ~/tmp/arcade/high_sun.arc.json                                                                                                              sumologic-additions
      {
          "user": "$USER",
          "createTime": "2022/12/01/20/22",
          "name": "$ARCADE_NAME",
          "version": 1,
          "components": {
              "asteroids-eks": {
                  "location": "gsd/asteroids-eks/default.json",
                  "overrides": {}
              },
              "eks-sumologic": {
                  "location": "gsd/eks-sumologic/default.json",
                  "overrides": {}
              },
          }
      }
    ```
  3. Upload Galaga Document
     1. `arcade galaga upload -f ~/tmp/arcade/${ARCADE_NAME}.json`
  4. Execute Galaga
     1. `arcade galaga create -p galaga/${ARCADE_NAME}/latest/latest.json`

### Location of data injection in yaml files 
```Note: we can inject anywhere, but this is the current injection locations```

* `EKS_CLUSTER`
  * ___ConfigMaps.yaml___
    * `{eks_cluster}` is the variable
* `SUMO API Keys`
  * ___Secret.yaml___
    * Comes from Secrets Manger
    * Secrets Format: _This should be passed as **kwargs into `deploy_secret()` inside of `eks_sumologic_fluentd.py.` Below is the format that comes from secrets manager_
    ```json
    {'sumo_id': 'xxxxx', 'sumo_key': 'xxxxxx'}
    ```
* `Container Images`
  * ___Prometheus.yaml___
    ```yaml
    name: arcade-fluentd-kube-promet-prometheus
    image: quay.io/prometheus/prometheus:v2.22.1
    ```
  * ___Pod.yaml___
    ```yaml
    name: arcade-fluentd-fluent-bit-test-connection
    image: busybox:latest
    ```
  * ___Job.yaml___
    Maybe Change
    ```yaml
    name: arcade-fluentd-sumologic-setup
    image: public.ecr.aws/sumologic/kubernetes-setup:3.4.0
    ```
  * ___Deployment.yaml___
    ```yaml
    name: arcade-fluentd-kube-state-metrics
    image: k8s.gcr.io/kube-state-metrics/kube-state-metrics:v1.9.8
    ---
    name: arcade-fluentd-kube-promet-operator
    image: quay.io/prometheus-operator/prometheus-operator:v0.44.0
    ```
  * ___DaemonSet.yaml___
    ```yaml
    name: arcade-fluentd-fluent-bit
    image: public.ecr.aws/sumologic/:fluent-bit1.6.10-sumo-2
    ---
    name: arcade-fluentd-prometheus-node-exporter
    image: quay.io/prometheus/node-exporter:v1.3.1
    ```
  * ___StatefulSet.yaml___
    Try these
    ```yaml
    name: arcade-fluentd-sumologic-fluentd-events
    image: public.ecr.aws/sumologic/kubernetes-fluentd:1.14.6-sumo-5
    ---
    name: arcade-fluentd-sumologic-fluentd-logs
    image: public.ecr.aws/sumologic/kubernetes-fluentd:1.14.6-sumo-5
    ---
    name: arcade-fluentd-sumologic-fluentd-metrics
    image: public.ecr.aws/sumologic/kubernetes-fluentd:1.14.6-sumo-5
    ```


### Install With Helm

* Install Helm

* Add Helm Repo 

```shell
helm repo add sumologic https://sumologic.github.io/sumologic-kubernetes-collection
```

* Create a file named values.yaml

```shell
touch value.yaml
```

* Add In values

```yaml
sumologic:
    accessId: ${SUMO_ACCESS_ID}
    accessKey: ${SUMO_ACCESS_KEY}
    clusterName: ${MY_CLUSTER_NAME}
```

* Install sumologic and Fluentd to EKS

```shell
helm upgrade --install my-release sumologic/sumologic -f values.yaml
```

* Use this one for Standlone Prometheus

```shell
helm upgrade --install my-release sumologic/sumologic --set sumologic.accessId='' --set sumologic.accessKey=''  --set sumologic.clusterName="asteroids-cool_sun-arc" --set prometheus-operator.enabled=false --namespace=fluentd-test  --create-namespace
```

* Do our checks

```shell
kubectl --namespace default get all -l "release=my-release"
``` 

* Export the Kubernetes Manifest to a local `YAML` file.

```shell
helm template my-release sumologic/sumologic --values=values.yaml > export.yaml
```


### _Important Links_
* Main Github Documentation
[Main Github Doc](https://github.com/SumoLogic/sumologic-kubernetes-collection/tree/2b3ca63f4e8dc98ec7744ec4bbd9575e28455073/deploy)

* Side by Side Prometheus Install
[Side by Side Prometheus Install](https://github.com/SumoLogic/sumologic-kubernetes-collection/blob/2b3ca63f4e8dc98ec7744ec4bbd9575e28455073/deploy/docs/SideBySidePrometheus.md)

* Install for stand alone Prometheus
[Standalone Prometheus](https://github.com/SumoLogic/sumologic-kubernetes-collection/blob/2b3ca63f4e8dc98ec7744ec4bbd9575e28455073/deploy/docs/standAlonePrometheus.md)

* All Docs 
[All Sumologic Kubernetes Documentation](https://github.com/SumoLogic/sumologic-kubernetes-collection/tree/2b3ca63f4e8dc98ec7744ec4bbd9575e28455073/deploy/docs)
