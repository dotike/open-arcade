from arclib import eks, common
import boto3
import time
import json
from arclib import k8s
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from botocore.exceptions import ClientError
import yaml

def check_if_grafana(arcade_name: str) -> bool:
    """Checks if Grafana Instance in Aws is present or not

    Args:
        arcade_name (str): Name of the Arcade

    Returns:
        bool: True if present, False if not
    """
    arcade_found_instances = []
    client = boto3.client('grafana')
    response = client.list_workspaces()
    if len(response['workspaces']) < 1:
        return False
    else:
        for space in response['workspaces']:
            if f'{arcade_name}-grafana' in space['name']:
                arcade_found_instances.append(space['name'])
                
    if f'{arcade_name}-grafana' in arcade_found_instances:
        return True
    else:
        return False
    
    

    
def get_prometheus_grafana_role(arcade_name: str, application: str) -> bool:
    """Verifies that the Prometheus or Grafana Role is present

    Args:
        arcade_name (str): Name of the arcade
        application (str): prometheus or grafana as the application name

    Returns:
        bool: True if the role is present, False if the role is not present
    """
    if application == 'grafana':
        role_name = f'{arcade_name}-graphana-role'
    if application == 'prometheus':
        role_name = f'{arcade_name}-EKS-ARCADE-ServiceAccount-Role' 
    
    client = boto3.client('iam')
    
    try:
        response = client.get_role(RoleName=role_name)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return True
        else:
            return False
    except client.exceptions.NoSuchEntityException:
        return False


def namespace_present(arcade_name: str, namespace: str) -> bool:
    """Checks to see if a namespace is present

    Args:
      arcade_name (str): Name of the Arcade Name
        namespace (str): Name of the kubernetes namespace

    Returns:
        bool: True if namespace exists, False if the namespace does not exist
    """
    list_of_namespaces = []
    
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    except ValueError:
        return False
    
    core_v1 = client.CoreV1Api()
    
    check = core_v1.list_namespace(pretty='pretty')

    for items in check._items:
        list_of_namespaces.append(items.metadata.name)
        
    if namespace in list_of_namespaces:
        return True
    else:
        return False


def get_grafana_status(arcade_name: str):
    """Gets the status of managed grafana being created

    Args:
        arcade_name (str): Name of the arcade

    Returns:
        str: status of grafana
    """
    client = boto3.client('grafana')
    try:
        get_id = client.list_workspaces()
        workspaces = [x for x in get_id['workspaces'] if x['name'] == f'{arcade_name}-grafana']
        get_workspace_id = workspaces[0]['endpoint'].split('.')[0]
        response = client.describe_workspace(workspaceId=get_workspace_id)
        get_status = response['workspace']['status']
        return get_status
    except ClientError as e:
        return e


def get_grafana_url(arcade_name: str) -> str:
    """Returns the url of the aws managed grafana

    Args:
        arcade_name (str): Name of the Arcade

    Returns:
        str: Returns the URL of Grafana, empty string if no grafana
    """
    status_list = []
    client = boto3.client('grafana')
    list_of_workspaces = []
    response = client.list_workspaces()
    
    for x in response['workspaces']:
        if f'{arcade_name}-grafana' in x['name']:
            list_of_workspaces.append(x)
    
    status = get_grafana_status(arcade_name=arcade_name)
    status_list.insert(0, str(status))
    while status_list[0] == 'CREATING':
        time.sleep(1)
        new_status = get_grafana_status(arcade_name=arcade_name)
        if status_list[0] == 'CREATING':
            status_list.insert(0, str(new_status))
            continue
        if status_list[0] == 'ACTIVE':
            break
    
    if list_of_workspaces == []:
        return ''
    else:
        return list_of_workspaces[0]['endpoint']


def get_oicd_arn(arcade_name: str) -> tuple:
    """Gets the OICD Arn withoud EKS cluster avaliable

    Args:
        arcade_name (str): Name of the Arcade

    Returns:
        tuple: If Success returns Tuple with (True, <ARN), If Failure, then (False, '')
    """
    found_oicd = []
    oicd_arn = []
    eks_cluster_name = arcade_name.replace('.', '-')
    eks_cluster = f"asteroids-{eks_cluster_name}"
    client = boto3.client('iam')
    response = client.list_open_id_connect_providers()['OpenIDConnectProviderList']
    for oicd in response:
        oicd_client = client.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=oicd['Arn'])
        found_oicd.append({oicd['Arn']: oicd_client['Tags']})
    
    for items in found_oicd:
        for key, value in items.items():
            if eks_cluster == value[0]['Value']:
                oicd_arn.insert(0, key)
            else:
                pass
    
    if len(oicd_arn) < 1:
        return (False, '')
    else:
        return (True, oicd_arn[0])
    


def get_oicd_info(cluster_name: str):
    """Returns the OICD Issuer

    Args:
        cluster_name (str): EKS cluster name

    Returns:
        str: oicd issuer
    """
    client = boto3.client('eks')
    response = client.describe_cluster(name=cluster_name)
    return response['cluster']['identity']['oidc']['issuer']


def create_policy(arcade_name: str, permission_policy: dict, graphana=True):
    """_summary_

    Args:
        arcade_name (str): _description_
        permission_policy (dict): _description_
        graphana (bool, optional): _description_. Defaults to True.

    Returns:
        _type_: _description_
    """
    client = boto3.client('iam')
    try:
        
        if graphana:
            reponse = client.create_policy(
                PolicyName=f"{arcade_name}-GraphanaWriteAccessPolicy",
                PolicyDocument=json.dumps(permission_policy)
            )
            return (True, reponse)
        else:
            reponse = client.create_policy(
                    PolicyName=f"{arcade_name}-PrometheusWriteAccessPolicy",
                    PolicyDocument=json.dumps(permission_policy)
                )
        
            return (True, reponse)
    except client.exceptions.EntityAlreadyExistsException:
        return False


def create_role(arcade_name: str, trust_relationship: dict):
    client = boto3.client('iam')
    try:
       response = client.create_role(
           RoleName=f"{arcade_name}-EKS-ARCADE-ServiceAccount-Role",
           AssumeRolePolicyDocument=json.dumps(trust_relationship)
       )
       return response
    except client.exceptions.EntityAlreadyExistsException:
        return 'Role Already Present'


def attach_role_policy(arcade_name: str):
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    client = boto3.client('iam')
    response = client.attach_role_policy(
            RoleName=f'{arcade_name}-EKS-ARCADE-ServiceAccount-Role',
            PolicyArn=f'arn:aws:iam::{account_id}:policy/{arcade_name}-PrometheusWriteAccessPolicy'
        )
    return response



def create_openid(cluster):
    # eksctl utils associate-iam-oidc-provider --region="$REGION" --cluster="$CLUSTERNAME" --approve # Only run this once
    client = boto3.client('iam')
    try:
        # Create openid connector
        response = client.create_open_id_connect_provider(
            Url=get_oicd_info(cluster),
            ClientIDList=[
                'sts.amazonaws.com',
            ],
            ThumbprintList=[
                '',
                # https://boto3.amazonaws.com/v1/documentation/api/1.9.42/reference/services/iam.html
            ],
            Tags=[
                {
                    'Key': 'Cluster',
                    'Value': cluster
                },
            ])
        return response['OpenIDConnectProviderArn']
    except:
        # Find the open ID connector
        response = client.list_open_id_connect_providers()
        list_of_oidc = response['OpenIDConnectProviderList']
        for x in list_of_oidc:
            z = client.get_open_id_connect_provider(
                OpenIDConnectProviderArn=x['Arn'])

            if z['Tags'][0]['Value'] == cluster:
                return x['Arn']
            else:
                pass


def create_oicd_prometheus(arcade_name: str):
    cluster = eks.arcade_to_cluster_name(arcade_name=arcade_name)
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    OIDC = get_oicd_info(cluster_name=cluster).split('/')
    oidc_provider = f"{OIDC[2]}/{OIDC[3]}/{OIDC[4]}"

    OICD_TRUST_RELATIONSHIP = {
        "Version":"2012-10-17",
        "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": f"arn:aws:iam::{account_id}:oidc-provider/{oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    f"{oidc_provider}:sub": f"system:serviceaccount:grafana:iamproxy-service-account"
                }
            }
        },
        {
          "Effect": "Allow",
          "Principal": {
            "Federated": f"arn:aws:iam::{account_id}:oidc-provider/{oidc_provider}"
          },
          "Action": "sts:AssumeRoleWithWebIdentity",
          "Condition": {
            "StringEquals": {
              f"{oidc_provider}:sub": f"system:serviceaccount:prometheus:iamproxy-service-account"
            }
          }
        }]}
    
    PERMISSION_POLICY = {
        "Version":"2012-10-17",
        "Statement":[
           {
              "Effect":"Allow",
              "Action":[
                 "aps:RemoteWrite",
                 "aps:QueryMetrics",
                 "aps:GetSeries",
                 "aps:GetLabels",
                 "aps:GetMetricMetadata"
              ],
              "Resource":"*"
           }
        ]}
    
    #arn:aws:iam::023960176222:role/few_dyke.arc-EKS-ARCADE-ServiceAccount-Role
    policy = create_policy(arcade_name=arcade_name, permission_policy=PERMISSION_POLICY, graphana=False)
    
    if policy:
        role = create_role(arcade_name=arcade_name, trust_relationship=OICD_TRUST_RELATIONSHIP)
        if role:
            attach_role_policy(arcade_name=arcade_name)
            create_openid(cluster)
            return True
        else:
            pass
    else:
        pass
    


def create_grafana_role(arcade_name: str):
    client = boto3.client('iam')
    region = common.get_arcade_region(arcade_name=arcade_name)
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    GRAFANA_TRUST = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "grafana.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
    GRAFANA_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "aps:ListWorkspaces",
                "aps:DescribeWorkspace",
                "aps:QueryMetrics",
                "aps:GetLabels",
                "aps:GetSeries",
                "aps:GetMetricMetadata"
            ],
            "Resource": "*"
        }
        ]
        }
    try:
        create_gpolicy = create_policy(arcade_name=arcade_name, permission_policy=GRAFANA_POLICY, graphana=True)
        if create_gpolicy:
            arn_policy = create_gpolicy[1]['Policy']['Arn']
        else:
            arn_policy = f"arn:aws:iam::{account_id}:policy/{arcade_name}-GraphanaWriteAccessPolicy"
    except client.exceptions.EntityAlreadyExistsException:
        arn_policy = f"arn:aws:iam::{account_id}:policy/{arcade_name}-GraphanaWriteAccessPolicy"
            
    
    try:
        create_grole = client.create_role(
            RoleName=f'{arcade_name}-graphana-role', AssumeRolePolicyDocument=json.dumps(GRAFANA_TRUST)
        )
        arn_role = create_grole['Role']['Arn']
    except client.exceptions.EntityAlreadyExistsException:
        arn_role = f"arn:aws:iam::{account_id}:role/{arcade_name}-graphana-role"

    # Attach policy to role
    response = client.attach_role_policy(RoleName=f"{arcade_name}-graphana-role", PolicyArn=arn_policy)
    
    return arn_role


def find_prometheus_workspaces(arcade_name: str) -> bool:
    """Finds workspace for prometheus

    Args:
        arcade_name (_type_): _description_

    Returns:
        _type_: _description_
    """
    list_of_workspaces = []
    client = boto3.client('amp')
    response = client.list_workspaces(alias=f'prometheus-{arcade_name}')
    for value in response['workspaces']:
        list_of_workspaces.append(value['alias'])
    
    
    if f'prometheus-{arcade_name}' in list_of_workspaces:
        return True
    else:
        return False



def get_aws_prometheus_workspace_id(arcade_name: str):
    client = boto3.client('amp')
    region = common.get_arcade_region(arcade_name=arcade_name)
    response = client.list_workspaces(alias=f"prometheus-{arcade_name}")
    url = f"https://aps-workspaces.{region}.amazonaws.com/workspaces/{response['workspaces'][0]['workspaceId']}/api/v1/remote_write"
    return url


def get_prometheus_role_arn_str(arcade_name: str) -> str:
    """Returns the arn string of the Role for prometheus

    Args:
        arcade_name (str): _description_

    Returns:
        str: _description_
    """
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    return f"arn:aws:iam::{account_id}:role/{arcade_name}-EKS-ARCADE-ServiceAccount-Role"


def find_grafana_workspaces(arcade_name):
    """Finds workspace for grafana

    Args:
        arcade_name (_type_): _description_

    Returns:
        _type_: _description_
    """
    list_of_workspaces = []
    client = boto3.client('grafana')
    response = client.list_workspaces()
    
    for value in response['workspaces']:
        list_of_workspaces.append(value['name'])
    
    if f'{arcade_name}-grafana' in list_of_workspaces:
        return True
    else:
        return False


def apply_prometheus_configmap(arcade_name: str):
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    region = common.get_arcade_region(arcade_name=arcade_name)
    get_prometheus_writer_url = get_aws_prometheus_workspace_id(arcade_name=arcade_name)
    
    core_v1 = client.CoreV1Api()
    
    configmap_yaml = f"""
apiVersion: v1
data:
  alerting_rules.yml: |
    {{}}
  alerts: |
    {{}}
  allow-snippet-annotations: "false"
  prometheus.yml: |
    global:
      evaluation_interval: 1m
      scrape_interval: 1m
      scrape_timeout: 10s
    remote_write:
    - queue_config:
        capacity: 2500
        max_samples_per_send: 1000
        max_shards: 200
      sigv4:
        region: {region}
      url: {get_prometheus_writer_url}
    rule_files:
    - /etc/config/recording_rules.yml
    - /etc/config/alerting_rules.yml
    - /etc/config/rules
    - /etc/config/alerts
    scrape_configs:
    - job_name: prometheus
      static_configs:
      - targets:
        - localhost:9090
    - bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      job_name: kubernetes-apiservers
      kubernetes_sd_configs:
      - role: endpoints
      relabel_configs:
      - action: keep
        regex: default;kubernetes;https
        source_labels:
        - __meta_kubernetes_namespace
        - __meta_kubernetes_service_name
        - __meta_kubernetes_endpoint_port_name
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        insecure_skip_verify: true
    - bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      job_name: kubernetes-nodes
      kubernetes_sd_configs:
      - role: node
      relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)
      - replacement: kubernetes.default.svc:443
        target_label: __address__
      - regex: (.+)
        replacement: /api/v1/nodes/$1/proxy/metrics
        source_labels:
        - __meta_kubernetes_node_name
        target_label: __metrics_path__
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        insecure_skip_verify: true
    - bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      job_name: kubernetes-nodes-cadvisor
      kubernetes_sd_configs:
      - role: node
      relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)
      - replacement: kubernetes.default.svc:443
        target_label: __address__
      - regex: (.+)
        replacement: /api/v1/nodes/$1/proxy/metrics/cadvisor
        source_labels:
        - __meta_kubernetes_node_name
        target_label: __metrics_path__
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        insecure_skip_verify: true
    - honor_labels: true
      job_name: kubernetes-service-endpoints
      kubernetes_sd_configs:
      - role: endpoints
      relabel_configs:
      - action: keep
        regex: true
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_scrape
      - action: drop
        regex: true
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_scrape_slow
      - action: replace
        regex: (https?)
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_scheme
        target_label: __scheme__
      - action: replace
        regex: (.+)
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_path
        target_label: __metrics_path__
      - action: replace
        regex: (.+?)(?::\d+)?;(\d+)
        replacement: $1:$2
        source_labels:
        - __address__
        - __meta_kubernetes_service_annotation_prometheus_io_port
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_service_annotation_prometheus_io_param_(.+)
        replacement: __param_$1
      - action: labelmap
        regex: __meta_kubernetes_service_label_(.+)
      - action: replace
        source_labels:
        - __meta_kubernetes_namespace
        target_label: namespace
      - action: replace
        source_labels:
        - __meta_kubernetes_service_name
        target_label: service
      - action: replace
        source_labels:
        - __meta_kubernetes_pod_node_name
        target_label: node
    - honor_labels: true
      job_name: kubernetes-service-endpoints-slow
      kubernetes_sd_configs:
      - role: endpoints
      relabel_configs:
      - action: keep
        regex: true
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_scrape_slow
      - action: replace
        regex: (https?)
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_scheme
        target_label: __scheme__
      - action: replace
        regex: (.+)
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_path
        target_label: __metrics_path__
      - action: replace
        regex: (.+?)(?::\d+)?;(\d+)
        replacement: $1:$2
        source_labels:
        - __address__
        - __meta_kubernetes_service_annotation_prometheus_io_port
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_service_annotation_prometheus_io_param_(.+)
        replacement: __param_$1
      - action: labelmap
        regex: __meta_kubernetes_service_label_(.+)
      - action: replace
        source_labels:
        - __meta_kubernetes_namespace
        target_label: namespace
      - action: replace
        source_labels:
        - __meta_kubernetes_service_name
        target_label: service
      - action: replace
        source_labels:
        - __meta_kubernetes_pod_node_name
        target_label: node
      scrape_interval: 5m
      scrape_timeout: 30s
    - honor_labels: true
      job_name: prometheus-pushgateway
      kubernetes_sd_configs:
      - role: service
      relabel_configs:
      - action: keep
        regex: pushgateway
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_probe
    - honor_labels: true
      job_name: kubernetes-services
      kubernetes_sd_configs:
      - role: service
      metrics_path: /probe
      params:
        module:
        - http_2xx
      relabel_configs:
      - action: keep
        regex: true
        source_labels:
        - __meta_kubernetes_service_annotation_prometheus_io_probe
      - source_labels:
        - __address__
        target_label: __param_target
      - replacement: blackbox
        target_label: __address__
      - source_labels:
        - __param_target
        target_label: instance
      - action: labelmap
        regex: __meta_kubernetes_service_label_(.+)
      - source_labels:
        - __meta_kubernetes_namespace
        target_label: namespace
      - source_labels:
        - __meta_kubernetes_service_name
        target_label: service
    - honor_labels: true
      job_name: kubernetes-pods
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
      - action: keep
        regex: true
        source_labels:
        - __meta_kubernetes_pod_annotation_prometheus_io_scrape
      - action: drop
        regex: true
        source_labels:
        - __meta_kubernetes_pod_annotation_prometheus_io_scrape_slow
      - action: replace
        regex: (https?)
        source_labels:
        - __meta_kubernetes_pod_annotation_prometheus_io_scheme
        target_label: __scheme__
      - action: replace
        regex: (.+)
        source_labels:
        - __meta_kubernetes_pod_annotation_prometheus_io_path
        target_label: __metrics_path__
      - action: replace
        regex: (.+?)(?::\d+)?;(\d+)
        replacement: $1:$2
        source_labels:
        - __address__
        - __meta_kubernetes_pod_annotation_prometheus_io_port
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_annotation_prometheus_io_param_(.+)
        replacement: __param_$1
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - action: replace
        source_labels:
        - __meta_kubernetes_namespace
        target_label: namespace
      - action: replace
        source_labels:
        - __meta_kubernetes_pod_name
        target_label: pod
      - action: drop
        regex: Pending|Succeeded|Failed|Completed
        source_labels:
        - __meta_kubernetes_pod_phase
    - honor_labels: true
      job_name: kubernetes-pods-slow
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
      - action: keep
        regex: true
        source_labels:
        - __meta_kubernetes_pod_annotation_prometheus_io_scrape_slow
      - action: replace
        regex: (https?)
        source_labels:
        - __meta_kubernetes_pod_annotation_prometheus_io_scheme
        target_label: __scheme__
      - action: replace
        regex: (.+)
        source_labels:
        - __meta_kubernetes_pod_annotation_prometheus_io_path
        target_label: __metrics_path__
      - action: replace
        regex: (.+?)(?::\d+)?;(\d+)
        replacement: $1:$2
        source_labels:
        - __address__
        - __meta_kubernetes_pod_annotation_prometheus_io_port
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_annotation_prometheus_io_param_(.+)
        replacement: __param_$1
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - action: replace
        source_labels:
        - __meta_kubernetes_namespace
        target_label: namespace
      - action: replace
        source_labels:
        - __meta_kubernetes_pod_name
        target_label: pod
      - action: drop
        regex: Pending|Succeeded|Failed|Completed
        source_labels:
        - __meta_kubernetes_pod_phase
      scrape_interval: 5m
      scrape_timeout: 30s
  recording_rules.yml: |
    {{}}
  rules: |
    {{}}
kind: ConfigMap
metadata:
  annotations:
    meta.helm.sh/release-name: promethus-for-arcade
    meta.helm.sh/release-namespace: prometheus
  creationTimestamp: "2022-07-21T20:54:48Z"
  labels:
    app: prometheus
    app.kubernetes.io/managed-by: Helm
    chart: prometheus-15.10.5
    component: server
    heritage: Helm
    release: promethus-for-arcade
  name: promethus-for-arcade-server
  namespace: prometheus
  """
    prometheus_configmap = yaml.safe_load(configmap_yaml)
    try:
        response = core_v1.create_namespaced_config_map(
            namespace='prometheus',
            body=prometheus_configmap
        )
        return True
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = core_v1.replace_namespaced_config_map(
                name=prometheus_configmap['metadata']['name'],
                namespace=prometheus_configmap['metadata']['namespace'],
                body=prometheus_configmap
            )
            return True
        
        raise api_error


# Create Service Account
def apply_prometheus_service_accounts(arcade_name: str):
    list_of_service_accounts = []
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    core_v1 = client.CoreV1Api()
    service_account = f"""
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app.kubernetes.io/component: metrics
        app.kubernetes.io/instance: promethus-for-arcade
        app.kubernetes.io/managed-by: Helm
        app.kubernetes.io/name: kube-state-metrics
        app.kubernetes.io/part-of: kube-state-metrics
        app.kubernetes.io/version: 2.5.0
        helm.sh/chart: kube-state-metrics-4.13.0
      name: promethus-for-arcade-kube-state-metrics
      namespace: prometheus
    secrets:
    - name: promethus-for-arcade-kube-state-metrics-token-jj6hl
    """
    
    iam_role_prometheus = get_prometheus_role_arn_str(arcade_name=arcade_name)
    
    iamproxy_service_account = f"""
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      annotations:
        eks.amazonaws.com/role-arn: {iam_role_prometheus}
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: server
        heritage: Helm
        release: promethus-for-arcade
      name: iamproxy-service-account
      namespace: prometheus
    secrets:
    - name: iamproxy-service-account-token-tdz98
    """
    
    amp_exploer_sa = """
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: node-exporter
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-node-exporter
      namespace: prometheus
    secrets:
    - name: promethus-for-arcade-node-exporter-token-d4rp5
    """
    
    prometheus_service_account = yaml.safe_load(service_account)
    prometheus_iamproxy_sa = yaml.safe_load(iamproxy_service_account)
    prometheus_amp_sa = yaml.safe_load(amp_exploer_sa)
    list_of_service_accounts.append(prometheus_service_account)
    list_of_service_accounts.append(prometheus_iamproxy_sa)
    list_of_service_accounts.append(prometheus_amp_sa)
    
    for service_accounts  in list_of_service_accounts:
        
        try:
            response = core_v1.create_namespaced_service_account(
                namespace=service_accounts['metadata']['namespace'],
                body=service_accounts
            )
        except ApiException as api_error:
            if api_error.status == 409:
                api_reponse = core_v1.replace_namespaced_service_account(
                    name=service_accounts['metadata']['name'],
                    namespace=service_accounts['metadata']['namespace'],
                    body=service_accounts
                )
            elif api_error.status == 401:
                pass
            else:
                raise api_error
        
    return True
    

    


def apply_prometheus_daemonset(arcade_name: str):
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    apps_v1 = client.AppsV1Api()
    
    daemonset = """
    apiVersion: apps/v1
    kind: DaemonSet
    metadata:
      annotations:
        deprecated.daemonset.template.generation: "1"
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      creationTimestamp: "2022-07-22T15:02:08Z"
      generation: 1
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: node-exporter
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-node-exporter
      namespace: prometheus
    spec:
      revisionHistoryLimit: 10
      selector:
        matchLabels:
          app: prometheus
          component: node-exporter
          release: promethus-for-arcade
      template:
        metadata:
          creationTimestamp: null
          labels:
            app: prometheus
            chart: prometheus-15.10.5
            component: node-exporter
            heritage: Helm
            release: promethus-for-arcade
        spec:
          containers:
          - args:
            - --path.procfs=/host/proc
            - --path.sysfs=/host/sys
            - --path.rootfs=/host/root
            - --web.listen-address=:9100
            image: quay.io/prometheus/node-exporter:v1.3.1
            imagePullPolicy: IfNotPresent
            name: prometheus-node-exporter
            ports:
            - containerPort: 9100
              hostPort: 9100
              name: metrics
              protocol: TCP
            resources: {}
            securityContext:
              allowPrivilegeEscalation: false
            terminationMessagePath: /dev/termination-log
            terminationMessagePolicy: File
            volumeMounts:
            - mountPath: /host/proc
              name: proc
              readOnly: true
            - mountPath: /host/sys
              name: sys
              readOnly: true
            - mountPath: /host/root
              mountPropagation: HostToContainer
              name: root
              readOnly: true
          dnsPolicy: ClusterFirst
          hostNetwork: true
          hostPID: true
          restartPolicy: Always
          schedulerName: default-scheduler
          securityContext:
            fsGroup: 65534
            runAsGroup: 65534
            runAsNonRoot: true
            runAsUser: 65534
          serviceAccount: promethus-for-arcade-node-exporter
          serviceAccountName: promethus-for-arcade-node-exporter
          terminationGracePeriodSeconds: 30
          volumes:
          - hostPath:
              path: /proc
              type: ""
            name: proc
          - hostPath:
              path: /sys
              type: ""
            name: sys
          - hostPath:
              path: /
              type: ""
            name: root
      updateStrategy:
        rollingUpdate:
          maxSurge: 0
          maxUnavailable: 1
        type: RollingUpdate
    """
        
    daemon_set = yaml.safe_load(daemonset)
    
    try:
        response = apps_v1.create_namespaced_daemon_set(
            namespace=daemon_set['metadata']['namespace'],
            body=daemon_set,
        )
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = apps_v1.replace_namespaced_daemon_set(
                namespace=daemon_set['metadata']['namespace'],
                name=daemon_set['metadata']['name'],
                body=daemon_set,
            )
        elif api_error.status == 401:
            pass
        else:
            raise api_error

    return True




def apply_prometheus_deployment(arcade_name: str):
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    apps_v1 = client.AppsV1Api()
    
    deployment_yaml = """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      annotations:
        deployment.kubernetes.io/revision: "1"
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      generation: 1
      labels:
        app.kubernetes.io/component: metrics
        app.kubernetes.io/instance: promethus-for-arcade
        app.kubernetes.io/managed-by: Helm
        app.kubernetes.io/name: kube-state-metrics
        app.kubernetes.io/part-of: kube-state-metrics
        app.kubernetes.io/version: 2.5.0
        helm.sh/chart: kube-state-metrics-4.13.0
      name: promethus-for-arcade-kube-state-metrics
      namespace: prometheus
    spec:
      progressDeadlineSeconds: 600
      replicas: 1
      revisionHistoryLimit: 10
      selector:
        matchLabels:
          app.kubernetes.io/instance: promethus-for-arcade
          app.kubernetes.io/name: kube-state-metrics
      strategy:
        rollingUpdate:
          maxSurge: 25%
          maxUnavailable: 25%
        type: RollingUpdate
      template:
        metadata:
          creationTimestamp: null
          labels:
            app.kubernetes.io/component: metrics
            app.kubernetes.io/instance: promethus-for-arcade
            app.kubernetes.io/managed-by: Helm
            app.kubernetes.io/name: kube-state-metrics
            app.kubernetes.io/part-of: kube-state-metrics
            app.kubernetes.io/version: 2.5.0
            helm.sh/chart: kube-state-metrics-4.13.0
        spec:
          containers:
          - args:
            - --port=8080
            - --resources=certificatesigningrequests,configmaps,cronjobs,daemonsets,deployments,endpoints,horizontalpodautoscalers,ingresses,jobs,limitranges,mutatingwebhookconfigurations,namespaces,networkpolicies,nodes,persistentvolumeclaims,persistentvolumes,poddisruptionbudgets,pods,replicasets,replicationcontrollers,resourcequotas,secrets,services,statefulsets,storageclasses,validatingwebhookconfigurations,volumeattachments
            - --telemetry-port=8081
            image: registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.5.0
            imagePullPolicy: IfNotPresent
            livenessProbe:
              failureThreshold: 3
              httpGet:
                path: /healthz
                port: 8080
                scheme: HTTP
              initialDelaySeconds: 5
              periodSeconds: 10
              successThreshold: 1
              timeoutSeconds: 5
            name: kube-state-metrics
            ports:
            - containerPort: 8080
              name: http
              protocol: TCP
            readinessProbe:
              failureThreshold: 3
              httpGet:
                path: /
                port: 8080
                scheme: HTTP
              initialDelaySeconds: 5
              periodSeconds: 10
              successThreshold: 1
              timeoutSeconds: 5
            resources: {}
            terminationMessagePath: /dev/termination-log
            terminationMessagePolicy: File
          dnsPolicy: ClusterFirst
          restartPolicy: Always
          schedulerName: default-scheduler
          securityContext:
            fsGroup: 65534
            runAsGroup: 65534
            runAsUser: 65534
          serviceAccount: promethus-for-arcade-kube-state-metrics
          serviceAccountName: promethus-for-arcade-kube-state-metrics
          terminationGracePeriodSeconds: 30
        """
    
    deployment = yaml.safe_load(deployment_yaml)
    
    
    try:
        response = apps_v1.create_namespaced_deployment(
            namespace=deployment['metadata']['namespace'],
            body=deployment
        )
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = apps_v1.replace_namespaced_deployment(
                name=deployment['metadata']['name'],
                namespace=deployment['metadata']['namespace'],
                body=deployment
            )
        elif api_error.status == 401:
            pass
        else:
            raise api_error
    
    return True
    

def apply_prometheus_statefuleset(arcade_name: str):
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    stateful_yaml = """
    apiVersion: apps/v1
    kind: StatefulSet
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      generation: 1
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: server
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-server
      namespace: prometheus
    spec:
      podManagementPolicy: OrderedReady
      replicas: 1
      revisionHistoryLimit: 10
      selector:
        matchLabels:
          app: prometheus
          component: server
          release: promethus-for-arcade
      serviceName: promethus-for-arcade-server-headless
      template:
        metadata:
          creationTimestamp: null
          labels:
            app: prometheus
            chart: prometheus-15.10.5
            component: server
            heritage: Helm
            release: promethus-for-arcade
        spec:
          containers:
          - args:
            - --volume-dir=/etc/config
            - --webhook-url=http://127.0.0.1:9090/-/reload
            image: jimmidyson/configmap-reload:v0.5.0
            imagePullPolicy: IfNotPresent
            name: prometheus-server-configmap-reload
            resources: {}
            securityContext: {}
            terminationMessagePath: /dev/termination-log
            terminationMessagePolicy: File
            volumeMounts:
            - mountPath: /etc/config
              name: config-volume
              readOnly: true
          - args:
            - --storage.tsdb.retention.time=1h
            - --config.file=/etc/config/prometheus.yml
            - --storage.tsdb.path=/data
            - --web.console.libraries=/etc/prometheus/console_libraries
            - --web.console.templates=/etc/prometheus/consoles
            - --web.enable-lifecycle
            image: quay.io/prometheus/prometheus:v2.36.2
            imagePullPolicy: IfNotPresent
            livenessProbe:
              failureThreshold: 3
              httpGet:
                path: /-/healthy
                port: 9090
                scheme: HTTP
              initialDelaySeconds: 30
              periodSeconds: 15
              successThreshold: 1
              timeoutSeconds: 10
            name: prometheus-server
            ports:
            - containerPort: 9090
              protocol: TCP
            readinessProbe:
              failureThreshold: 3
              httpGet:
                path: /-/ready
                port: 9090
                scheme: HTTP
              initialDelaySeconds: 30
              periodSeconds: 5
              successThreshold: 1
              timeoutSeconds: 4
            resources: {}
            securityContext: {}
            terminationMessagePath: /dev/termination-log
            terminationMessagePolicy: File
            volumeMounts:
            - mountPath: /etc/config
              name: config-volume
            - mountPath: /data
              name: storage-volume
          dnsPolicy: ClusterFirst
          enableServiceLinks: true
          restartPolicy: Always
          schedulerName: default-scheduler
          securityContext:
            fsGroup: 65534
            runAsGroup: 65534
            runAsNonRoot: true
            runAsUser: 65534
          serviceAccount: iamproxy-service-account
          serviceAccountName: iamproxy-service-account
          terminationGracePeriodSeconds: 300
          volumes:
          - configMap:
              defaultMode: 420
              name: promethus-for-arcade-server
            name: config-volume
      updateStrategy:
        rollingUpdate:
          partition: 0
        type: RollingUpdate
      volumeClaimTemplates:
      - apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          creationTimestamp: null
          name: storage-volume
        spec:
          accessModes:
          - ReadWriteOnce
          resources:
            requests:
              storage: 8Gi
          volumeMode: Filesystem
        status:
          phase: Pending
    """
    
    statefulset = yaml.safe_load(stateful_yaml)
    
    apps_v1 = client.AppsV1Api()
    
    try:
        reponse = apps_v1.create_namespaced_stateful_set(
                namespace=statefulset['metadata']['namespace'],
                body=statefulset
            )
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = apps_v1.replace_namespaced_stateful_set(
                name=statefulset['metadata']['name'],
                namespace=statefulset['metadata']['namespace'],
                body=statefulset
            )
        elif api_error.status == 401:
            pass
        else:
            raise api_error
    
    return True
    
    

def apply_prometheus_service(arcade_name: str):
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    core_v1 = client.CoreV1Api()
    
    amp_server = """
    apiVersion: v1
    kind: Service
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: server
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-server
      namespace: prometheus
    spec:
      ipFamilies:
      - IPv4
      ipFamilyPolicy: SingleStack
      ports:
      - name: http
        port: 80
        protocol: TCP
        targetPort: 9090
      selector:
        app: prometheus
        component: server
        release: promethus-for-arcade
      sessionAffinity: None
      type: ClusterIP
    status:
      loadBalancer: {}
    """
    
    node_exporter = """
    apiVersion: v1
    kind: Service
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
        prometheus.io/scrape: "true"
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: node-exporter
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-node-exporter
      namespace: prometheus
    spec:
      ipFamilies:
      - IPv4
      ipFamilyPolicy: SingleStack
      ports:
      - name: metrics
        port: 9100
        protocol: TCP
        targetPort: 9100
      selector:
        app: prometheus
        component: node-exporter
        release: promethus-for-arcade
      sessionAffinity: None
      type: ClusterIP
    status:
      loadBalancer: {}
    """
    
    prometheus_for_amp_kubemetrics = """
    apiVersion: v1
    kind: Service
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
        prometheus.io/scrape: "true"
      labels:
        app.kubernetes.io/component: metrics
        app.kubernetes.io/instance: promethus-for-arcade
        app.kubernetes.io/managed-by: Helm
        app.kubernetes.io/name: kube-state-metrics
        app.kubernetes.io/part-of: kube-state-metrics
        app.kubernetes.io/version: 2.5.0
        helm.sh/chart: kube-state-metrics-4.13.0
      name: promethus-for-arcade-kube-state-metrics
      namespace: prometheus
    spec:
      ipFamilies:
      - IPv4
      ipFamilyPolicy: SingleStack
      ports:
      - name: http
        port: 8080
        protocol: TCP
        targetPort: 8080
      selector:
        app.kubernetes.io/instance: promethus-for-arcade
        app.kubernetes.io/name: kube-state-metrics
      sessionAffinity: None
      type: ClusterIP
    status:
      loadBalancer: {}
    """
    
    prometheus_for_amp_server_headless = """
    apiVersion: v1
    kind: Service
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: server
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-server-headless
      namespace: prometheus
    spec:
      clusterIP: None
      clusterIPs:
      - None
      ipFamilies:
      - IPv4
      ipFamilyPolicy: SingleStack
      ports:
      - name: http
        port: 80
        protocol: TCP
        targetPort: 9090
      selector:
        app: prometheus
        component: server
        release: promethus-for-arcade
      sessionAffinity: None
      type: ClusterIP
    status:
      loadBalancer: {}
    """
    
    kube_dns = """
    apiVersion: v1
    kind: Service
    metadata:
      annotations:
        prometheus.io/port: "9153"
        prometheus.io/scrape: "true"
      labels:
        eks.amazonaws.com/component: kube-dns
        k8s-app: kube-dns
        kubernetes.io/cluster-service: "true"
        kubernetes.io/name: CoreDNS
      name: kube-dns
      namespace: kube-system
    spec:
      clusterIP: 172.20.0.10
      clusterIPs:
      - 172.20.0.10
      ipFamilies:
      - IPv4
      ipFamilyPolicy: SingleStack
      ports:
      - name: dns
        port: 53
        protocol: UDP
        targetPort: 53
      - name: dns-tcp
        port: 53
        protocol: TCP
        targetPort: 53
      selector:
        k8s-app: kube-dns
      sessionAffinity: None
      type: ClusterIP
    status:
      loadBalancer: {}
    """
    
    list_of_services = []
    
    amp_kubemetrics = yaml.safe_load(prometheus_for_amp_kubemetrics)
    amp_server_ = yaml.safe_load(amp_server)
    amp_kubemetrics_ = yaml.safe_load(node_exporter)
    prometheus_amp_serverheadless = yaml.safe_load(prometheus_for_amp_server_headless)
    dns = yaml.safe_load(kube_dns)
    
    list_of_services.append(amp_kubemetrics)
    list_of_services.append(amp_server_)
    list_of_services.append(amp_kubemetrics_)
    list_of_services.append(prometheus_amp_serverheadless)
    # list_of_services.append(dns)
    
    
    for services in list_of_services:
        try:
            reponse = core_v1.create_namespaced_service(
                namespace=services['metadata']['namespace'],
                body=services
            )
            
        except ApiException as api_error:
            if api_error.status == 409:
                core_v1.delete_namespaced_service(
                    name=services['metadata']['name'],
                    namespace=services['metadata']['namespace']
                )
                core_v1.create_namespaced_service(
                    namespace=services['metadata']['namespace'],
                    body=services
                )
            elif api_error.status == 401:
                pass
            else:
                raise api_error
            
    return True

    



def apply_prometheus_cluster_role(arcade_name: str):
    
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    rbac_v1 = client.RbacAuthorizationV1Api()
    
    cr_state_metrics = """
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app.kubernetes.io/component: metrics
        app.kubernetes.io/instance: promethus-for-arcade
        app.kubernetes.io/managed-by: Helm
        app.kubernetes.io/name: kube-state-metrics
        app.kubernetes.io/part-of: kube-state-metrics
        app.kubernetes.io/version: 2.5.0
        helm.sh/chart: kube-state-metrics-4.13.0
      name: promethus-for-arcade-kube-state-metrics
    rules:
    - apiGroups:
      - certificates.k8s.io
      resources:
      - certificatesigningrequests
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - configmaps
      verbs:
      - list
      - watch
    - apiGroups:
      - batch
      resources:
      - cronjobs
      verbs:
      - list
      - watch
    - apiGroups:
      - extensions
      - apps
      resources:
      - daemonsets
      verbs:
      - list
      - watch
    - apiGroups:
      - extensions
      - apps
      resources:
      - deployments
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - endpoints
      verbs:
      - list
      - watch
    - apiGroups:
      - autoscaling
      resources:
      - horizontalpodautoscalers
      verbs:
      - list
      - watch
    - apiGroups:
      - extensions
      - networking.k8s.io
      resources:
      - ingresses
      verbs:
      - list
      - watch
    - apiGroups:
      - batch
      resources:
      - jobs
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - limitranges
      verbs:
      - list
      - watch
    - apiGroups:
      - admissionregistration.k8s.io
      resources:
      - mutatingwebhookconfigurations
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - namespaces
      verbs:
      - list
      - watch
    - apiGroups:
      - networking.k8s.io
      resources:
      - networkpolicies
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - nodes
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - persistentvolumeclaims
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - persistentvolumes
      verbs:
      - list
      - watch
    - apiGroups:
      - policy
      resources:
      - poddisruptionbudgets
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - pods
      verbs:
      - list
      - watch
    - apiGroups:
      - extensions
      - apps
      resources:
      - replicasets
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - replicationcontrollers
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - resourcequotas
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - secrets
      verbs:
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - services
      verbs:
      - list
      - watch
    - apiGroups:
      - apps
      resources:
      - statefulsets
      verbs:
      - list
      - watch
    - apiGroups:
      - storage.k8s.io
      resources:
      - storageclasses
      verbs:
      - list
      - watch
    - apiGroups:
      - admissionregistration.k8s.io
      resources:
      - validatingwebhookconfigurations
      verbs:
      - list
      - watch
    - apiGroups:
      - storage.k8s.io
      resources:
      - volumeattachments
      verbs:
      - list
      - watch
    """
    
    amp_server_cr = """
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: server
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-server
    rules:
    - apiGroups:
      - ""
      resources:
      - nodes
      - nodes/proxy
      - nodes/metrics
      - services
      - endpoints
      - pods
      - ingresses
      - configmaps
      verbs:
      - get
      - list
      - watch
    - apiGroups:
      - extensions
      - networking.k8s.io
      resources:
      - ingresses/status
      - ingresses
      verbs:
      - get
      - list
      - watch
    - nonResourceURLs:
      - /metrics
      verbs:
      - get
    """
    
    list_of_CR = []
    
    metrics = yaml.safe_load(cr_state_metrics)
    amp_s = yaml.safe_load(amp_server_cr)
    list_of_CR.append(metrics)
    list_of_CR.append(amp_s)
    
    for cr in list_of_CR:
        
        try:
            response = rbac_v1.create_cluster_role(body=cr)
        except ApiException as api_error:
            if api_error.status == 409:
                api_response = rbac_v1.replace_cluster_role(
                    name=cr['metadata']['name'],
                    body=cr
                )
            elif api_error.status == 401:
                pass
            else:
                raise api_error
            
    return True
    


def apply_cr_bindings(arcade_name: str):
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    rbac_v1 = client.RbacAuthorizationV1Api()
    
    amp_server = """
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app: prometheus
        app.kubernetes.io/managed-by: Helm
        chart: prometheus-15.10.5
        component: server
        heritage: Helm
        release: promethus-for-arcade
      name: promethus-for-arcade-server
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: promethus-for-arcade-server
    subjects:
    - kind: ServiceAccount
      name: iamproxy-service-account
      namespace: prometheus
    """
    
    state_metrics = """
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      annotations:
        meta.helm.sh/release-name: promethus-for-arcade
        meta.helm.sh/release-namespace: prometheus
      labels:
        app.kubernetes.io/component: metrics
        app.kubernetes.io/instance: promethus-for-arcade
        app.kubernetes.io/managed-by: Helm
        app.kubernetes.io/name: kube-state-metrics
        app.kubernetes.io/part-of: kube-state-metrics
        app.kubernetes.io/version: 2.5.0
        helm.sh/chart: kube-state-metrics-4.13.0
      name: promethus-for-arcade-kube-state-metrics
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: promethus-for-arcade-kube-state-metrics
    subjects:
    - kind: ServiceAccount
      name: promethus-for-arcade-kube-state-metrics
      namespace: prometheus
    """
    
    list_of_crb = []
    metrics = yaml.safe_load(state_metrics)
    server = yaml.safe_load(amp_server)
    list_of_crb.append(server)
    list_of_crb.append(metrics)
    
    for crb in list_of_crb:
        try:
            response = rbac_v1.create_cluster_role_binding(body=crb)
        except ApiException as api_error:
            if api_error.status == 409:
                api_response = rbac_v1.replace_cluster_role_binding(
                    name=crb['metadata']['name'],
                    body=crb
                )
            elif api_error.status == 401:
                pass
            else:
                raise api_error
            
    return True
    
