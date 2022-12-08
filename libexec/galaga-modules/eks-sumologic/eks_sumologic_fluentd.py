import base64
import json
import yaml
from pprint import pprint
from pathlib import Path
from arclib import common, ecr, eks, k8s, log, storage
from botocore.exceptions import ClientError
from kubernetes import client, config, utils
from kubernetes.client.rest import ApiException


def pretty_dump(my_dict: dict):
    """Returns a Pretty Dictionary

    Args:
        my_dict (dict): Dictionary to return

    Returns:
        dict: Json.Dump of Dictionary
    """
    return json.dumps(my_dict, sort_keys=True, indent=4)


def get_yaml_dirctory(kind: str) -> str:
    """Gets the Directory Path the yaml file for Kubernetes Manifest

    Args:
        kind (str): Kubernetes Manifest Kind

    Returns:
        str: Path to the Kubernetes Manifest
    """
    p = Path(__file__)
    parent_folder = p.parent
    for dirs in parent_folder.glob('*'):
        if dirs.is_dir():
            one_level_up = dirs
            for files in one_level_up.glob('*'):
                if files.is_dir():
                    if kind == files.name:
                        mainfest_path = files
    
    return mainfest_path


def create_namespace(namespace: str, arcade_name: str) -> bool:
    """Creates Kubernetes Namespace
    Args:
        namespace (str): name of the namespace
        arcade_name (str): name of the arcade
    Returns:
        bool: Returns True if the namespace was created, False if there is a failure
    """
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    core_v1 = client.CoreV1Api()
    try:
        core_v1.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace)))
        return True
    except ApiException as api_error:
        if api_error.status == 400 or 409:
            core_v1.replace_namespace(name=namespace, body=client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace)))
        elif api_error.status == 401:
            pass
        else:
            return False
    
    
def open_mainifest_and_generate(path: str, filename: str) -> list:
    """Opens Kubernetes Manifest and converts to dict and appends to a list

    Args:
        path (str): The path of the yaml files that contain the kubernetes manifest, You can use  get_yaml_dirctory() to get this path.
        filename (str): Name of the Yaml File with out the .yaml

    Returns:
        list: All the yaml manifest inside a list
    """
    list_of_dict = []

    with open(f'{path}/{filename}.yaml', 'r') as file:
        converted_yaml_file = yaml.safe_load_all(file)
        for all_files in converted_yaml_file:
            list_of_dict.append(all_files)

    return list_of_dict



def create_sumologic_fluentd(arcade_name: str, kind: str, namespace: str, eks_cluster: str, **kwargs: dict) -> None:
    """ Deploys Diffrent Kubernetes Manifest. This as of right now is centered around fluentd. 

    Information:
        How to Execute:
            If using **kwargs then we will need a dict to be passed in with the first key named my_kwargs
            If not using **kwargs then no need to pass in as this is optional

            kwargs example: 
            >>> my_kwargs = {
            >>>    'sumologic_accessid': '',
            >>>    'sumologic_access_key': '',
            >>> }

            To execute the kubernetes apply with these functions do the following.
            Call create_sumologic_fluentd()
            The main thing to change is the kind, this is a kubernetes kind for each kind you want to deploy
            
            Examples: ClusterRole, ClusterRoleBindings, ConfigMaps, DaemonSet, Deployment, Job, Pod, PodDisruptionBudget, PodSecurityPolicy,
            PriorityClass, Secret, ServiceAccount, StatefulSet
            Note: The names are case sensitve, needs to match what is in the yaml files in the kind section, if not it will fail.

            If we wanted to deploy a DaemonSet this is how it would look:

            >>> deploy = create_sumologic_fluentd(arcade_name=${ARCADE_NAME}, kind='DaemonSet', namespace='fluentd', eks_cluster=${EKS_CLUSTER})
            >>> kubectl get daemonset -n fluentd

    
    Args:
        arcade_name (str): Name of the Arcade
        kind (str): The Kubernetes Manifest Kind 
        namespace (str): Name of the Kubernetes Namespace
        eks_cluster (str): Name of the EKS cluster that Kubernetes is running on

    Raises:
        Exception: kubernetes python api error

    Returns:
        None: No return
    """
    
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False

    mainfest_location_dir = get_yaml_dirctory(kind=kind)

    if kind == 'PodSecurityPolicy':
        k8s_client = client.PolicyV1beta1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            configure = client.V1beta1PodSecurityPolicy(
                api_version=all_files['apiVersion'], kind=all_files['kind'], 
                metadata=all_files['metadata'], spec=all_files['spec'])
            try:
                k8s_client.create_pod_security_policy(body=configure)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_pod_security_policy(body=configure, name=all_files['metadata']['name'])
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False

    
    if kind == 'ServiceAccount':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            try:
                k8s_client.create_namespaced_service_account(namespace=namespace, body=all_files)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_namespaced_service_account(name=all_files['metadata']['name'], namespace=namespace, body=all_files)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    
    if kind == 'ConfigMap':

        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            if all_files['metadata']['name'] == f'arcade-{namespace}-sumologic-{namespace}-logs':
                all_files['data']['logs.source.containers.conf'] = all_files['data']['logs.source.containers.conf'].format(eks_cluster=eks_cluster)
                all_files['data']['logs.source.default.conf'] = all_files['data']['logs.source.default.conf'].format(eks_cluster=eks_cluster)
                all_files['data']['logs.source.systemd.conf'] = all_files['data']['logs.source.systemd.conf'].format(eks_cluster=eks_cluster)
            
            if all_files['metadata']['name'] == f'arcade-{namespace}-sumologic-{namespace}-events':
                all_files['data']['events.conf'] = all_files['data']['events.conf'].format(eks_cluster=eks_cluster)
            
            if all_files['metadata']['name'] == f'arcade-{namespace}-sumologic-{namespace}-metrics':
                all_files['data']['common.conf'] = all_files['data']['common.conf'].format(eks_cluster=eks_cluster)
            
            if all_files['metadata']['name'] == f'arcade-{namespace}-sumologic-setup':
                all_files['data']['variables.tf'] = all_files['data']['variables.tf'].format(eks_cluster=eks_cluster)
                all_files['data']['setup.sh'] = all_files['data']['setup.sh'].format(eks_cluster=eks_cluster)
            try:
                k8s_client.create_namespaced_config_map(body=all_files, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_namespaced_config_map(body=all_files, namespace=namespace, name=all_files['metadata']['name'])
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False


    if kind == 'PodDisruptionBudget':
        k8s_client = client.PolicyV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            try:
                k8s_client.create_namespaced_pod_disruption_budget(namespace=namespace, body=all_files)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    # Have to get the resource version prior to the update of this
                    get_old_resource_version = k8s_client.read_namespaced_pod_disruption_budget(
                        name=all_files['metadata']['name'], namespace=namespace, pretty=True)
                    resource_version = get_old_resource_version.metadata.resource_version
                    all_files['metadata']['resourceVersion'] = resource_version
                    k8s_client.replace_namespaced_pod_disruption_budget(body=all_files, namespace=namespace, name=all_files['metadata']['name'])
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    if kind == 'StatefulSet':
        k8s_client = client.AppsV1Api()
        current_used_images = {'image': 'public.ecr.aws/sumologic/kubernetes-fluentd:1.14.6-sumo-5'}
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            if current_used_images:
                all_files['spec']['template']['spec']['containers'][0]['image'] = current_used_images['image']
            try:
                k8s_client.create_namespaced_stateful_set(namespace=namespace, body=all_files)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_namespaced_stateful_set(
                        body=all_files, namespace='fluentd',
                        name=all_files['metadata']['name'])
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'CRD':
        k8s_client = client.ApiextensionsV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            api_version = all_files['apiVersion']
            _kind = all_files['kind']
            metadata = all_files['metadata']
            spec = all_files['spec']

            data = client.V1CustomResourceDefinition(
                api_version=api_version, kind=_kind, metadata=metadata, spec=spec
            )
            try:
                k8s_client.create_custom_resource_definition(body=data)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_custom_resource_definition(name=all_files['metadata']['name'], body=data)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'Secret':
        # This requires kwargs dict for creds
        if not kwargs:
            raise Exception(f'No kwargs passed! Dict is required to execute {kind}\n sumologic_accessid and sumologic_access_key are required')
        
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            if all_files['metadata']['name'] == f'arcade-{namespace}-sumologic-setup':
                # Modify data 
                
                if not kwargs:
                    return False
                
                get_kwargs = kwargs['kwargs']
                # Convert AccessID to base64
                convert_access_id_b64 = get_kwargs['sumologic_accessid'].encode('ascii')
                access_id_base64_bytes = base64.b64encode(convert_access_id_b64)
                access_id_base64_string = access_id_base64_bytes.decode("ascii")
                # Convert Access Key to base64
                convert_access_key_b64 = get_kwargs['sumologic_access_key'].encode('ascii')
                access_key_base64_bytes = base64.b64encode(convert_access_key_b64)
                access_key_base64_string = access_key_base64_bytes.decode("ascii")
                all_files['data']['SUMOLOGIC_ACCESSID'] = access_id_base64_string
                all_files['data']['SUMOLOGIC_ACCESSKEY'] = access_key_base64_string
            
            try:
                k8s_client.create_namespaced_secret(namespace=namespace, body=all_files)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_namespaced_secret(all_files['metadata']['name'], namespace=namespace, body=all_files)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'ClusterRole':
        k8s_client = client.RbacAuthorizationV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            try:
                set_body = client.V1ClusterRole(
                    api_version=all_files['apiVersion'],
                    kind=all_files['kind'], metadata=all_files['metadata'],
                    rules=all_files['rules']
                )
                k8s_client.create_cluster_role(body=set_body)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_cluster_role(name=all_files['metadata']['name'], body=all_files)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False


    if kind == 'ClusterRoleBinding':
        k8s_client = client.RbacAuthorizationV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            # print(all_files['metadata']['name'])
            data_to_push = client.V1ClusterRoleBinding(
                api_version=all_files['apiVersion'], kind=all_files['kind'], metadata=all_files['metadata'],
                role_ref=all_files['roleRef'], subjects=all_files['subjects']
            )
            try:
                k8s_client.create_cluster_role_binding(body=data_to_push)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_cluster_role_binding(name=all_files['metadata']['name'], body=data_to_push)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    
    if kind == 'Service':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            try:
                if 'namespace' in all_files['metadata']:
                    if all_files['metadata']['namespace'] == 'kube-system':
                        k8s_client.create_namespaced_service(namespace='kube-system', body=all_files)

                else:
                    k8s_client.create_namespaced_service(namespace=namespace, body=all_files)

            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    # # Some things need metadata.resource_version applied during update.
                    if 'namespace' in all_files['metadata']:
                        if all_files['metadata']['namespace'] == 'kube-system':
                            get_ = k8s_client.read_namespaced_service(name=all_files['metadata']['name'], namespace='kube-system')
                            all_files['metadata']['resourceVersion'] = get_.metadata.resource_version
                            k8s_client.replace_namespaced_service(name=all_files['metadata']['name'], namespace=get_.metadata.namespace, body=all_files)
                    else:
                        get_ = k8s_client.read_namespaced_service(name=all_files['metadata']['name'], namespace=namespace)
                        all_files['metadata']['resourceVersion'] = get_.metadata.resource_version
                        k8s_client.replace_namespaced_service(name=all_files['metadata']['name'], namespace=get_.metadata.namespace, body=all_files)
                    
                
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False

            
    if kind == 'DaemonSet':
        k8s_client = client.AppsV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            _body = client.V1DaemonSet(
                    api_version=all_files['apiVersion'], kind=all_files['kind'], metadata=all_files['metadata'],
                    spec=all_files['spec'])
            try:
                k8s_client.create_namespaced_daemon_set(body=_body, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_namespaced_daemon_set(name=all_files['metadata']['name'], namespace=namespace, body=_body)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    
    if kind == 'Deployment':
        #TODO NOTE THIS HAS A DOCKER IMAGE
        # image: "k8s.gcr.io/kube-state-metrics/kube-state-metrics:v1.9.8"
        k8s_client = client.AppsV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            try:
                k8s_client.create_namespaced_deployment(namespace=namespace, body=all_files)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_namespaced_deployment(name=all_files['metadata']['name'], namespace=namespace, body=all_files)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False

    
    if kind == 'PriorityClass':
        k8s_client = client.SchedulingV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            configured_data = client.V1PriorityClass(
                api_version=all_files['apiVersion'], description=all_files['description'],
                global_default=all_files['globalDefault'], kind=all_files['kind'],
                metadata=all_files['metadata'], value=all_files['value']
            )
            try:
                k8s_client.create_priority_class(body=configured_data)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_priority_class(name=all_files['metadata']['name'], body=configured_data)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    if kind == 'Prometheus':
        k8s_client = client.CustomObjectsApi()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            get_group = all_files['apiVersion'].split('/')[0]
            version = all_files['apiVersion'].split('/')[1]
            _pluarl = all_files['kind'].lower() + 's'

            if all_files['kind'] == 'Prometheus':
                _pluarl = 'prometheuses'

            try:
                k8s_client.create_namespaced_custom_object(
                group=get_group, version=version, namespace=namespace, plural=_pluarl, body=all_files
            )
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    # Note need to get resource version first
                    get_resource_Version = k8s_client.get_namespaced_custom_object(group=get_group, version=version, namespace=namespace, plural=_pluarl, name=all_files['metadata']['name'])['metadata']['resourceVersion']
                    all_files['metadata']['resourceVersion'] = get_resource_Version
                    k8s_client.replace_namespaced_custom_object(
                        group=get_group, version=version, namespace=namespace, plural=_pluarl, name=all_files['metadata']['name'], body=all_files
                    )
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False


    
    if kind == 'Pod':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            data = client.V1Pod(
                api_version=all_files['apiVersion'], metadata=all_files['metadata'],
                spec=all_files['spec'])
            try:
                k8s_client.create_namespaced_pod(namespace=namespace, body=data)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.replace_namespaced_pod(name=all_files['metadata']['name'], namespace=namespace, body=data)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    
    if kind == 'Job':
        # TODO JOB has Continaer images
        k8s_client = client.BatchV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            data = client.V1Job(
                api_version=all_files['apiVersion'], kind=all_files['kind'],
                metadata=all_files['metadata'], spec=all_files['spec']
            )
            try:
                k8s_client.create_namespaced_job(namespace=namespace, body=data)
            except ApiException as api_error:
                if api_error.status == 400 or 409:
                    k8s_client.create_namespaced_job(name=all_files['metadata']['name'], namespace=namespace, body=data)
                elif api_error.status == 401:
                    pass
                else:
                    pprint(api_error)
                    return False

    return True


def deploy_secret(arcade_name: str, eks_cluster: str, namespace: str, sumo_id: str, sumo_key: str, kind='Secret') -> bool:
    """Deploys Secrets for SumoLogic to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        sumo_id (str): SUMOLOGIC access id
        sumo_key (str): SUMOLOGIC access key
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'Secret'.

    Returns:
        bool: True if deployed, False if not.
    """
    my_kwargs = {
        'sumologic_accessid': sumo_id,
        'sumologic_access_key': sumo_key
    }
    
    eks_secrets = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster,
        kwargs=my_kwargs
    )

    if not eks_secrets:
        return False
    else:
        return True


def deploy_configmaps(arcade_name: str, eks_cluster: str, namespace: str, kind='ConfigMap') -> bool:
    """Executes Configmap Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'ConfigMap'.

    Returns:
        bool: True if deployed, False if not.
    """
    configmap = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not configmap:
        return False
    else:
        return True


def deploy_cluster_role(arcade_name: str, eks_cluster: str, namespace: str, kind='ClusterRole') -> bool:
    """Executes ClusterRole Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'ClusterRole'.

    Returns:
        bool: True if deployed, False if not.
    """
    cluster_role = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not cluster_role:
        return False
    else:
        return True


def deploy_cluster_role_bindings(arcade_name: str, eks_cluster: str, namespace: str, kind='ClusterRoleBinding') -> bool:
    """Executes ClusterRoleBinding Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'ClusterRoleBinding'.

    Returns:
        bool: True if deployed, False if not.
    """
    cluster_role_binding = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not cluster_role_binding:
        return False
    else:
        return True


def deploy_daemonset(arcade_name: str, eks_cluster: str, namespace: str, kind='DaemonSet'):
    """Executes DaemonSet Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'DaemonSet'.

    Returns:
        bool: True if deployed, False if not.
    """
    daemon_set = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not daemon_set:
        return False
    else:
        return True


def deploy_deployment(arcade_name: str, eks_cluster: str, namespace: str, kind='Deployment', **kwargs):
    """Executes Deployment Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'Deployment'.

    Returns:
        bool: True if deployed, False if not.
    """
    deployment = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not deployment:
        return False
    else:
        return True


def deploy_job(arcade_name: str, eks_cluster: str, namespace: str, kind='Job'):
    """Executes Job Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'Job'.

    Returns:
        bool: True if deployed, False if not.
    """
    job = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not job:
        return False
    else:
        return True


def deploy_pod(arcade_name: str, eks_cluster: str, namespace: str, kind='Pod'):
    """Executes Pod Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'Pod'.

    Returns:
        bool: True if deployed, False if not.
    """
    pod = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not pod:
        return False
    else:
        return True


def deploy_pod_disruption_budget(arcade_name: str, eks_cluster: str, namespace: str, kind='PodDisruptionBudget'):
    """Executes PodDisruptionBudget Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'PodDisruptionBudget'.

    Returns:
        bool: True if deployed, False if not.
    """
    pod_disruption_budget = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not pod_disruption_budget:
        return False
    else:
        return True


def deploy_pod_security_policy(arcade_name: str, eks_cluster: str, namespace: str, kind='PodSecurityPolicy'):
    """Executes PodSecurityPolicy Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'PodSecurityPolicy'.

    Returns:
        bool: True if deployed, False if not.
    """
    pod_security_policy = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not pod_security_policy:
        return False
    else:
        return True


def deploy_priority_class(arcade_name: str, eks_cluster: str, namespace: str, kind='PriorityClass'):
    """Executes PriorityClass Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'PriorityClass'.

    Returns:
        bool: True if deployed, False if not.
    """
    deploy_priority_class = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not deploy_priority_class:
        return False
    else:
        return True


def deploy_service(arcade_name: str, eks_cluster: str, namespace: str, kind='Service'):
    """Executes Service Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'Service'.

    Returns:
        bool: True if deployed, False if not.
    """
    service = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not service:
        return False
    else:
        return True


def deploy_service_account(arcade_name: str, eks_cluster: str, namespace: str, kind='ServiceAccount'):
    """Executes ServiceAccount Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'ServiceAccount'.

    Returns:
        bool: True if deployed, False if not.
    """
    service_account = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not service_account:
        return False
    else:
        return True


def deploy_stateful_set(arcade_name: str, eks_cluster: str, namespace: str, kind='StatefulSet', **kwargs):
    """Executes StatefulSet Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'StatefulSet'.

    Returns:
        bool: True if deployed, False if not.
    """
    stateful_set = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not stateful_set:
        return False
    else:
        return True


def deploy_crd(arcade_name: str, eks_cluster: str, namespace: str, kind='CRD') -> bool:
    """Deploys CRD to eks.

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'CRD'.

    Returns:
        bool: True if deployed, False if not.
    """
    crd = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )
    if not crd:
        return False
    else:
        return True


def deploy_prometheus(arcade_name: str, eks_cluster: str, namespace: str, kind='Prometheus') -> bool:
    """Executes Prometheus Deployment to EKS

    Args:
        arcade_name (str): Name of the Arcade
        eks_cluster (str): Name of the EKS cluster
        namespace (str): Namespace to be depoyed to
        kind (str, optional): The kind of maifest deployment. Shouldn't have to change. Defaults to 'StatefulSet'.

    Returns:
        bool: True if deployed, False if not.
    """
    stateful_set = create_sumologic_fluentd(
        arcade_name=arcade_name,
        kind=kind,
        namespace=namespace,
        eks_cluster=eks_cluster
    )

    if not stateful_set:
        return False
    else:
        return True


def delete_namespace(arcade_name: str, namespace: str) -> bool:
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    k8s_client = client.CoreV1Api()

    try:
        k8s_client.delete_namespace(name=namespace)
    except ApiException as api_error:
        if api_error.status == 404:
            pass
        else:
            pprint(api_error)
            return False

    return True


def delete_sumologic(arcade_name: str, namespace: str, kind: str) -> bool:
    """Deletes Kubernetes Flunetd/Sumologic Intergration
    Args:
        arcade_name (str): Name of the Arcade
        namespace (str): Name of the namespace
        kind (str): The kubernetes manifest kind

    Returns:
        bool: True, if successful, False if not successfull
    """
    mainfest_location_dir = get_yaml_dirctory(kind=kind)

    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False

    if kind == 'CRD':
        k8s_client = client.ApiextensionsV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_custom_resource_definition(name=name)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'PodSecurityPolicy':
        k8s_client = client.PolicyV1beta1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_pod_security_policy(name=name)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'PodDisruptionBudget':
        k8s_client = client.PolicyV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_pod_disruption_budget(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'ServiceAccount':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_service_account(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'Secret':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_secret(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'ConfigMap':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_config_map(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'ClusterRole':
        k8s_client = client.RbacAuthorizationV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_cluster_role(name=name)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'ClusterRoleBinding':
        k8s_client = client.RbacAuthorizationV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_cluster_role_binding(name=name)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'Service':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                if 'namespace' in all_files['metadata']:
                    if all_files['metadata']['namespace'] == 'kube-system':
                        k8s_client.delete_namespaced_service(name=name, namespace='kube-system')
                else:
                    k8s_client.delete_namespaced_service(name=name, namespace=namespace)
            
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    if kind == 'DaemonSet':
        k8s_client = client.AppsV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_daemon_set(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'Deployment':
        k8s_client = client.AppsV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_deployment(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'StatefulSet':
        k8s_client = client.AppsV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_stateful_set(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False


    if kind == 'Prometheus':
        k8s_client = client.CustomObjectsApi()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            get_group = all_files['apiVersion'].split('/')[0]
            version = all_files['apiVersion'].split('/')[1]
            _pluarl = all_files['kind'].lower() + 's'

            if all_files['kind'] == 'Prometheus':
                _pluarl = 'prometheuses'
            try:
                k8s_client.delete_namespaced_custom_object(group=get_group, version=version, namespace=namespace, plural=_pluarl, name=name)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'PriorityClass':
        k8s_client = client.SchedulingV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_priority_class(name=name)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    if kind == 'Pod':
        k8s_client = client.CoreV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']
            try:
                k8s_client.delete_namespaced_pod(name=name, namespace=namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False
    
    if kind == 'Job':
        k8s_client = client.BatchV1Api()
        manifest = open_mainifest_and_generate(path=mainfest_location_dir, filename=kind)
        for all_files in manifest:
            name = all_files['metadata']['name']

            try:
                k8s_client.delete_namespaced_job(name, namespace)
            except ApiException as api_error:
                if api_error.status == 404:
                    pass
                else:
                    pprint(api_error)
                    return False

    return True

