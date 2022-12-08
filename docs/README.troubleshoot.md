# ARCADE Development: Troubleshooting

### This is a document that provides debugging methodologies and how to troubleshoot and fix issues.

### Any and all additions here are highly appreciated!

## ASTEROID

### Monitoring

#### View all deployments (services added and enabled above)
  > % kubectl get deployments --all-namespaces

#### View named asteroid's deployments.
  > % kubectl get deployments -n ${ASTEROID_NAME}

#### View the pods(services) running and their state.
  > % kubectl get pods -n ${ASTEROID_NAME}

#### View a service's logs.
  > % kubectl logs -f <name_from_get_pods_above> -n ${ASTEROID_NAME} --previous=false >& /tmp/svc_name.log &
  >
  > % less /tmp/svc_name.log

#### View details of the above pods. Helpful to see why a service stays in STATUS:Pending.
  > % kubectl describe pods -n ${ASTEROID_NAME}

#### View all active asteroids.
  > % arcade asteroid list -A ${ARCADE_NAME}

### Debugging

#### If the reconcile failed on a component, you can run the following to back it off and fix it.
  > % arcade asteroid disable -A ${ARCADE_NAME} -a ${ASTEROID_NAME}
  >
  > % arcade narc reconcile
#### Then see if you can resolve the issue. If not, enable and reconcile again and try some of the steps below.

#### If a service just seems to get skipped over you can run this command to see if there are any
#### leftover configs.
  > % kubectl get configmap -n ${ASTEROID_NAME}

#### Run this to delete them if you find any that shouldn't be there.
#### Don't remove the 'kube-root-ca.crt' configmap.
  > % kubectl delete configmap -n ${ASTEROID_NAME} <from_above>
#### Or use this one to nuke all the ones you should nuke and start over clean.
  > % kubectl get configmap -n ${ASTEROID_NAME} | grep narc-${ASTEROID_NAME} | awk '{print $1}' | xargs kubectl delete configmap -n ${ASTEROID_NAME}
#### Then try again after they are deleted.

#### Connect to ec2 instance:
  > % kubectl get pods -n ${ASTEROID_NAME}
  >
  > % kubectl exec -it <select a name from the list above> -n ${ASTEROID_NAME} -- /bin/bash
#### Install telnet:
  > % apt clean; apt update; apt install telnet
#### From there you can use telnet to test memcached (ElastiCache) for instance:
  > % telnet aoa-aws.osaxwu.cfg.usw2.cache.amazonaws.com 11211

#### Connect to webservice to see if things are running.
#### Determine the kubernetes pod running webservice.
  > % kubectl get po -n ${ASTEROID_NAME} | grep webservice
#### Setup a port forward:
  > % sudo kubectl port-forward pod/<pod_name_from_above> 443:443 -n ${ASTEROID_NAME}
#### In your browser connect to: https://localhost
