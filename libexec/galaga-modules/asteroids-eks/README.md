# Galaga Module
## ASTEROIDS EKS

### Description
This installer will create the component infrastructure necessary for ASTEROIDS to run.
 * private alb
 * public alb
 * EKS cluster
 * Nodegroup for EKS cluster
 * Fleuntd DaemonSet for log collection to log-relay

### Available Service Overrides
`-o services/<component>/service_options/{parameter}=value`

For creation and update:
 * services/eks/service_options/eks_version=1.21
 * services/nodegroup/service_options/asteroids/nodes=4
 * services/nodegroup/service_options/asteroids/max_nodes=4

**Update ARCADE toe_nail.arc to support 6 EKS nodes in the asteroids nodegroup.**

`% arcade galaga add -A toe_nail.arc -p gsd/asteroids-eks/default.json -o services/nodegroup/service_options/asteroids/nodes=6`

**If 'nodes' is greater than 'max_nodes', 'max_nodes' will be set to the value of 'nodes'.**

