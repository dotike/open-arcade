# Galaga Module
## log-relay (ASG)

### Description
This installer will install a Log Relay as an AWS Auto Scaling Group cluster in the Arcade
When the log relay is setup, it will also create a CloudWatch group and send all logs to this group. This creation happens as part of the installation and configuration of the CloudWatch agent in the ASG instances.

### Available Service Options
Parameters provided to the service where the specified defaults can be overridden by a Galaga

`-o services/asg/service_options/{parameter}=value`

For creation:
 * services/asg/service_options/asg_capacity=1
 * services/asg/service_options/asg_max_capacity=1
 * services/asg/service_options/ebs_root_vol_size=20
 * services/asg/service_options/ebs_data_vol_size=100

### Uploading user_data

`% arcade galaga userdata upload -f libexec/galaga-modules/log-relay/log-relay.tpl --gsd log-relay`
