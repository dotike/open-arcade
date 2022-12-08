# Galaga module
## ASTEROIDS MSK

### Description
This installer will create the component infrastructure necessary for ASTEROIDS to run.
 * MSK cluster

### Available Service Options
Parameters provided to the service where the specified defaults can be overridden by a Galaga

`-o services/msk/service_options/{parameter}=value`

For creation:
 * services/msk/service_options/instance_type=kafka.m5.large
 * services/msk/service_options/kafka_version=2.6.2
 * services/msk/service_options/ebs_size=100
 * services/msk/service_options/brokers_per_az=1
 * services/msk/service_options/cfg_auto_create_topics_enable=true
 * services/msk/service_options/cfg_delete_topic_enable=true
