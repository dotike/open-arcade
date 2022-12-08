AWS Resources "tagability"
Last update: Fall 2022

Most AWS products and components can be tagged.  Some cannot, and some are ambigious.
The following list is was compiled as a by-product of tagging work, Summer 2022. https://docs.google.com/spreadsheets/d/1TLJH91KwLg9PLpLi8F3ifPk4I9nG6LEMZolLJzkJIDM/edit?usp=sharing

----

**Resources with Tagging Supported**
(and supported by ARCADE tagging facilities)

  - EC2 EIP
  - EC2 Instance
  - EC2 InternetGateway
  - EC2 NatGateway
  - EC2 NetworkAcl
  - EC2 NetworkInterface
  - EC2 RouteTable
  - EC2 SecurityGroup
  - EC2 Subnet
  - EC2 VPC
  - EC2 Volume (EBS)
  - EKS Cluster
  - EKS Nodegroup
  - ElasticLoadBalancingV2 LoadBalancer
    + Only tested with application load balancers; classic and network untested, although network should work
  - ElasticLoadBalancingV2 TargetGroup
  - Kafka Cluster
  - Lambda Function
    + Arcade scoped; should be able to filter by VPC to find
  - RDS DBInstance
  - RDS DBSecurityGroup
    + Tagged when VPC sg's get tagged
  - RDS DBSubnetGroup
    + Not the end of the world if not implemented; the subnets themselves are tagged
  - Route53 HealthCheck
    + Arcade Scoped
  - Route53 HostedZone
  - S3 Bucket

**Probably Need to Tag**

  - ElastiCache CacheCluster
    + If we do, it probably wont be until a later phase. We don't currently use it. Also, see elasticache configuration

**Not currenlty planning on tagging**
(can't/wont)

  - SSM Parameter
    + Implementation is ready but untested
  - SecretsManager Secret
    + Implementation currently only gets secrets whose title have the arcade name, not asteroids
  - CloudFormation Stack
  - CloudTrail Trail
  - CloudWatch Alarm
  - CodeBuild Project
  - CodePipeline Pipeline
  - CodePipeline Webhook
  - DynamoDB Table
  - EC2 Container Registry
  - EC2 DHCPOptions
  - EC2 Image
  - ECS TaskDefinition
  - Events Rule
  - GuardDuty
  - IAM InstanceProfile
    + Account scoped
  - IAM ManagedPolicy
    + Account scoped
  - IAM OpenIDConnectProvider
  - IAM SAMLProvider
  - KMS Key
  - RDS DBClusterParameterGroup
    + Leaning towards no
  - RDS DBParameterGroup
    + Leaning toward yes just because some asteroids use it
  - RDS DBSnapshot
    + Leaning towards no
  - RDS OptionGroup
    + Leaning towards no

**Unsure of tagging capabilities**

  - EC2 Snapshot
    + Probably not
  - ElasticLoadBalancing LoadBalancer


----
Misc. Notes
* this list is high-level. There are some nitty-gritty things inside some of these resources that can also be tagged. Those will be noted when known.
* this listed was derived from the ResourceGroup Tag Editor, then added to based on looking at the billing breakdown
