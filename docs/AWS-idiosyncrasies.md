# Behaviors and operations peculiar to Amazon Web Services (AWS).

## New Accounts 4 hour validation on first use
2022.06, issue first observed ~2016.

This is a rarely observed intermittent issue, which happens under the following conditions:

  - When using a completely new AWS account
  - When building a VPC using any region

The first operations to build resources in a given region are blocked by AWS, until AWS validates the region is available for use.

### Example

The following AWS API error was returned in a new, unused, AWS account.

The proces was:

  1) New AWS account provisioned, (sat for several days until use)
  2) VPC Created
  3) Subnets and related network object requirements created
  4) The first EC2 instance was being created, and *the following error was hit*:

```
ValueError: /Users/andy.dunlap/Documents/arcade/libexec/grv-create main(): create_stage(): state nat_instances_complete: An error occurred (PendingVerification) when calling the RunInstances operation: Your request for accessing resources in this region is being validated, and you will not be able to launch additional resources in this region until the validation is complete. We will notify you by email once your request has been validated. While normally resolved within minutes, please allow up to 4 hours for this process to complete. If the issue still persists, please let us know by writing to aws-verification@amazon.com for further assistance.
```

Note: this error was returned for an EC2 instance, but this has also been seen before for other “service” object types, for example, NAT Gateways, EKS Clusters, and the like. This error has not encountered for VPC “network” object types, (e.g. S3 gateways, ALB’s, and the like).

In every case where this issue is hit, waiting 4 hours does indeed resolve things.

### Steps necessary if resoulition is to be automated:

To provide new AWS accounts where the first users do not encounter this error while deploying services, the following steps need to happen:

  - A full VPC needs to be built in every available region (or, every region planned for common use)
  - At least 1 EC2 instance should be lit in any availability zone, (triggering this opaque AWS issue)
    - For completeness, 1 EC2 instance should be lit in every availability zone, (from reading online, it is unclear if this trigger is fully region related, or, an AZ related validation.)
  - The created EC2 instance(s) should be deleted, and all created VPC resource built should be deleted.
  - Wait 4 hours, re-run these operations to confirm the account is “validated” and ready for use.

----

