# Galaga Installer
## Hashicorp Vault Enterprise

### Description
This installer will configure Hashicorp Vault Enterprise for the Arcade.  This service is intended to be used as a secrets store.
Application required secret data can be added to Secrets Manager and the application can retrieve that data at run time.
This is the implementation of the Hashicorp supported vault we license from them.

### Available Service Options
Parameters provided to the service where the specified defaults can be overridden by a Galaga

* **cluster_name**: Name for the Vault cluster
* **vault_domain**: The domain the Vault cluster should use
* **vault_asg_capacity**: The max size for the Vault node autoscale group
* **vault_instance_type**: Instance type for each Vault node
* **vault_node_ami_name**: AMI NAME to use when creating a Vault node
* **elb_internal**: Toggle to speficy whether the Internal or External Load Balancer will be used
* **vault_vol_delete_on_termination**: Toggle for Delete on Termination for the Vault EBS volume
* **vault_ebs_root_vol_type**: Volume type for Vault node root EBS volume
* **vault_ebs_root_vol_size**: Volume size for Vault node root EBS volume
* **vault_ebs_vol_encrypted**: Toggle for whether or not the EBS volumes are encrypted
* **vault_ebs_data_vol_type**: Volume type for Vault node data EBS volume
* **vault_ebs_data_vol_size**: Volume size for Vault node data EBS volume


### Vault Enterprise(vault.json) and Vault Community(vault-community.json) CAN NOT be installed simultaneously within the same galaga.json.
