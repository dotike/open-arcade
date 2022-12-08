# Galaga Installer
## Galaga Zero (Arcade Initialization)

### Description
This installer will configure the Arcade with basic required functionality.  For example certain IAM permission tweaking 
that is required for tooling to function and S3 bucket configuration.  This is intended to run once for an account and become 
a noop whenever it's executed again (unless modifications have been made).

### Available Service Options
Parameters provided to the service where the specified defaults can be overridden by a Galaga

* **super_service_account**: Account number for the super service account
* **super_service_role_name**: Read secret role name
* **super_service_prefix**: Prefix for the superservice