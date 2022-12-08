% GRV-CREATE(1) grv-create 0.1
% Addepar Infrastructure Platform Tools Team <iptools@addepar.com>
% Jan 2021


# NAME
grv-create - create a GRV

# SYNOPSIS
**grv-create** -c [class]\
**grv-create** -h\
**grv-create** -i [creation index]\
**grv-create** -l\
**grv-create** -r [region]\
**grv-create** -v\
**grv-create** -y


# DESCRIPTION 
**grv-create** is part of the gravitar tools suite. It is used to create a GRV, which is an arcade formated AWS VPC in a given AWS region. By default that region is us-east-2 (Ohio)


# OPTIONS


# EXAMPLES
**grv-create -y**
: Creates the GRV using the default options

**grc-create -r us-west-2**
: Creates a GRV in the AWS region us-west-2 (oregon) 


# EXIT STATUS
**0**  if OK\
**1**  if not OK\
**2**  if skip\
**3**  if not yet\
**4**  if fail\
**5**  if not found\



# ENVIRONMENT
**grv-create** uses a number of environment variables

**AWS_DEFAULT_REGION**
: This overrides the default AWS region (us-east-2)

**MYHIER**
: Sets the base directory from which the rest of the gravatar tooling can be found.

**ATMP**
: ARCADE tmp, the tool **arcade** sets this environment variable and defaults 
to "${HOME}/tmp/arcade", which is a scratch directory like /tmp but the 
contents survive a reboot of the system.

**TMP_DIR**
: DEPRECATED, This environment variable is the equilivent of **ATMP**.
The reason for this is some programs used this instead of **ATMP**.

**VERBOSE**
: Setting this to yes or True turns on verbose output


# BUGS
There are no bugs in our code. Should you find one please report it in Jira.


# SEE ALSO
grv (1), grv-destroy (1), grv-init (1), grv-list (1)


