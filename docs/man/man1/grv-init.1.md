% GRV-INIT(1) grv-init 0.1
% Addepar Infrastructure Platform Tools Team <iptools@addepar.com>
% Jan 2021

# NAME
grv-init - combinator over the grv tooling


# SYNOPSIS
**grv-init**\
**grv-init** -h\
**grv-init** -y\
**grv-init** -v


# DESCRIPTION 
**grv** is a driver script that envokes the command to create, destroy, init, and list GRVs


# OPTIONS
**-h**
: Prints the help options

**y**
: Answers "yes" to all options

**-v**
: Turns on verbose output


# EXAMPLES
**arcade grv init -y**
: Sets up the current shell got GRV creation


# EXIT STSTUS
**0**  if OK\
**44**  AWS is not properly setup


# ENVIRONMENT
**MYHIER**
: Sets the base directory from which the rest of the gravatar tooling can be found.

**AWS_ACCESS_KEY_ID**
: Used to create a zone info file


# BUGS
Please report any bugs in jira


# SEE ALSO
grv (1), grv-create (1), grv-destroy (1), grv-list (1)


