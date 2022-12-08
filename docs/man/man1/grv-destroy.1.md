% GRV-DESTROY(1) grv-destroy 0.1
% Addepar Infrastructure Platform Tools Team <iptools@addepar.com>
% Jan 2021

# NAME
grv-destroy - delete a GRV

# SYNOPSIS
**grv-destroy** -a\
**grv-destroy** -h\
**grv-destroy** -p [GRV name]\
**grv-destroy** -v\
**grv-destroy** -y


# DESCRIPTION 
**grv** is a driver script that envokes the command to create, destroy, init, and list GRVs


# OPTIONS


# EXAMPLES


# EXIT STATUS
**0**  if OK\
**1**  if a minor problem


# ENVIRONMENT
**grv-destroy** uses a number of environment variables

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
Currently (Jan 2022) this command does not work. Do Not Use


# SEE ALSO
grv (1), grv-create (1), grv-init (1), grv-list (1)


