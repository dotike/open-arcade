% ARCADE-SET(1) arcade-set 0.0.1
% Addepar Infrastructure Platform Tools Team <iptools@addepar.com>
% Jan 2021

# NAME
arcade-set - Configure current shell environmen to use arcade tooling

# SYNOPSIS
source **arcade-set** < ARCADE NAME >\
source **arcade-set** -h\
source **arcade-set** -n

# DESCRIPTION 

# OPTIONS

# EXAMPLES

# EXIT STATUS
**0** if OK\
**1** if an error occured

# ENVIRONMENT
**arcade-set** uses a number of environment variables, most of which are
set by **arcade-set**


**ARCADE_NAME**
: boo


**AWS_DEFAULT_REGION**
: boo


**GALAGA_BUCKET**
: boo


**GSD_BUCKET**
: boo


**MYHIER**
: boo


**PATH**
: boo


**PYTHONPATH**
: boo


**ATMP**
: ARCADE tmp, the tool **arcade** sets this environment variable and defaults
to "${HOME}/tmp/arcade", which is a scratch directory like /tmp but the
contents survive a reboot of the system.


**TMP_DIR**
: DEPRECATED, This environment variable is the equilivent of **ATMP**.
The reason for this is some programs used this instead of **ATMP**.


**VERBOSE**
: This variable is set to **1**, **yes**, or **true** by the user to turn
on verbose output.


# BUGS
Please report any bugs in jira


# SEE ALSO



