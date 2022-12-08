The only Unix command you need to know is man


How to make man pages, with out loosing your mind

https://www.howtogeek.com/682871/how-to-create-a-man-page-on-linux/

sudo apt update && sudo apt intstall -y pandoc

# TODO: need to address man page location via installer,
# e.g. install to same install path as tooling, and add to MANPATH
sudo mkdir -p <install_path>/share/man/{man1,man3,man4}

pandoc grv-create.1.md -s -t man | /usr/bin/man -l -

pandoc grv-create.1.md -s -t man -o grv-create.1

gzip grv-create.1

sudo cp grv-create.1.gz /usr/local/share/man/man1

sudo mandb 

Conventional  section  names include 
NAME 
SYNOPSIS 
CONFIGURATION 
DESCRIPTION 
OPTIONS  
EXIT STATUS  
RETURN VALUE  
ERRORS  
ENVIRONMENT
FILES  
VERSIONS  
CONFORMING TO  
NOTES  
BUGS  
EXAMPLE 
AUTHORS
SEE ALSO
