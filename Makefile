# make is easy, and sometimes fun!
all:
	printf "\nCheck out the example dropped into:\n  misc/make_example/Makefile\n\n"

install: misc/install.proposal.deleteme.txt
	cat misc/install.proposal.deleteme.txt

test: tests/deleteme
	printf "\nI would love to see all tests run from one command,\n  - unit tests\n  - functional tests\n\n"

