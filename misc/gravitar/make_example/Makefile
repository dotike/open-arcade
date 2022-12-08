# just dorking around
all: foo.txt foo.py
	cp foo.txt /tmp/foo.txt
	cat /tmp/foo.txt
	./foo.py
	printf "\nInstall Completed\n(you can run `make uninstall` if you wish)\n"

uninstall: 
	$(RM) /tmp/foo.txt
