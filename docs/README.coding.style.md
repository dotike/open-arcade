# IPTOOLS Coding Style

---

## Languages
  - The IPTOOLS team develops in two languages; Python 3 and POSIX shell. The use of other languages is discouraged unless there is a compelling need. The supported python is one with a version greater that 3.6. Pthon and shell are invoked as follows;
    ```
      #!/usr/bin/env python3
      #!/bin/sh
    ```

---

## Library -- arclib
  - One of the primary focus of the IPTOOLS group is the development and maintenance of the arclib. Written in python3 it is the repository of code common to the tools used to support the Arcade system. Any functionality that is found in more than one tool should be made generic and placed in one of the modules contained in the arclib. All tools in the Arcade system will use the library version of a given function and not a local copy. Local copies of a function should be removed from the tool after the functionality has been moved to a library module.      

---

## Library -- additional modules
  - The use of additional external libraries should be kept to a minimum with only those libraries that directly affect the Arcade system should be installed. External libraries that are used by the arclib should be included in the list of required libraries in the **setup.py** file under **INSTALL_REQUIRES**. External libraries should also be added the **requirements.txt** file.

---

## Modules
  - IPTOOLS libraries, currently only arclib, is composed a series of python files refereed to as modules. Each module contains functions pertaining to a specific functionality and the file name indicates. For example, the file, ami.py, contains functions related to the usage of AMI.

  - Files of python and shell code shall start with the following three lines, in the case of python;
    ```
    #!/usr/bin/env python3
    # -*- mode: python -*-
    # -*- coding: utf-8 -*-
    ```
    The exception to this is the case of a library modules where there is no **main** function where the first line is, /usr/bin/env python3, should be dropped.

    In the case of shell;
    ```
    #!/bin/sh
    # -*- mode: shell -*-
    # -*- coding: utf-8 -*-
    ```

  - In keeping with PEP 8 a module should contain docstring and dunder information.

  ```
  """
  < module name > -- < short module description >
  """

  # @depends: boto3, python (>=3.7)
  __version__ = 'X.Y.Z'
  __author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
  __description__ = "< short module description >"
  ```

  The above block of text should be placed between the editor mode and encoding hints and the python includes.

  - Module level global variables are discouraged. Global variables can lead to unexpected side effects. The scope of a variable should be a s low as possible.

---

## Functions
  - Each module contains functions that directly relate the module functionality. In keeping with the *nix philosophy a function does one thing only and does it well. The name of the function reflects what the function does.

  - It is suggested that the first word of a function be a verb reflecting what the function does. e.g. **get_ami_version()**  

  - A best practice is there is one entry point to a function and one exit point. Exiting out of a function early is discouraged except in the case of a fatal error. Early exits are one of the sources of spaghetti code.

  - When exiting out of a function the function should return something even if only a return of 0. Code that simply falls out of a function can lead to confusion by people using the code.  

  
---

## PEP 8
  - The IPTOOLS team and the Arcade system adheres to the PEP 8 standard as much as possible. The use of pylint goes a long way to keeping to this standard. Please refer to the [PEP 8](https://peps.python.org/pep-0008/) document for more information.

---

## pylint
  - The use of pylint is strongly encouraged. Before any code is merged into the dev branch it is expected that the code will be able to pass through pylint with a minimum of warnings. Those warnings that can be safely ignored will be determined by the team and the users .pylintrc.

  - A user should have a **.pylintrc** in their home directory. The .pylintrc is generated as follows
  ```
  pylint --generate-rcfile > $HOME/.pylintrc
  ```    

  - The users manual for pylint can be found at [pylint](https://pylint.pycqa.org/en/latest/index.html)


---

## On Argparse

When using (Argparse)[https://docs.python.org/3/library/argparse.html], our programs should conform to a UNIX-ish standard when handling command line options.

These basic standards for argparse usage get us 90% of the way there:

```
        parser = argparse.ArgumentParser(
            description=__description__,
            epilog=__usage__,
            prog='arcade <program name>',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
```

    - description - leverage this critical default, (don't parse main() docstring)
    - epilog - put man-page style usage information here, anything which explains:
        - what is this program for?
        - what output should a user expect?
        - what behaviors or specific common nuance should we tell users?
        - what ENV vars doess our program respect or expect?
        - how does our program exit in common special cases?

    - prog - The name of the program should follow this convention. If the name was asd-init.py, then the prog should be arcade asd init.
    - formatter_class - be explicit with output for the programs, (argparse mangles multiline text by default)

Whenever detailed arg handling and output is required, (getopt())[https://docs.python.org/3/library/getopt.html] is always a fine alternative choice- but as a team we should try to first (use Argparse)[https://docs.python.org/3/library/argparse.html] because:

    - Argparse is quick to use (a lot of things handled for you)
    - Argparse encourages interfaces-first programming
    - Argparse is commonly used, and well understood across the team 
