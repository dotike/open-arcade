# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
cli -- A library for common or uniform command line interface
components, particularly things which we want to do consistently
across all tools.
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <Iptools@Addepar.Com>'
__description__ = ""
__version__ = '1.0.0'


import os
import sys


# --------------------------------------------------------------------
#
# vprint
#
# --------------------------------------------------------------------
def vprint(prettymuchanything='', fd=sys.stderr):
    '''
    Verbose print string, rf verbose mode is set, Prints just about
    anything to screen, prepending with '#' for safety.
    Suitable for use instead of code commentary.  Also suitable to
    print variables, JSON or python object dumps which a user may
    care aobut, etc...

    Strings handed to this method will print to screen only if
      - the ENV var "VERBOSE" is not null, (or an emty string)
      - the variable 'verbose' exists and is not null

    These settings are often set via getopt input, or, are inherited
    from a program condition, or calling parent process.

    Args:

      prettymuchanything - Usually strings, but just about any
                           python object will be printed.

      fd - file descriptor out, usually 'sys.stderr' or 'sys.stdout'
           Does not force this file descriptor if program is already
           redirecting.

    Returns:

      If "VERBOSE" or 'verbose' set, Print input to screen, via fd.
      Prints/returns nothing if "VERBOSE" not set.

    Examples:

      vprint("We are doing someting important now.")
      # will print that string to stderr, if "VERBOSE" set

      vprint(some_gnarly_boto_object)
      # will print that output as string to stderr, if "VERBOSE" set

      vprint("foo", fd=sys.stdout)
      # will print the string "foo" to stdout, if "VERBOSE" set

    '''
    try:
        if os.environ['VERBOSE']:
            print("# {}".format(str(prettymuchanything)), file=fd)
        elif verbose:
            print("# {}".format(str(prettymuchanything)), file=fd)
    except Exception:
        pass
    # End of vprint


# --------------------------------------------------------------------
#
# yes_no
#
# --------------------------------------------------------------------
def yes_no(optional_bypass=None):
    '''
    NOTICE: causes interactive interruption to program runtime

    For convienence, bad input will cause your program to exit.
    (Generally bad practice for a library call, but this is an easy
    helper method.)

    Call this method to present and process a yes/no answer from user
    input, return this choice as True/False, die on bad input.

    Can be bypassed if any Non-Null value is passed.

    Function Input:
       optional_bypass - any non-Null value will not pause to present
       user input, and will immediately return "True", as if a user
       has presented yes.

    Human Input:
       A human will be asked to supply a yes or no answer.
       The only 'correct' response values are:
         - "y", "Y", "yes", or "YES"
         - "n", "N", "no", or "NO"

    Output:
        Just a boolean, True or False

        Any incorrect human input will print a message to stderr,
        and exit the program.

    Example Usage:

    >> sys.stdout.write("Do you think I'm funny? [y/n] ")
    >>
    >> if cli.yes_no():
    >>     print("Alright!")
    >>     tell_another_joke()
    >> else:
    >>     print("meh.")
    >>     sys.exit(44)

    '''
    try:
        if optional_bypass:
            return True
        else:
            user_choice = input()
            if user_choice.lower() in ['y', 'yes']:
                return True
            elif user_choice.lower() in ['n', 'no']:
                return False
            else:
                # This is bad form for most library methods,
                # but it makes this method very simple to use:
                sys.exit("Bad input, expected yes or no.")

    except Exception as err:
        raise type(err)(
            'yes_no() error: {}'.format(err))

    # End of yes_no

