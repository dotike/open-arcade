# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
log -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import logging


# --------------------------------------------------------------------
#
# add_log_level_agument
#
# --------------------------------------------------------------------
def add_log_level_argument(parser):
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity, default is WARNING",
                        action="count", default=0)


# --------------------------------------------------------------------
#
# set_log_level
#
# --------------------------------------------------------------------
def set_log_level(verbose):
    if verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)
