import pathlib
from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent

VERSION      = '1.0.7'
PACKAGE_NAME = 'arclib'
AUTHOR       = 'Infrastructure Platform Tools'
AUTHOR_EMAIL = 'iptools@addepar.com'
URL          = ''

DESCRIPTION = 'Library of the Arcade tools'
LONG_DESCRIPTION = (HERE / "README.md").read_text()
LONG_DESC_TYPE = "text/markdown"

INSTALL_REQUIRES = [
    'PyYAML',
    'boto3',
    'botocore',
    'graphlib',
    'jsonschema',
    'kubernetes'
]

setup(name=PACKAGE_NAME,
      version=VERSION,
      description=DESCRIPTION,
      long_description=LONG_DESCRIPTION,
      long_description_content_type=LONG_DESC_TYPE,
      author=AUTHOR,
      license=LICENSE,
      author_email=AUTHOR_EMAIL,
      url=URL,
      install_requires=INSTALL_REQUIRES,
      packages=find_packages()
      )
