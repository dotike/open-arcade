import boto3
import sys

s3 = boto3.client('s3')
s3.download_fileobj('asd2021', '21/01/12/23/30/6feadb30a18b0aa503b3a85fc7a89393.json', sys.stdout.buffer)
