import os
import logging
import sys
import subprocess
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import glob


def lambda_handler(event, context):
    subprocess.call('pip3 install mysql-connector-python -t /tmp/ --no-cache-dir'.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sys.path.insert(1, '/tmp/')
    from mysql.connector import connect, Error
    download_file(event['Bucket'], 'arcade_db/empty_asteroid_backup.sql', '/tmp/db.sql')
    my_db = connect(host=event['DBNAME'], user=event['USERNAME'], passwd=event['PASSWORD'], buffered=True)
    with my_db.cursor() as cursor:
        try:
            logging.info('Excuting Cursor to Create ARCADE DB')
            d = cursor.execute('CREATE DATABASE arcade')
            logging.info(d)
            print(d)
        except:
            logging.info('Dropping to pass/Something went wrong')
            print('Dropping to pass/Something went wrong')
            pass
        userarcade = cursor.execute('USE arcade')
        logging.info(userarcade)
        with open('/tmp/db.sql', 'rb') as f:
            for line in f:
                z = cursor.execute(f.read(), multi=True)
                logging.info(z)
                print(z)

def verify(event):
    my_list = []
    my_db = connect(host=event['DBNAME'], user=event['USERNAME'], passwd=event['PASSWORD'], buffered=True)
    mycursor = my_db.cursor()
    mycursor.execute('USE arcade')
    mycursor.execute("Show tables;")
    myresult = mycursor.fetchall()
    
    for x in myresult:
        my_list.append(x)
    
    for items in my_list:
        print(items)


def download_file(s3_bucket: str, s3_file_path: str, local_file_name: str):
    s3 = boto3.resource('s3')
    try:
        download = s3.Bucket(s3_bucket).download_file(s3_file_path, local_file_name)
        return True
    except ClientError as e:
        return e
