# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
s3_object_lock -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import boto3
import os

from datetime import datetime


# --------------------------------------------------------------------
# 
# S3ObjectLockedException
#
# --------------------------------------------------------------------
class S3ObjectLockedException(Exception):
    """Raised when the S3ObjectLock is not acquired """
    pass

# --------------------------------------------------------------------
#
# S3ObjectLock
#
# --------------------------------------------------------------------
class S3ObjectLock:
    """A context manager class to handle lock using s3 object"""
    def __init__(self, bucket: str, name: str, key: str, verbose=False) -> None:
        """Constructor of the class

        Args:
            bucket: the s3 bucket
            name: the name of the lock
            key: the key of the s3 object
        Returns: None
        """
        conn = boto3.resource('s3')
        self.bucket = conn.Bucket(bucket)
        self.name = name
        self.key = key
        self.verbose = verbose

    def _lock_busy(self) -> bool:
        """Check whether the lock is busy"""
        obj_list = list(self.bucket.objects.filter(Prefix=self.key))
        return len(obj_list) == 1 and obj_list[0].key == self.key

    def __enter__(self):
        """Acquire s3 object lock"""
        user = os.getenv('USER', '')
        create_time = datetime.utcnow().strftime("%FT%TZ")
        lock_content = f"by user: {user}, locked timestamp: {create_time}"

        if self._lock_busy():
            message = self.bucket.Object(self.key).get()['Body'].read().decode('utf-8')
            raise S3ObjectLockedException(f"{self.name} locked {message}. Try again in a few minutes.")

        if self.verbose:
            print(f"Locking {self.name}")
        self.bucket.put_object(Key=self.key, Body=str.encode(lock_content))
        return self

    def __exit__(self, exit_type, exit_value, exit_traceback):
        """Release s3 object lock"""
        if self._lock_busy():
            if self.verbose:
                print(f"Unlocking {self.name}")
            self.bucket.objects.filter(Prefix=self.key).delete()

        if exit_type:
            if exit_type == S3ObjectLockedException:
                print(exit_value)
                return True
            else:
                return False
        return True
