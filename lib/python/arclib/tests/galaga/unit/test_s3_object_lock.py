import boto3

from moto import mock_s3

from modules.s3_object_lock import S3ObjectLock


@mock_s3
def test_lock(aws_credentials):
    bucket = 'mybucket'

    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket=bucket)

    with S3ObjectLock("mybucket", "test", "test.lock") as lock:
        assert lock
        objects = list(lock.bucket.objects.filter(Prefix=lock.key))
        assert len(objects) == 1

        with S3ObjectLock("mybucket", "test", "test.lock"):
            assert False

    objects = list(lock.bucket.objects.filter(Prefix=lock.key))
    assert len(objects) == 0
