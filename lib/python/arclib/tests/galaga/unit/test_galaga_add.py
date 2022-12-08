
import boto3
import json
import pytest
import os

from moto import mock_s3

galaga_create = __import__("galaga-create")
galaga_add = __import__("galaga-add")
gsd_init = __import__("gsd-init")
gsd_upload = __import__("gsd-upload")


@mock_s3
def test_galaga_add(aws_credentials, monkeypatch, gsd_eks, gsd_nodegroup, gsd_alb, s3_gsd_eks, s3_gsd_nodegroup, s3_gsd_alb):
    dummy_galaga_file = '/tmp/kind_raw.json'
    if os.path.exists(dummy_galaga_file):
        os.remove(dummy_galaga_file)
    monkeypatch.setattr("sys.argv", ["pytest", "-a", 'kind_raw'])
    galaga_create.main()
    assert os.path.exists(dummy_galaga_file)

    monkeypatch.setenv('GSD_BUCKET', 'mybucket')
    monkeypatch.setenv('GALAGA_BUCKET', 'mybucket')

    with pytest.raises(SystemExit):
        galaga_add.main()

    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    monkeypatch.setattr("sys.argv", ["pytest"])
    gsd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_eks])
    gsd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_nodegroup])
    gsd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_alb])
    gsd_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-a", "kind_raw", "-f", s3_gsd_eks, '-o',
        'service_options/eks_version=1.20'])
 
    galaga_add.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-a", "kind_raw", "-f", s3_gsd_nodegroup])
    galaga_add.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-a", "kind_raw", "-f", s3_gsd_alb])
    galaga_add.main()
        
    with open(dummy_galaga_file) as f:
        data = json.load(f)
        assert len(data['components']) == 3
        assert data['components']['eks']['overrides']['service_options/eks_version'] == "1.20"

    os.remove(dummy_galaga_file)
