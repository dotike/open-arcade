
import json
import os

asteroid_create = __import__("asteroid-create")


def test_asteroid_create(monkeypatch, dummy_asteroid_file):
    if os.path.exists(dummy_asteroid_file):
        os.remove(dummy_asteroid_file)
    monkeypatch.setenv('TMP_DIR', '/tmp')
    monkeypatch.setattr("sys.argv", ["pytest", "-a", "dummyasteroid"])
    asteroid_create.main()
    assert os.path.exists(dummy_asteroid_file)

    os.remove(dummy_asteroid_file)

    monkeypatch.setattr("sys.argv", ["pytest", "-a", "dummyasteroid", "--version", "5"])
    asteroid_create.main()
    with open(dummy_asteroid_file) as f:
        data = json.load(f)
        assert data['version'] == 5

    os.remove(dummy_asteroid_file)

    monkeypatch.setattr("sys.argv", ["pytest", "-a", "dummyasteroid", "--version", "5", "-m", "key=value"])
    asteroid_create.main()
    with open(dummy_asteroid_file) as f:
        data = json.load(f)
        assert data['version'] == 5
        assert data['metadata']['key'] == 'value'

    os.remove(dummy_asteroid_file)
