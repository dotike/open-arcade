import os
import pytest

from AWSInstaller import AWSInstaller


@pytest.mark.asyncio
async def test_installer():
    file_installer = AWSInstaller('kind_raw.grv', 'file')
    if os.path.exists('/tmp/test.pid'):
        os.remove('/tmp/test.pid')
    
    status = await file_installer.status()
    assert 1 == status[0]
    status = await file_installer.install()
    assert 0 == status[0]
    status = await file_installer.install()
    assert 0 == status[0]
    status = await file_installer.status()
    assert 0 == status[0]
    status = await file_installer.uninstall()
    assert 0 == status[0]
    status = await file_installer.uninstall()
    assert 0 == status[0]
