#!/bin/sh

echo "Current version of moto does not support msk."
echo "Right now msk testing is run on test-dampred-grv"
echo "The testing could run about 25 minutes."

python3 -m pytest $PWD/eks
