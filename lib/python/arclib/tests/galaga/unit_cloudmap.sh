#!/bin/sh

echo "Current version of moto does not support cloudmap."
echo "Right now cloudmap testing is run on puny_jam.grv"

python3 -m pytest $PWD/cloudmap
