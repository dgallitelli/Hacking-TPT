#!/bin/bash

echo "### BUILDING LOADER .... ###"
cd ./src/loader/
./build.sh
echo "### LOADER IS BUILT. ###"

echo "### BUILDING MIRAI WITH OPTIONS $1 $2"
cd ./src/mirai/
./build.sh $1 $2
cd ../..
echo "### MIRAI IS BUILT. ###"

echo "### LAUNCHING THE CONTAINERS ###"
docker-compose up --build
