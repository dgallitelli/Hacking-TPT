#!/bin/bash

cd ./src/mirai/
./build.sh debug telnet
cd ../..
docker-compose up --build
