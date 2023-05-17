#!/bin/bash
rm ./multilang/resources/sysaudit/alg/src/*.c
rm ./multilang/resources/sysaudit/lib/src/*.c
rm ./multilang/resources/sysaudit/alg/*.so
rm ./multilang/resources/sysaudit/lib/*.so
python3 setup.py build

