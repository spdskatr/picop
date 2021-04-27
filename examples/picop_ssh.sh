#!/bin/bash

# Connect through ssh
ssh -t -i path/to/key.pem user@127.0.0.1 picop $*
