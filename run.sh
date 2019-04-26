#!/bin/bash

uwsgi -s /tmp/polychaeta.sock --manage-script-name --enable-threads --mount /polychaeta=polychaeta:app
sudo chmod o+w /tmp/polychaeta.sock
