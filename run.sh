#!/bin/bash

uwsgi -s /tmp/frrbot.sock --manage-script-name --enable-threads --mount /frrbot=frrbot:app
sudo chmod o+w /tmp/frrbot.sock
