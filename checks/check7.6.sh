#!/bin/bash

# 
printf "******* 7.6 Ensure that swarm manager is run in auto-lock mode (Automated) *******\n"

if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    if ! docker swarm unlock-key 2>/dev/null | grep 'SWMKEY' 2>/dev/null 1>&2; then
      warn -s "$check"
      printf "\033[0;31m (Warn) \033[0m\n"
    else
      printf "\033[0;32m (PASS)  \033[0m\n"
    fi
else
  printf "\033[0;32m (Swarm mode not enabled) \033[0m\n"
  printf "\033[0;32m (PASS)  \033[0m\n"
fi