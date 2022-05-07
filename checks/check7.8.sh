#!/bin/bash

printf "******* 7.8 Ensure that node certificates are rotated as appropriate (Manual) *******\n"

if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
    if docker info 2>/dev/null | grep "Expiry Duration: 2 days"; then
      printf "\033[0;32m (PASS)  \033[0m\n"
    else
      printf "\033[0;34m (INFO)  \033[0m\n"
    fi
else
  printf "\033[0;32m (Swarm mode not enabled) \033[0m\n"
  printf "\033[0;32m (PASS)  \033[0m\n"
fi