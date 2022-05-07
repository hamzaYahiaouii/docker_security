#!/bin/bash


printf "******* 7.2 Ensure that the minimum number of manager nodes have been created in a swarm (Automated) *******\n"

if docker info 2>/dev/null | grep -e "Swarm:*\sactive\s*" >/dev/null 2>&1; then
    managernodes=$(docker node ls | grep -c "Leader")
    if [ "$managernodes" -eq 1 ]; then
      printf "\033[0;32m (PASS)  \033[0m\n"
    
    else
      printf "\033[0;31m (WARN) \033[0m\n"
    fi
else
  printf "\033[0;32m (Swarm mode not enabled) \033[0m\n"
  printf "\033[0;32m (PASS)  \033[0m\n"
fi