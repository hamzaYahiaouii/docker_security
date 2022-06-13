#!/bin/bash

printf "******* 7.3 Ensure that swarm services are bound to a specific host interface (Automated) *******\n"

if docker info 2>/dev/null | grep -e "Swarm:*\sactive\s*" >/dev/null 2>&1; then
    $netbin -lnt | grep -e '\[::]:2377 ' -e ':::2377' -e '*:2377 ' -e ' 0\.0\.0\.0:2377 ' >/dev/null 2>&1
    if [ $? -eq 1 ]; then
      printf "\033[0;32m (PASS)  \033[0m\n"
      
    else
    printf "\033[0;31m (WARN) \033[0m\n"
    fi
else
  printf "\033[0;32m (Swarm mode not enabled) \033[0m\n"
  printf "\033[0;32m (PASS)  \033[0m\n"
fi