#!/bin/bash

# 

printf "******* 7.7 Ensure that the swarm manager auto-lock key is rotated periodically (Manual) *******\n"

if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
  printf "\033[0;34m (NOTE) \033[0m\n" 

else
  printf "\033[0;32m (Swarm mode not enabled) \033[0m\n"
  printf "\033[0;32m (PASS)  \033[0m\n"
fi