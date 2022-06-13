#!/bin/bash


printf "******* 7.10 Ensure that management plane traffic is separated from data plane traffic (Manual) *******\n"

if docker info 2>/dev/null | grep -e "Swarm:\s*active\s*" >/dev/null 2>&1; then
  printf "\033[0;34m (INFO)  \033[0m\n"

else
  printf "\033[0;32m (Swarm mode not enabled) \033[0m\n"
  printf "\033[0;32m (PASS)  \033[0m\n"
fi