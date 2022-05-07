#!/bin/bash

printf "******* 7.1 Ensure swarm mode is not Enabled, if not needed (Automated) *******\n"

if docker info 2>/dev/null | grep -e "Swarm:*\sinactive\s*" >/dev/null 2>&1; then
    printf "\033[0;32m (PASS)  \033[0m\n"
else
printf "\033[0;31m (WARN) \033[0m\n"
fi