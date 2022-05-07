#!/bin/bash

printf "******* 7.4 Ensure that all Docker swarm overlay networks are encrypted (Automated) *******\n"


fail=0
unencrypted_networks=""
for encnet in $(docker network ls --filter driver=overlay --quiet); do
    if docker network inspect --format '{{.Name}} {{ .Options }}' "$encnet" | \
      grep -v 'encrypted:' 2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        fail=1
      fi
      printf "\033[0;31m (WARN: Unencrypted overlay network: $(docker network inspect --format '{{ .Name }} ({{ .Scope }})' "$encnet")) \033[0m\n"
      unencrypted_networks="$unencrypted_networks $(docker network inspect --format '{{ .Name }} ({{ .Scope }})' "$encnet")"
    fi
done
# We went through all the networks and found none that are unencrypted
if [ $fail -eq 0 ]; then
    printf "\033[0;32m (PASS) \033[0m\n"
else
printf "\033[0;31m (WARN: Unencrypted overlay networks: $unencrypted_networks) \033[0m\n "
fi