#!/bin/bash


printf "******* Ensure that container sprawl is avoided (Manual) *******\n"

total_containers=$(docker info 2>/dev/null | grep "Containers" | awk '{print $2}')
running_containers=$(docker ps -q | wc -l | awk '{print $1}')
diff="$((total_containers - running_containers))"
if [ "$diff" -gt 25 ]; then
    printf "\033[1;34m * There are currently a total of $total_containers containers, with only $running_containers of them currently running \033[0m\n"
else
    printf "\033[1;34m * There are currently a total of $total_containers containers, with $running_containers of them currently running \033[0m\n"
fi
printf "\033[1;34m * $total_containers total/$running_containers running \033[0m\n"