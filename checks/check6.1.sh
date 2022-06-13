#!/bin/bash


printf "******* Ensure that image sprawl is avoided (Manual) *******\n"

images=$(docker images -q | sort -u | wc -l | awk '{print $1}')
active_images=0
for c in $(docker inspect --format "{{.Image}}" "$(docker ps -qa)" 2>/dev/null); do
    if docker images --no-trunc -a | grep "$c" > /dev/null ; then
      active_images=$(( active_images += 1 ))
    fi
done

printf "\033[1;34m * There are currently: $images images \033[0m\n"
  
if [ "$active_images" -lt "$((images / 2))" ]; then
    printf "\033[1;34m * Only $active_images out of $images are in use \033[0m\n"
fi

printf "\033[1;34m * $active_images active/$images in use \033[0m\n"