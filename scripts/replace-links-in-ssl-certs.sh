#!/bin/bash

set -eo pipefail

for I in /etc/ssl/certs/*; do 
    [ -L "${I}" ] && readlink "${I}" | grep -q "/" && cp --remove-destination "$(readlink "${I}")" "${I}"
done

exit 0
