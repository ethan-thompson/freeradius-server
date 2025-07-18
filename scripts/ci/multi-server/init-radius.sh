#!/bin/bash

# Replace with the actual GID of /var/run/test.sock on the host
SOCK_GID=$(stat -c '%g' /var/run/test.sock)

# Create a group with that GID inside the container if it doesn't exist
# if ! getent group sockgroup > /dev/null; then
#   groupadd -g "$SOCK_GID" sockgroup
# fi

# # Add freerad to that group
# usermod -aG sockgroup freerad

# # Now run FreeRADIUS
# # exec radiusd -X
ls -la /var/run/test.sock
# groups freerad

chown freerad:freerad /var/run/test.sock

ls -la /var/run/test.sock

cat /docker-entrypoint.sh

tail -f /dev/null

# Fuck it
# chmod 777 /var/run/test.sock

# Install socat if not already installed
# if ! command -v socat &> /dev/null; then
#   echo "socat not found, installing..."
#   apt-get update && apt-get install -y socat
# else
#   echo "socat is already installed."
# fi

# # Check if /tmp/test.sock exists and is writable
# if [ ! -S /tmp/test.sock ]; then
#   echo "/tmp/test.sock does not exist or is not a socket."
#   exit 1
# fi

# Echo "test" to the socket
# if ! echo "test" | socat - UNIX-CONNECT:/tmp/test.sock; then
#   echo "Failed to send data to /tmp/test.sock."
#   exit 1
# else
#   echo "Successfully sent data to /tmp/test.sock."
# fi

# Call the original entrypoint script
# exec /docker-entrypoint.sh radiusd -X

# Call radiusd in debug mode
# radiusd -X
