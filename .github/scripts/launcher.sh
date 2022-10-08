#!/usr/bin/env bash

# -e: exit when any command fails
# -x: all executed commands are printed to the terminal
# -o pipefail: prevents errors in a pipeline from being masked
set -exo pipefail

# GITHUB_WORKSPACE is set by actions/checkout@v3

export DOCKER_BUILD_DIR="/root/$PROJECT_NAME"

docker run \
           --memory-swap -1 \
           --env WORKSPACE_DIR=$DOCKER_BUILD_DIR \
           --env DOCKER_IMAGE=$DOCKER_IMAGE \
           --env-file .ci/docker.env \
           -v "$GITHUB_WORKSPACE:$DOCKER_BUILD_DIR" \
           `echo ${DOCKER_IMAGE} | sed 's/-/:/'` \
           /bin/bash -c "$DOCKER_BUILD_DIR/.ci/docker.sh"

exit 0
