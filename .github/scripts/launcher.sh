#!/usr/bin/env bash

# -e: exit when any command fails
# -x: all executed commands are printed to the terminal
# -o pipefail: prevents errors in a pipeline from being masked
set -exo pipefail

# GITHUB_WORKSPACE is set by actions/checkout@v3

export DOCKER_WORKSPACE_DIR="/root/$PROJECT_NAME"
export WORKSPACE_DIR=~/${PLATFORM}_${DOCKER_IMAGE}

# Do not share the same workspace
cp -rf $GITHUB_WORKSPACE $WORKSPACE_DIR

docker run \
           --memory-swap -1 \
           --platform `echo $PLATFORM | sed 's/-/\//'` \
           --env WORKSPACE_DIR=$DOCKER_WORKSPACE_DIR \
           --env DOCKER_IMAGE=$DOCKER_IMAGE \
           --env PLATFORM=$PLATFORM \
           --env-file .ci/docker.env \
           -v "${WORKSPACE_DIR}:${DOCKER_WORKSPACE_DIR}" \
           `echo $DOCKER_IMAGE | sed 's/-/:/'` \
           /bin/bash -c "${DOCKER_WORKSPACE_DIR}/.ci/docker.sh"

exit 0
