#!/usr/bin/env bash

# -e: exit when any command fails
# -x: all executed commands are printed to the terminal
# -o pipefail: prevents errors in a pipeline from being masked
set -exo pipefail
env

cd $WORKSPACE_DIR

# mark generic commands
cat README.md | sed '/^ *```all.*$/,/^ *```$/ s/^ *\$/_M_/' > ${DOCKER_IMAGE}_parse
# mark platform dependent commands
sed -i '/^ *```.*'"${DOCKER_IMAGE}"'.*/,/^ *```$/ s/^ *\$/_M_/' ${DOCKER_IMAGE}_parse
# comment all lines without the marker
sed -i '/^_M_/! s/^/# /' ${DOCKER_IMAGE}_parse
# remove the appended comment from all marked lines
sed -i '/^_M_/ s/<--.*//' ${DOCKER_IMAGE}_parse
# remove the marker and prepend the time command
sed -i 's/^_M_ /time /' ${DOCKER_IMAGE}_parse
# remove time command if requested
sed -i '/^# *```.*'timeless'.*/,/^# *```$/ s/^time //' ${DOCKER_IMAGE}_parse
# remove sudo, it is not necessary in docker
sed -i 's/sudo //g' ${DOCKER_IMAGE}_parse

cp .ci/script.sh ./${DOCKER_IMAGE}.sh
cat ${DOCKER_IMAGE}_parse >> ${DOCKER_IMAGE}.sh
echo -e '\nexit 0' >> ${DOCKER_IMAGE}.sh

# set parameters for tzdata configuration use
TZ=Etc/UCT
ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

./${DOCKER_IMAGE}.sh

exit 0