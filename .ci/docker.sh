#!/usr/bin/env bash

# -e: exit when any command fails
# -x: all executed commands are printed to the terminal
# -o pipefail: prevents errors in a pipeline from being masked
set -exo pipefail
env

SCRIPT_NAME=${PLATFORM}_${DOCKER_IMAGE}
cd $WORKSPACE_DIR

# mark generic commands
cat README.md | sed '/^ *```all.*$/,/^ *```$/ s/^ *\$/_M_/' > ${SCRIPT_NAME}_parse
# mark platform dependent commands
sed -i '/^ *```.*'"${DOCKER_IMAGE}"'.*/,/^ *```$/ s/^ *\$/_M_/' ${SCRIPT_NAME}_parse
# comment all lines without the marker
sed -i '/^_M_/! s/^/# /' ${SCRIPT_NAME}_parse
# remove the appended comment from all marked lines
sed -i '/^_M_/ s/<--.*//' ${SCRIPT_NAME}_parse
# remove the marker and prepend the time command
sed -i 's/^_M_ /time /' ${SCRIPT_NAME}_parse
# remove time command if requested
sed -i '/^# *```.*'timeless'.*/,/^# *```$/ s/^time //' ${SCRIPT_NAME}_parse
# remove sudo, it is not necessary in docker
sed -i 's/sudo //g' ${SCRIPT_NAME}_parse

cp .ci/script.sh ./${SCRIPT_NAME}.sh
cat ${SCRIPT_NAME}_parse >> ${SCRIPT_NAME}.sh
echo -e '\nexit 0' >> ${SCRIPT_NAME}.sh

# set parameters for tzdata configuration use
TZ=Etc/UCT
ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

./${SCRIPT_NAME}.sh

exit 0