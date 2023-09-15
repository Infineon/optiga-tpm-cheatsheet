#!/usr/bin/env bash

# -e: exit when any command fails
# -x: all executed commands are printed to the terminal
# -o pipefail: prevents errors in a pipeline from being masked
set -exo pipefail

SCRIPT_NAME=${PLATFORM}_${DOCKER_IMAGE}

cd $WORKSPACE_DIR

# Mark generic commands
cat README.md | sed '/^ *```all.*$/,/^ *```$/ s/^ *\$/_M_/' > ${SCRIPT_NAME}_parse
# Mark distro dependent commands
sed -i '/^ *```.*'"${DOCKER_IMAGE}"'.*/,/^ *```$/ s/^ *\$/_M_/' ${SCRIPT_NAME}_parse
# Comment all lines without the marker
sed -i '/^_M_/! s/^/# /' ${SCRIPT_NAME}_parse
# Remove the appended comment from all marked lines
sed -i '/^_M_/ s/<--.*//' ${SCRIPT_NAME}_parse
# Remove the marker and prepend the time command
sed -i 's/^_M_ /time /' ${SCRIPT_NAME}_parse
# Remove time command if requested
sed -i '/^# *```.*'timeless'.*/,/^# *```$/ s/^time //' ${SCRIPT_NAME}_parse
# Remove sudo, it is not necessary in docker
sed -i 's/sudo //g' ${SCRIPT_NAME}_parse

# Initialize an executable script
cat > ${SCRIPT_NAME}.sh << EOF
#!/usr/bin/env bash
set -exo pipefail

EOF

cat ${SCRIPT_NAME}_parse >> ${SCRIPT_NAME}.sh
echo -e '\nexit 0' >> ${SCRIPT_NAME}.sh

# set parameters for tzdata configuration use
TZ=Etc/UCT
ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

chmod a+x ${SCRIPT_NAME}.sh
./${SCRIPT_NAME}.sh

exit 0
