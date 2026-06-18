#!/bin/bash

SCRIPT_LOCATION=$(realpath "$0")                                    #
WORK_LOCATION=$(dirname "$SCRIPT_LOCATION")                         #
SCI_ADDRESS=$(scion address)                                        #
TRC_DIR="${WORK_LOCATION}/traceroute"                               #
TRC_FILE="${TRC_DIR}/${SCI_ADDRESS}"                                #
#####################################################################

[ ! -d "${TRC_DIR}" ] && mkdir "${TRC_DIR}"

# make host visible and wait for others to do the same
touch "${TRC_FILE}" && sleep 10

# connectivity tests (traceroute)
for f in "${TRC_DIR}/"*; do
        #other hosts
        ohost=$(basename "${f}")
        if [ "${ohost}" != "${SCI_ADDRESS}" ]; then
                echo "${SCI_ADDRESS} ----------> ${ohost}" >> "${TRC_FILE}"
                echo "scion traceroute --log.level debug ${ohost}" >> "${TRC_FILE}"
                # why pipe via tee? because 2&>1 results in wrong arg count errors from traceroute, although it works in interactive use...
                scion traceroute --log.level debug "${ohost}" |& tee -a "${TRC_FILE}"
                echo " " >> "${TRC_FILE}"
        fi
done
