#!/usr/bin/env bash
# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Logging helpers used by network.sh and the channel/chaincode scripts.

C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_BLUE='\033[0;34m'
C_YELLOW='\033[1;33m'

println() { echo -e "$1"; }
errorln() { println "${C_RED}${1}${C_RESET}"; }
successln() { println "${C_GREEN}${1}${C_RESET}"; }
infoln() { println "${C_BLUE}${1}${C_RESET}"; }
warnln() { println "${C_YELLOW}${1}${C_RESET}"; }

fatalln() {
  errorln "$1"
  exit 1
}

export -f errorln successln infoln warnln println

# verifyResult <exit_code> <message>
verifyResult() {
  if [ "$1" -ne 0 ]; then
    fatalln "$2"
  fi
}
