#!/bin/bash
#
# Copyright 2022 Intel(R).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
function usage() {
    echo "$0 - utility to sign a given file.
    -in <file>        content to sign
    -out <file>       file path to save the signed enclve
    -keyout <file>    path where to write the public key used
    -h | -help        this help string"
    exit 1
}

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

in=
out=
keyout=
while [ $# -gt 0 ]; do
  opt=$1 ; shift
  case "$opt" in
    -in)  in=$1; shift ;;
    -out) out=$1; shift ;;
    -keyout) keyout=$1; shift ;;
    -h | -help) usage ;;
    *) echo "Unknown argument $opt"
  esac
done

if [ -z "$in" -o -z "$out" ]; then
    echo "Incomplete arguments"
    usage
fi

if [ ! -f ${SCRIPT_DIR}/privatekey.pem ]; then
  echo "ERROR: Missing privatekey.pem. You can generate one using 'make enclave-config/priatekey.pem'"
fi

openssl dgst -sha256 -sign ${SCRIPT_DIR}/privatekey.pem -out $out $in && \
if [ ! -z "$keyout" ] ; then openssl rsa -in ${SCRIPT_DIR}/privatekey.pem -pubout > $keyout ; fi
