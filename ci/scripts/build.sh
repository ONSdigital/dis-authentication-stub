#!/bin/bash -eux

pushd dis-authentication-stub
  make build
  cp build/dis-authentication-stub Dockerfile.concourse ../build
popd
