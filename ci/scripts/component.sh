#!/bin/bash -eux

pushd dis-authentication-stub
  make test-component
popd
