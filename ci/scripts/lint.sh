#!/bin/bash -eux

pushd dis-authentication-stub
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
  make lint
popd
