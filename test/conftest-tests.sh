#!/usr/bin/env bats

load bats-support-clone
load test_helper/bats-support/load
load test_helper/redhatcop-bats-library/load

setup_file() {
  rm -rf /tmp/rhcop
}

@test "container-image-latest" {
  tmp=$(split_files "policy/container-image-latest/test_data/unit")

  cmd="conftest test ${tmp} --output tap"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [ "${lines[1]}" = "not ok 1 - ${tmp}/list.yml - main - Deployment/imageuseslatesttag: container 'bar' is using the latest tag for its image (quay.io/redhat-cop/openshift-applier:latest), which is an anti-pattern." ]
  [ "${lines[2]}" = "" ]
}

@test "container-image-latest - show the conftest command by failing" {
  tmp=$(split_files "policy/container-image-latest/test_data/unit")

  cmd="conftest test ${tmp} --output tap"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 0 ]
}
