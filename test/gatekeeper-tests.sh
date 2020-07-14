#!/usr/bin/env bats

load bats-support-clone
load test_helper/bats-support/load
load test_helper/redhatcop-bats-library/load

setup_file() {
  export project_name="regopolicies-undertest-$(date +'%d%m%Y-%H%M%S')"

  rm -rf /tmp/rhcop
  oc process -f test/namespace-under-test.yml -p=PROJECT_NAME=${project_name} | oc create -f -
}

teardown_file() {
  oc delete project/${project_name}
}

@test "container-image-latest" {
  tmp=$(split_files "policy/container-image-latest/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == "Error from server ([denied by containerimagelatest] Deployment/imageuseslatesttag"* ]]
  [[ "${lines[1]}" = "" ]]
}

@test "container-image-latest - show the oc command by failing" {
  tmp=$(split_files "policy/container-image-latest/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 0 ]
}
