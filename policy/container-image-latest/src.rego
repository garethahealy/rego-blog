package main

default is_gatekeeper = false

is_gatekeeper {
  has_field(input, "review")
  has_field(input.review, "object")
}

has_field(obj, field) {
  obj[field]
}

object = input {
  not is_gatekeeper
}

object = input.review.object {
  is_gatekeeper
}

name = object.metadata.name

kind = object.kind

is_deployment {
  lower(kind) == "deployment"
}

pod_containers(pod) = all_containers {
  keys = {"containers", "initContainers"}
  all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

pods[pod] {
  is_deployment
  pod = object.spec.template
}

containers[container] {
  pods[pod]
  all_containers = pod_containers(pod)
  container = all_containers[_]
}

format(msg) = gatekeeper_format {
  is_gatekeeper
  gatekeeper_format = {"msg": msg}
}

format(msg) = msg {
  not is_gatekeeper
}

# @title Check workload kinds are not using the latest tag for their image
# @kinds apps/Deployment
violation[msg] {
  is_deployment

  container := containers[_]

  endswith(container.image, ":latest")

  msg := format(sprintf("%s/%s: container '%s' is using the latest tag for its image (%s), which is an anti-pattern.", [kind, name, container.name, container.image]))
}
