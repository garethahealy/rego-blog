package main

default is_gatekeeper = false

# Checks whether the policy 'input' has came from Gatekeeper
is_gatekeeper {
  has_field(input, "review")
  has_field(input.review, "object")
}

# Check the obj contains a field
has_field(obj, field) {
  obj[field]
}

# Get the input, as the input is not Gatekeeper based
object = input {
  not is_gatekeeper
}

# Get the input.review.object, as the input is Gatekeeper based
object = input.review.object {
  is_gatekeeper
}

# Set the .metadata.name of the object we are currently working on
name = object.metadata.name

# Set the .kind of the object we are currently working on
kind = object.kind

# Is the kind a Deployment?
is_deployment {
  lower(kind) == "deployment"
}

# Get all containers from a pod
pod_containers(pod) = all_containers {
  keys = {"containers", "initContainers"}
  all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

# Get the pod spec, if the input is a Deployment
pods[pod] {
  is_deployment
  pod = object.spec.template
}

# Get all containers, from the input
containers[container] {
  pods[pod]
  all_containers = pod_containers(pod)
  container = all_containers[_]
}

# Get the format for messages on Gatekeeper
format(msg) = gatekeeper_format {
  is_gatekeeper
  gatekeeper_format = {"msg": msg}
}

# Get msg as ism, when not on Gatekeeper
format(msg) = msg {
  not is_gatekeeper
}

# @title Check a Deployment is not using the latest tag for their image
# @kinds apps/Deployment
violation[msg] {
  is_deployment

  container := containers[_]

  endswith(container.image, ":latest")

  msg := format(sprintf("%s/%s: container '%s' is using the latest tag for its image (%s), which is an anti-pattern.", [kind, name, container.name, container.image]))
}
