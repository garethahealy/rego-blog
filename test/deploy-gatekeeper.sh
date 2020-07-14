#!/usr/bin/env bash

command -v oc &> /dev/null || { echo >&2 'ERROR: oc not installed - Aborting'; exit 1; }
command -v konstraint &> /dev/null || { echo >&2 'ERROR: konstraint not installed - Aborting'; exit 1; }

gatekeeper_version="v3.1.0-beta.11"

deploy_gatekeeper() {
  echo ""
  echo "Deploying gatekeeper..."
  oc create -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${gatekeeper_version}/deploy/gatekeeper.yaml
  oc project gatekeeper-system

  echo ""
  echo "Patching gatekeeper to work on OCP..."
  oc adm policy add-scc-to-user anyuid system:serviceaccount:gatekeeper-system:gatekeeper-admin
  oc patch Deployment/gatekeeper-controller-manager --type json -p='[{"op": "remove", "path": "/spec/template/metadata/annotations"}]' -n gatekeeper-system
}

patch_namespaceselector_for_webhook() {
  echo ""
  echo "Patching ValidatingWebhookConfiguration/gatekeeper-validating-webhook-configuration to only watch namespaces with: 'redhat-cop.github.com/gatekeeper-active == true'..."
  oc patch ValidatingWebhookConfiguration/gatekeeper-validating-webhook-configuration -p='{"webhooks":[{"name":"validation.gatekeeper.sh","namespaceSelector":{"matchExpressions":[{"key":"redhat-cop.github.com/gatekeeper-active","operator":"In","values":["true"]}]}}]}'

  echo ""
  echo "Restarting Gatekeeper and waiting for it to be ready..."
  oc delete pods --all -n gatekeeper-system
  oc rollout status Deployment/gatekeeper-audit -n gatekeeper-system --watch=true
  oc rollout status Deployment/gatekeeper-controller-manager -n gatekeeper-system --watch=true
}

generate_constraints() {
  echo "Creating ConstraintTemplates via konstraint..."
  konstraint doc -o POLICIES.md
  konstraint create
}

deploy_constraints() {
  echo ""
  echo "Deploying Constraints..."

  # shellcheck disable=SC2038
  for file in $(find policy/* \( -name "template.yaml" -o -name "constraint.yaml" \) -type f | xargs); do
    name=$(oc create -f "${file}" -n gatekeeper-system -o name || exit $?)
    echo "${name}"

    until oc get ${name} -o json | jq ".status.byPod | length" | grep -q "4";
    do
      echo "Waiting for: .status.byPod | length == 4"
      sleep 5s
    done

    until [[ -z $(oc get ${name} -o json | jq "select(.status.byPod[].errors != null)") ]];
    do
      echo "Waiting for: .status.byPod[].errors == ''"
      sleep 5s
    done

    echo ""
  done
}

# Process arguments
case $1 in
  deploy_gatekeeper)
    deploy_gatekeeper
    patch_namespaceselector_for_webhook
    ;;
  deploy_constraints)
    generate_constraints
    deploy_constraints
    ;;
  *)
    echo "Not an option"
    exit 1
esac
