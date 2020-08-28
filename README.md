[![License](https://img.shields.io/hexpm/l/plug.svg?maxAge=2592000)]()
![Generate README.html](https://github.com/garethahealy/rego-blog/workflows/Generate%20README.html/badge.svg)

# Automate your security practices and policies on OpenShift with Open Policy Agent (OPA)
This blog post aims to explain the basics around OPA and how the Red Hat [Containers Community of Practice](https://github.com/redhat-cop) (CoP)
has started to implement a collection of policies using the toolset.

As a member of the Red Hat [UK&I Consulting](https://www.redhat.com/en/services/consulting) team, I work with customers
who are in the process of onboarding their applications onto [OpenShift Container Platform (OCP)](https://developers.redhat.com/products/openshift/overview/).
One type of question customers typically ask is:
_"How do I stop an application team deploying images with the latest tag? or using requests and limits which are disruptive to the platform?"_

Previously, I would have suggested building a process around their CI/CD pipelines to validate the Kubernetes resources and, based on company policy, 
allow or deny the release. Although this works for most situations, it has one major flaw.
It is not natively built into or on top of Kubernetes, which allows teams to bypass policies if they are not mandated, or 
by manually changing the released resources via `oc` or the web console.
This type of implementation always has aspects of _"security through obscurity"_ which is doomed to fail.

So what do I think the answer could be? [OPA](https://www.openpolicyagent.org)[*[1]](#DISCLAIMER).

## What is OPA?
> https://github.com/open-policy-agent

From the [website](https://www.openpolicyagent.org/docs/latest/):

> The Open Policy Agent (OPA, pronounced "oh-pa") is an open-source, general-purpose policy engine that unifies policy enforcement across the stack. 
> OPA provides a high-level declarative language that lets you specify policy as code and simple APIs to offload policy decision-making from your software. 
> You can use OPA to enforce policies in microservices, Kubernetes, CI/CD pipelines, API gateways, and more.

In simple terms; it is a framework which allows you to build rules for your Kubernetes resources to allow or deny the resource to be applied to a cluster. 
For example imagine you need to:
- Prevent user from setting CPU limits?
- Force all deployment resources to have certain labels?
- Force all deployments to have a matching `PodDisruptionBudget`

All of these scenarios are easily implementable via OPA and its policy language; `rego` (pronounced "ray-go").

The following diagram provides an overview of the OPA architecture.

![OPA Overview](images/opa-service.svg)

## If OPA is a framework, how do I use it?
The first step to using OPA is writing a `HelloWorld` policy which outputs the `input` object.

```rego
1 package main
2
3 violation[msg] {
4   msg := sprintf("input == %s", [input])
5 }
```

Once we have a policy, we can look at the toolset to execute it. OPA gives you the policy engine but to build a full solution 
that works on and off-cluster, it's best to combine OPA with the following complementary tooling:
- OPA Conftest
- OPA Gatekeeper
- konstraint

### OPA Conftest
[Conftest](https://github.com/open-policy-agent/conftest) is a golang-based CLI which is part of the OPA project. 
It allows you to execute OPA policies against a YAML/JSON dataset. It is a great addition to a CI/CD pipeline to [left-shift](https://www.redhat.com/en/topics/security) compliance testing against
your companies policies. Instead of waiting for developers to deploy the resources and discover they are not compliant,
Conftest allow them to validate the resources as part of their Software Development Life Cycle (SDLC).

### OPA Gatekeeper
[Gatekeeper](https://github.com/open-policy-agent/gatekeeper) is a set of `Pods` which work via a Kubernetes [admission controller webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/),
this enables your policies to be natively part of your cluster within the `oc create` and `oc update` lifecycle.
Gatekeeper can audit cluster resources which were created before the policy, enabling them to be retrospectively fixed.

### konstraint
[konstraint](https://github.com/plexsystems/konstraint) is a golang-based CLI which is used to generate `ConstraintTemplate` and `Constraint`.
Constraints are the CRDs used by Gatekeeper to store your policies on-cluster.

## OK, let's take a look at a simple policy

```rego
1  package main
2
3  default is_gatekeeper = false
4
5  # Checks whether the policy 'input' has came from Gatekeeper
6  is_gatekeeper {
7    has_field(input, "review")
8    has_field(input.review, "object")
9  }
10
11  # Check the obj contains a field
12  has_field(obj, field) {
13    obj[field]
14  }
15
16  # Get the input, as the input is not Gatekeeper based
17  object = input {
18    not is_gatekeeper
19  }
20
21  # Get the input.review.object, as the input is Gatekeeper based
22  object = input.review.object {
23    is_gatekeeper
24  }
25
26  # Set the .metadata.name of the object we are currently working on
27  name = object.metadata.name
28
29  # Set the .kind of the object we are currently working on
30  kind = object.kind
31
32  # Is the kind a Deployment?
33  is_deployment {
34    lower(kind) == "deployment"
35  }
36
37  # Get all containers from a pod
38  pod_containers(pod) = all_containers {
39    keys = {"containers", "initContainers"}
40    all_containers = [c | keys[k]; c = pod.spec[k][_]]
41  }
42
43  # Get the pod spec, if the input is a Deployment
44  pods[pod] {
45    is_deployment
46    pod = object.spec.template
47  }
48
49  # Get all containers, from the input
50  containers[container] {
51    pods[pod]
52    all_containers = pod_containers(pod)
53    container = all_containers[_]
54  }
55
56  # Get the format for messages on Gatekeeper
57  format(msg) = gatekeeper_format {
58    is_gatekeeper
59    gatekeeper_format = {"msg": msg}
60  }
61
62  # Get msg as ism, when not on Gatekeeper
63  format(msg) = msg {
64    not is_gatekeeper
65  }
66
67  # @title Check a Deployment is not using the latest tag for their image
68  # @kinds apps/Deployment
69  violation[msg] {
70    is_deployment
71
72    container := containers[_]
73
74    endswith(container.image, ":latest")
75
76    msg := format(sprintf("%s/%s: container '%s' is using the latest tag for its image (%s), which is an anti-pattern.", [kind, name, container.name, container.image]))
77  }
```

The above might not look simple, but it is. The important thing to remember is that the policy is targeting both `conftest` and `Gatekeeper`
which is why it might look complicated. 

Firstly a quick overview:
- _line 1 to 65_: are helper methods pulled from [konstraint lib.](https://github.com/plexsystems/konstraint/tree/main/examples/lib)
- _line 69 to 77_: is the actual rego policy block.

Let's go line-by-line and explain what each bit is doing:
- _line 6_: `is_gatekeeper`: is a rule which checks whether the policy is being run on Gatekeeper, which allows our policies to target non-Gatekeeper environments, such as conftest.
- _line 17 and 22_: `object`: is a _"factored out"_ variable, which allows for an `OR`. In simple terms, if `is_gatekeeper` is true, `object = input.review.object` else `object = input`.
- _line 27 and 30: `name/kind`: set two helper variables.
- _line 33_: `is_deployment`: is a rule to check if the kind we are working on, is a deployment.
- _line 38_: `pod_containers`: is a method which returns all `containers` which are part of a `pod`.
- _line 44_: `pods`: is a rule which returns the `pod` spec of the `object`.
- _line 50_: `containers`: is a rule which returns an array of `containers`, by getting the `pod` and then its `containers` via the previous helper methods.
- _line 57 and 63_: `format` are _"factored out"_ methods which allow for an `OR`, that return a message data structure depending on where the policy is being executed.
- _line 67_: is a `konstraint` comment, which is used via `konstraint doc` to auto-generate documentation.
- _line 68_: is a `konstraint` comment, which is used via `konstraint create` to auto-generate Gatekeeper `ConstraintTemplate` and `Constraint`.

Finally, we put that all together in our policy:
- _line 70_: if the input is a deployment.
- _line 72_: iterate over its containers.
- _line 74_: if any container image, ends with ":latest".
- _line 76_: return this error message.

## Cool, how do I run that?
To run the above policy, it is expected the following tools are installed:
- [conftest](https://www.conftest.dev/install)
- [konstraint](https://github.com/plexsystems/konstraint#installation)
- [bats-core](https://github.com/bats-core/bats-core#installation); is as a testing framework which will execute conftest.
- [jq](https://stedolan.github.io/jq/download); is used by the BATS framework to process JSON files.
- [yq](https://pypi.org/project/yq); is used by the BATS framework to process YAML files.

You can execute the above policy by running the below commands. 
_NOTE_: A user with cluster-admin permissions is required to deploy Gatekeeper.

```bash
git clone https://github.com/garethahealy/rego-blog.git
cd rego-blog

echo "Let's have a look at the test data..."
cat policy/container-image-latest/test_data/unit/list.yml

echo "Let's have a look at the BATS tests..."
cat test/conftest-tests.sh

echo "Now, let's run the conftest tests locally against that data.."
bats test/conftest-tests.sh

echo "Cool. Everything works as expected locally. But what about on-cluster?"

echo "Now, let's deploy gatekeeper (cluster-admin permissions required with a valid session)..."
test/deploy-gatekeeper.sh deploy_gatekeeper

echo "Now, let's deploy the gatekeeper contraints..."
test/deploy-gatekeeper.sh deploy_constraints

echo "Let's look at the auto-generated ConstraintTemplate. Notice its the same policy, but in the CR..."
cat policy/container-image-latest/template.yaml

echo "Let's look at the auto-generated Constraint..."
cat policy/container-image-latest/constraint.yaml

echo "Finally, let's check the policy is active for our namespace..."
bats test/gatekeeper-tests.sh
```

So what did the above do?
- You executed `test/conftest-tests.sh`; which used `BATS` to run `conftest` which validated the policy worked as expected locally.
- You executed `test/deploy-gatekeeper.sh deploy_gatekeeper`; which deployed OPA Gatekeeper onto your cluster in the `gatekeeper-system` namespace, monitoring projects labeled `redhat-cop.github.com/gatekeeper-active: 'true'`.
- You executed `test/deploy-gatekeeper.sh deploy_constraints`; which used `konstraint` to auto-generate the Gatekeeper CRs which were applied to your cluster.
- You executed `test/gatekeeper-tests.sh`; which used `BATS` to run `oc create` which validated the policy worked as expected on-cluster.

If you are unable to install the software required, you can use the OPA Playground below which is setup with the policy and data:
- [https://play.openpolicyagent.org/p/Gu4vP4hJA0](https://play.openpolicyagent.org/p/Gu4vP4hJA0)

## OK, But how do I fit that into my CI/CD pipeline?
I've previously mentioned `left-shifting` your companies policies but what does this mean in practical terms for OPA?
The following example presumes you are using a Jenkins deployed onto your cluster via:

```bash
oc new-project jenkins
oc process jenkins-persistent -p DISABLE_ADMINISTRATIVE_MONITORS=true -p MEMORY_LIMIT=2Gi -n openshift | oc create -f -
oc rollout status dc/jenkins --watch=true
```

If you are using another CI/CD tool, the key point is that we want to execute `bats test/conftest-tests.sh` before deploying to the cluster.
To be able to execute that bash script, you will need to replicate the same functionality from this [Dockerfile](https://github.com/redhat-cop/containers-quickstarts/blob/master/jenkins-agents/jenkins-agent-conftest/Dockerfile).

Firstly, we need to build a Jenkins agent which can execute `BATS` and `conftest` in our Jenkins project. 

```bash
oc import-image quay.io/redhat-cop/jenkins-agent-python:v1.0 --confirm
oc create -f jenkins/ConftestBuildConfig.yaml
oc start-build conftest-docker-build -w
```

Once the build is complete, lets open Jenkins and create a new pipeline job from our Jenkinsfile:

```groovy
node ("jenkins-agent-conftest") {
    stage("Clone blog") {
        sh "git clone https://github.com/garethahealy/rego-blog.git"
    }
    
    stage("Run conftest") {
        dir("rego-blog") {
            sh "bats test/conftest-tests.sh"
        }
    }
}
```

Now lets trigger the Jenkins job and check it outputs the same as our local test.

## What next?
Hopefully, you've seen the power of rego policies which are executed locally via `conftest` and on-cluster via `Gatekeeper`.

All the above work has been part of Red Hat Containers Community of Practice (CoP). The aim has been to:
- Understand the basics of writing rego policies. 
- Learn what is and is not possible.
- What the toolset is and how it can be used.
- Start to build a set of policies OCP users can use "off-the-shelf".

We've made a good start on the last point but are always interested in what other OPA users are implementing.
If you are interested in contributing or seeing the policies we've implemented, check out:

> https://github.com/redhat-cop/rego-policies

Want to start writing policies? Below are some useful links to get you started:
- [Policy language overview](https://www.openpolicyagent.org/docs/latest/policy-language)
- [Policy reference](https://www.openpolicyagent.org/docs/latest/policy-reference)
- [Playground enviroment](https://play.openpolicyagent.org)
- [Got a question? Head over to their slack](https://slack.openpolicyagent.org)

## Thanks to...
For reviewing and giving great feedback:
- [wmcdonald404](https://github.com/wmcdonald404)
- [noelo](https://github.com/noelo)
- [monodot](https://github.com/monodot)

## <a name="DISCLAIMER"></a>DISCLAIMER
[1] Open Policy Agent is an open source project. It is not a Red Hat sponsored nor is it supported under a Red Hat subscription.
