[![License](https://img.shields.io/hexpm/l/plug.svg?maxAge=2592000)]()

# Using the Open Policy Agent (OPA) toolset to left-shift your company's best practices and policies
This blog post aims to explain the basics around OPA and how the Red Hat [Containers Community of Practice](https://github.com/redhat-cop) (CoP)
has started to implement policies using the toolset.

As part of the Red Hat [UK&I Professional Services](https://www.redhat.com/en/services/consulting) team, I work with customers
who are in the process of onboarding their applications onto [OpenShift Container Platform (OCP)](https://developers.redhat.com/products/openshift/overview/).
One question customers typically ask is:
_"How do I stop an application team deploying from latest? Or using requests and limits which are disruptive to the platform?"_

Previously, I would have suggested building a process around their CI/CD pipelines to validate the k8s resources and, based on company policy, 
allow or deny the release. Although this works for most situations, it has one major flaw.
It is not natively built into or on top of k8s, which allows teams to bypass policies if they are not mandated, or 
by manually changing the released resources via `oc` or the web console.
This type of implementation always has aspects of _"security through obscurity"_ which is doomed to fail.

So what do I think the answer could be? [OPA](https://www.openpolicyagent.org)[*[1]](#DISCLAIMER).

## What is OPA?
> https://github.com/open-policy-agent

Straight from the horse's mouth:

> The Open Policy Agent (OPA, pronounced "oh-pa") is an open-source, general-purpose policy engine that unifies policy enforcement across the stack. 
> OPA provides a high-level declarative language that lets you specify policy as code and simple APIs to offload policy decision-making from your software. 
> You can use OPA to enforce policies in microservices, Kubernetes, CI/CD pipelines, API gateways, and more.

In simple terms, it is a framework which allows you to build rules for your k8s resources to allow or deny. For example:
- Don't want to allow users to set CPU limits?
- Want to force all deployment resources to have certain labels?
- Want to force all deployments to have a matching `PodDisruptionBudget`?

All of these scenarios are easily implementable via OPA's policy language: `rego` (pronounced "ray-go").

## If OPA is a framework, how do I use it?
OPA gives you the policy engine but to build a full solution that works off-cluster and on-cluster, it is best combined with the following complimentary tooling:
- OPA conftest
- OPA Gatekeeper
- konstraint

### OPA conftest
[conftest](https://github.com/open-policy-agent/conftest) is a golang CLI which is part of the OPA project. 
It allows you to execute OPA policies against a YAML/JSON dataset. It is a great fit to be executed as part of your CI/CD pipeline to left-shift
your company's policies. Instead of waiting for your developers to deploy the resources and discover they are not compliant,
allow them to validate the resources as part of their current development sprint.

### OPA Gatekeeper
[Gatekeeper](https://github.com/open-policy-agent/gatekeeper) is a set of `Pods` which work via a [admission controller webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/),
this enables your policies to be natively part of your cluster within the `oc create` and `oc update` lifecycle.
Gatekeeper can audit cluster resources which were created before the policy, enabling them to be retrospectively fixed.

### konstraint
[konstraint](https://github.com/plexsystems/konstraint) is a golang CLI which is used to generate `ConstraintTemplate` and `Constraint`.
Constraints are the CRDs used by Gatekeeper to store your policies on-cluster.

## OK, let's take a look at a simple policy

```rego
1  package main
2
3  default is_gatekeeper = false
4
5  is_gatekeeper {
6    has_field(input, "review")
7    has_field(input.review, "object")
8  }
9
10  has_field(obj, field) {
11    obj[field]
12  }
13
14  object = input {
15    not is_gatekeeper
16  }
17
18  object = input.review.object {
19    is_gatekeeper
20  }
21
22  name = object.metadata.name
23
24  kind = object.kind
25
26  is_deployment {
27    lower(kind) == "deployment"
28  }
29
30  pod_containers(pod) = all_containers {
31    keys = {"containers", "initContainers"}
32    all_containers = [c | keys[k]; c = pod.spec[k][_]]
33  }
34
35  pods[pod] {
36    is_deployment
37    pod = object.spec.template
38  }
39
40  containers[container] {
41    pods[pod]
42    all_containers = pod_containers(pod)
43    container = all_containers[_]
44  }
45
46  format(msg) = gatekeeper_format {
47    is_gatekeeper
48    gatekeeper_format = {"msg": msg}
49  }
50
51  format(msg) = msg {
52    not is_gatekeeper
53  }
54
55  # @title Check workload kinds are not using the latest tag for their image
56  # @kinds apps/Deployment
57  violation[msg] {
58    is_deployment
59
60    container := containers[_]
61
62    endswith(container.image, ":latest")
63
64    msg := format(sprintf("%s/%s: container '%s' is using the latest tag for its image (%s), which is an anti-pattern.", [kind, name, container.name, container.image]))
65  }
```

The above might not look simple, but it is. The important thing to remember is that the policy is targeting both `Gatekeeper` and `conftest`
which is why it might look complicated. Firstly a quick overview:
- _line 1 to 53_: are helper methods pulled from [konstraint lib.](https://github.com/plexsystems/konstraint/tree/main/examples/lib)
- _line 57 to 65_: is the actual rego policy block.

Let's go line-by-line and explain what each bit is doing:
- _line 5_: `is_gatekeeper`: is a rule which checks whether the policy is being run on Gatekeeper, which allows our policies to target non-Gatekeeper environments, such as conftest.
- _line 14 and 18_: `object`: is a _"factored out"_ variable, which allows for an `OR`. In simple terms, if `is_gatekeeper` is true, `object = input.review.object` else `object = input`.
- _line 22 and 24_: `name/kind`: set two helper variables.
- _line 26_: `is_deployment`: is a rule to check if the kind we are working on, is a deployment.
- _line 30_: `pod_containers`: is a method which returns all `containers` which are part of a `pod`.
- _line 35_: `pods`: is a rule which returns the `pod` spec of the `object`.
- _line 40_: `containers`: is a rule which returns an array of `containers`, by getting the `pod` and then its `containers` via the previous helper methods.
- _line 46 and 51_: `format` are _"factored out"_ methods which allow for an `OR`, that return a message data structure depending on where the policy is being executed.
- _line 55_: is a `konstraint` comment, which is used via `konstraint doc` to auto-generate documentation.
- _line 56_: is a `konstraint` comment, which is used via `konstraint create` to auto-generate Gatekeeper `ConstraintTemplate` and `Constraint`.

Finally, we put that all together in our policy:
- _line 58_: if the input is a deployment.
- _line 60_: iterate over its containers.
- _line 62_: if any container image, ends with ":latest".
- _line 64_: return this error message.

## Cool, how do I run that?
To run the above policy, it is expected the following tools are installed:
- [conftest](https://www.conftest.dev/install)
- [konstraint](https://github.com/plexsystems/konstraint#installation)
- [jq](https://stedolan.github.io/jq/download)
- [yq](https://pypi.org/project/yq)
- [bats-core](https://github.com/bats-core/bats-core#installation)

You can execute the above policy by running the below. _NOTE_: A user with cluster-admin permissions is required to deploy Gatekeeper.

```bash
git clone https://github.com/garethahealy/rego-blog.git
cd rego-blog

echo "Let's have a look at the test data.."
cat policy/container-image-latest/test_data/unit/list.yml

echo "Now, let's run the conftest tests locally against that data.."
bats test/conftest-tests.sh

echo "Cool. Everything works as expected locally. But what about on-cluster?"
echo "Now, let's deploy gatekeeper (cluster-admin permissions required with a valid session)..."
test/deploy-gatekeeper.sh deploy_gatekeeper

echo "Now, let's deploy the gatekeeper contraints..."
test/deploy-gatekeeper.sh deploy_constraints

echo "Finally, let's check the policy is active for our namespace..."
bats test/gatekeeper-tests.sh
```

**TODO: so what did i just learn?**

If you are feeling lazy and love asci-cinema:

    _TODOs_

## OK, But how do I fit that into my CI/CD pipeline?
**TODO: this section feels a bit light, ideas?...**

The title of this blog mentions how to `left-shift` your company's policies. So let's do that:

Firstly, we need to build a Jenkins agent which can execute conftest in our `jenkins` project:
```bash
oc import-image quay.io/redhat-cop/jenkins-agent-python:v1.0 --confirm
oc create -f jenkins/ConftestBuildConfig.yaml
```

Now we can deploy out Jenkinsfile:
```jenkinsfile
podTemplate(label: 'conftest-agent', cloud: 'openshift', serviceAccount: 'jenkins', containers: [
        containerTemplate(name: 'jnlp', image: 'image-registry.openshift-image-registry.svc:5000/jenkins/jenkins-agent-conftest', privileged: false, alwaysPullImage: true, args: '${computer.jnlpmac} ${computer.name}', ttyEnabled: false)
]) {
    node ('conftest-agent') {
        stage('Run conftest') {
            sh "git clone https://github.com/garethahealy/rego-blog.git"
            dir("rego-blog") {
                sh "bats test/conftest-tests.sh"
            }
        }
    }
}
```

The idea here is that we would integrate the conftest stage as part of our application pipelines.

## What next?
Hopefully, you've seen the power of rego policies which are executed locally via conftest and on-cluster via Gatekeeper.

All the above work has been part of Red Hat Containers Community of Practice (CoP). The aim has been to:
- Understand the basics of writing rego policies. 
- Learn what is and is not possible.
- What the toolset is and how it can be used.
- Start to build out a set of policies OCP users can use "off-the-shelf".

We've made a good start on the last point but are always interested in what other OPA users are implementing.
If you are interested in contributing or seeing the policies we've implemented, check out:

> https://github.com/redhat-cop/rego-policies

## <a name="DISCLAIMER"></a>DISCLAIMER
[1] Open Policy Agent is not a Red Hat sponsored project nor is it supported under a Red Hat subscription and is strictly an upstream project.
