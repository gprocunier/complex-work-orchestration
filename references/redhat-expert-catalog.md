# Red Hat Expert Catalog

Use this catalog when a Bead needs a Red Hat product-focused Distinguished
Engineer lens. These profiles calibrate review output; they do not grant
implementation authority and they do not override share-boundary or opt-in
rules.

## Available Lenses

- `contract-jd-redhat-openshift-platform`: OpenShift Container Platform cluster
  lifecycle, operators, ingress, MachineConfig, upgrades, and day-2 operations.
- `contract-jd-redhat-openshift-app-dev`: OpenShift application build,
  deployment, configuration, developer workflow, pipelines, and runtime
  validation.
- `contract-jd-redhat-openshift-ai`: OpenShift AI workbenches, pipelines, model
  serving, KServe, vLLM, accelerators, and data/model boundaries.
- `contract-jd-redhat-rhoso`: Red Hat OpenStack Services on OpenShift
  control-plane, dataplane, service topology, networking, storage, and
  migration review.
- `contract-jd-redhat-rhacm`: Red Hat Advanced Cluster Management hub and
  managed cluster behavior, policy governance, placement, and cluster lifecycle.
- `contract-jd-redhat-rhacs`: Red Hat Advanced Cluster Security posture,
  admission control, runtime detection, vulnerability management, compliance,
  and Secured Cluster integration.
- `contract-jd-redhat-rhel`: Red Hat Enterprise Linux host and fleet behavior,
  systemd, SELinux, package lifecycle, Identity Management, and Satellite
  content management.

## Routing Notes

Prefer an explicit requested role when the product lens matters:

```bash
python3 scripts/route_work.py \
  --requested-role rhacs \
  "Review RHACS admission control and policy enforcement behavior."
```

Use separate expert-review Beads when a task spans products. For example, an
OpenShift AI model-serving issue with cluster ingress symptoms should usually
get both `openshift_ai` and `openshift_platform` lenses rather than one broad
generic review.

## RHEL Sub-Specialties

Red Hat Identity Management and Red Hat Satellite are represented inside the
single `rhel` expert:

- IdM terms include Identity Management, IdM, FreeIPA, Kerberos, DNS,
  certificates, and SSSD.
- Satellite terms include Satellite, Capsule, content views, lifecycle
  environments, activation keys, registration, and patch orchestration.

Use the same `contract-jd-redhat-rhel` job label for these reviews and state the
sub-specialty in the Bead purpose and expected output.
