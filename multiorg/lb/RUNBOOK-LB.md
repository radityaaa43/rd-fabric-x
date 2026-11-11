# Runbook: per-party LoadBalancer Service (S16, render only)

`render.py` prints one `Service type: LoadBalancer` for one party carrying the four Arma listeners (assembler, consenter, router, batcher1);
`--per-role` prints four Services instead. It is the S16 manifest (cross-cluster paths use the public LB endpoint of the target role).
It only prints to stdout; it never applies anything and never contacts a cluster. Ports come from `PORT_PLAN` in `multiorg/fca/enroll.py`
(assembler 8011, consenter 8012, router 8013, batcher1 8014). Name: `lb-<N>` in namespace `rd-fabricx-<party>` (N: bi 1, bank-a 2, bank-b 3, bank-c 4).

## Commands

ACL-first: `--acl-id` and at least one `--source-range` are required. A range must be a single IPv4 host (`/32`); anything wider
(`0.0.0.0/0`, `/24`, ...) is refused with an empty stdout. Duplicate ranges are de-duplicated.

```
python3 multiorg/lb/render.py bi     --acl-id <acl-id> --source-range <cluster-2-egress>/32
python3 multiorg/lb/render.py bank-a --acl-id <acl-id> --source-range <cluster-2-egress>/32
python3 multiorg/lb/render.py bank-b --acl-id <acl-id> --source-range <cluster-2-egress>/32
python3 multiorg/lb/render.py bank-c --acl-id <acl-id> --source-range <cluster-1-egress>/32
```

Source range per side:
- bi, bank-a, bank-b live on cluster 1 and are called from cluster 2 (bank-c): use the cluster 2 egress address as `/32`.
- bank-c lives on cluster 2 and is called from cluster 1 (bi, bank-a, bank-b): use the cluster 1 egress address as `/32`.

The egress addresses are not in this repo; take them from the S16 PRE. Do not guess them.

## Order

1. The ACL object (whitelist with the peer egress `/32` entries) exists in the Alibaba Cloud CLB console/API. Note its `acl-id`.
2. Render with that id. Review the output.
3. Only then apply it inside a GO window with the party's own kubeconfig. The ACL is referenced from the Service annotations, so
   the listener is created with the whitelist and is never open. An empty whitelist would forward all requests, so the ACL must
   not be empty at apply time.

This render never applies anything.

## Cost

Decided: one CLB per party, 4 in total. With `--per-role` it would be 4 per party, 16 in total.

## Decided topology (lead): one LoadBalancer Service per party
`lb-<N>` in `rd-fabricx-<party>` carries all four listeners (8011 assembler, 8012 consenter, 8013 router, 8014 batcher1): one CLB and one ACL per party, 4 CLBs in total. A Service takes ONE ACL (docs: "does not support multiple policy groups"), so the one ACL covers the whole party. The per-role split (16 CLBs) stays available as `--per-role`.
`externalTrafficPolicy: Local` (the CLB mounts only the nodes where the pods run; keeps the client source IP) with the `scheduler: wrr` annotation, which the ACK page says Local mode requires.

## S11 pod contract (what the role pods must look like for this Service)
- Labels on the router, batcher1, consenter and assembler pods of a party: `app.kubernetes.io/part-of: rd-fabricx`, `party: <party>`, `rd-fabricx/arma: "true"` (the Service selector; not used by the CA pods, which carry `app.kubernetes.io/name: fca-org<N>`).
- Each pod declares a NAMED containerPort: `router` 8013, `batcher1` 8014, `consenter` 8012, `assembler` 8011. The Service uses the names as targetPort, so a port reaches only the pods that declare it (a numeric targetPort would send every port to every selected pod).
- [unverified] until S11 exists; the S11 render must be tested against this contract. Until then the CLB has no healthy backend (health abnormal is expected).

## Apply (under the standing GO; the values are lead's)
```
python3 multiorg/lb/render.py <party> --acl-id <acl> --source-range <cidr> | kubectl --kubeconfig <K> apply -f -
```
- bi, bank-a, bank-b (cluster 1, admin kubeconfig): `--acl-id acl-d9ji5nwbqutwulof33ydb --source-range 47.237.84.150/32` (the cluster-2 egress address).
- bank-c (cluster 2, `KUBECONFIG_C2`, only `rd-fabricx-bank-c` named): `--acl-id acl-gs5m5o9vb3olr19484tyg --source-range 8.215.62.92/32` (the cluster-1 egress address).
- Self-checks to quote per LB: Service annotations (acl-status/acl-id/acl-type), ingress IP from `kubectl get svc`, the CCM events from `kubectl describe svc` (AclStatus/AclType/AclId); no cloud CLI. ACL entries are not readable from the cluster and are not changed by this render.
- Rollback: `kubectl delete svc lb-<N> -n rd-fabricx-<party>` releases the CLB; the CLB IP changes on re-create, and the certs/genesis would carry the old IP (B3-SAN), so do not delete after B3-SAN.

## Annotations

Read in the Alibaba Cloud ACK documentation for ACK managed clusters, "How to configure Classic Load Balancer (CLB) for ACK clusters using annotations"
(https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/add-annotations-to-the-yaml-file-of-a-service-to-configure-clb-instances;
the ACK Serverless page of the same title was read first and has the same content). Its ACL example sets `acl-status: "on"`, `acl-id`
("does not support multiple policy groups": one ACL per Service) and `acl-type: "white"` on a `type: LoadBalancer` Service,
prefix `service.beta.kubernetes.io/alibaba-cloud-loadbalancer-`: `acl-status` (`on`/`off`), `acl-id` (required when status is `on`,
one group only), `acl-type` (`white`/`black`), `address-type` (`internet` default / `intranet`). ACL annotations need CCM
v1.9.3.164-g2105d2e-aliyun or later; `address-type` needs CCM v1.9.3 or later. The CCM version on the clusters was not checked.

## Open points

- [unverified] `spec.loadBalancerSourceRanges`: standard Kubernetes field, but the ACK managed page above does not mention it (searched). Whether the
  Alibaba CCM honours it next to the ACL annotations is not verified. The ACL is the control that was read in the docs.
- [unverified] Selector `app.kubernetes.io/name: <role>-<N>`: the S11 role pods do not exist yet; this is an assumption about their labels.
  Check against the S11 manifests before apply.
- [unverified] CCM version on cluster 1 and cluster 2 (see above).
- `externalTrafficPolicy: Local` + `scheduler: wrr` are set (lead). The ACK page says Local attaches only nodes hosting the pods and needs `wrr`; that it also keeps the client source IP for the ACL is Kubernetes semantics, not stated on that page [unverified].
- Per-role (16 CLBs) versus per-party (4 CLBs): DECIDED per-party; per-role kept as `--per-role`.
