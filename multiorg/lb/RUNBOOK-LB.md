# Runbook: per-role LoadBalancer Services (S16 input, repo-only)

`render.py` prints four `Service type: LoadBalancer` objects for one party, one per Arma role (assembler, consenter, router, batcher1).
It is an input to S16 (cross-cluster paths use the public LB endpoint of the target role). It only prints to stdout; it never applies
anything and never contacts a cluster. Ports come from `PORT_PLAN` in `multiorg/fca/enroll.py` (assembler 8011, consenter 8012,
router 8013, batcher1 8014). Names: `lb-<role>-<N>` in namespace `rd-fabricx-<party>` (N: bi 1, bank-a 2, bank-b 3, bank-c 4).

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

If each Service gets its own CLB instance: 4 per party, 16 in total (4 parties x 4 roles). One LB per party carrying four listeners
(the ports are distinct, so it is possible) would be 4 in total. Decision open, see below.

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
- `externalTrafficPolicy: Local` is left out. The ACK page says Local attaches only nodes hosting the pods (default Cluster attaches all nodes)
  and needs the `scheduler` annotation `wrr`; it does not say whether it is needed to keep the client source IP for the ACL. Question open.
- Per-role LBs (16 CLBs) versus one LB per party with four listeners (4 CLBs): not decided here.
