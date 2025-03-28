
# Cert-Manager Linode Solver

Archived, current repo is https://github.com/ice-bergtech/cert-manager-webhook-linode

This adapter allows you to use the popular [Cert-Manager](https://cert-manager.io/) with [Linode DNS Manager](https://www.linode.com/docs/guides/dns-manager/) as ACME DNS01 Challange Provider.

One use-case is to use wildcard certificates with [Let's Encrypt](https://letsencrypt.org/).

It leverages the official [Linode Go Client](https://github.com/linode/linodego)


## Installation

### Linode Webhook Solver

```bash
helm install cert-manager-linode chart/ -n cert-manager
```

### Configure Cert-Manager Cluster Issuer

https://cert-manager.io/docs/configuration/acme/dns01/webhook/

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: your-email-address
    privateKeySecretRef:
      name: letsencrypt-prod
    server: https://acme-v02.api.letsencrypt.org/directory
    solvers:
      - dns01:
          webhook:
            groupName: acme.cluster.local
            solverName: linode
            config:
              apiKey: your-api-key
```

Pass API Key with a Secret:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: your-email-address
    privateKeySecretRef:
      name: letsencrypt-prod
    server: https://acme-v02.api.letsencrypt.org/directory
    solvers:
      - dns01:
          webhook:
            groupName: acme.cluster.local
            solverName: linode
            config:
              apiKeySecretRef:
                name: linode-token
                key: data
---
apiVersion: v1
kind: Secret
metadata:
  name: 'linode-token'
  namespace: cert-manager
stringData:
  data: 'your-api-key'
---
```

## Troubleshooting

# Visibility

Errors from the service will appear as events in cert-manager `challenge` resources.

```
Warning  PresentError  10m (x8 over 20m)  cert-manager-challenges  Error presenting challenge: kube secret error: issue fetching secret: resource name may not be empty
```

### Service account
```
linode.acme.cluster.local is forbidden: User "system:serviceaccount:cert-manager:cert-manager-chart" cannot create resource "linode" in API group "acme.cluster.local" at the cluster scope
```

Make sure the service account is references properly.
In the chart, set the var `certManager.serviceAccountName` to the service account created by cert manager.
