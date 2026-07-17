# cleanup-crew

Scan your AWS account for unused resources, review evidence-backed findings,
and clean them up safely — with a tag-and-wait grace period so nothing gets
deleted the moment it's flagged.

## Why

Idle EBS volumes, unassociated Elastic IPs, orphaned snapshots, and empty
load balancers quietly accumulate cost. `cleanup-crew` finds them, explains
*why* each one was flagged, and only ever deletes something after you've
explicitly approved it twice: once to mark it for deletion, and once more
(or a grace period elapsing) to actually remove it.

## How it works

```
scan   →  review          →  sweep
(read-  (tag resources you  (delete resources whose
 only)   approve as          grace period has elapsed,
         "pending-deletion") after re-verifying they're
                              still unused and a final
                              confirmation)
```

1. **`cleanup-crew scan`** — read-only. Walks your enabled AWS regions and
   runs every scanner. No AWS resource is ever modified by `scan`. Findings
   (resource id, why it was flagged, evidence, estimated monthly cost) are
   saved locally and printed as a table.
2. **`cleanup-crew review`** — interactively walk through findings and
   approve or decline each one. Approved resources are tagged in AWS
   (`cleanup:pending-deletion=<date>`) — this is reversible by removing the
   tag, and is the *only* mutation this step performs.
3. **`cleanup-crew sweep`** — re-checks every pending resource is *still*
   unused (in case it got attached/used again since being tagged) and that
   its grace period (7 days by default) has elapsed, prompts for a final
   confirmation, then deletes and logs the action.
4. **`cleanup-crew report`** — renders current findings/pending/history to a
   static HTML file you can open locally or publish to GitHub Pages.

Any resource tagged `cleanup:ignore=true` is skipped entirely, at scan time.

## v1 resource coverage

- Unattached EBS volumes
- Unassociated Elastic IPs
- Orphaned EBS snapshots (source volume no longer exists)
- Stopped EC2 instances (stopped longer than a configurable threshold)
- Idle/empty load balancers (ALB/NLB/CLB with no healthy/registered targets)
- Unused security groups (not attached to any network interface)

More resource types (RDS, Lambda, unused IAM credentials, NAT gateways, old
AMIs, CloudWatch log groups, S3) are planned but out of scope for v1.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.10+ and AWS credentials available via the normal boto3
resolution chain (`~/.aws/config`, `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, etc.).
See [`docs/iam-policy.json`](docs/iam-policy.json) for a least-privilege IAM
policy — you don't need full admin credentials to run this.

## Usage

```bash
cleanup-crew scan --profile my-profile           # read-only, safe to run anytime
cleanup-crew review                              # interactively approve/decline findings
cleanup-crew sweep                                # delete anything past its grace period
cleanup-crew report --out reports/latest.html     # generate a static HTML report
```

Configuration is via `AWSCLEANUP_*` environment variables, e.g.
`AWSCLEANUP_GRACE_PERIOD_DAYS=14`. See `src/awscleanup/config.py` for the
full list of settings.

## Safety model

- Dry-run by default everywhere — `scan` never mutates AWS.
- Tag-and-wait grace period before anything is deleted (default 7 days).
- Sweep re-verifies a resource is still unused immediately before deleting it.
- Every tag and delete action is appended to a local audit log
  (`~/.awscleanup/audit.log`).
- Least-privilege IAM policy provided — no admin credentials required.

## Development

```bash
pip install -e ".[dev]"
pytest                 # unit tests, AWS calls mocked via moto
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
