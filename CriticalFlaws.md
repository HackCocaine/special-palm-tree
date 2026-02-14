❌ Critical Logical Inconsistencies

Now the important part.

❌ 1. Top-Level Risk vs Computed Score Contradiction

Top-level:

"riskScore": 85
"riskLevel": "critical"


Assessment layer:

"computedScore": 11
"trendDirection": "decreasing"
"delta": -39


This is a fatal credibility flaw.

Your dashboard says:

Critical risk increasing

Your scoring engine says:

Low risk decreasing severely

These cannot coexist.

You must choose:

Either dashboard derives from assessmentLayer.scoring.computedScore

Or dashboard is removed entirely

Right now it breaks trust.

❌ 2. Classification Contradiction

Correlation:

score: 0.14
strength: weak
cveOverlap: 0
serviceMatch: 0


Classification:

type: "targeted"
confidence: 75


Rationale says:

"Specific CVE targeting"
"Strong cross-source correlation"

But your correlation object literally says the opposite.

This is analytical hallucination.

Given:

No infra exposure

No CVE overlap

Weak correlation

Stale social data

The only defensible classification would be:

type: "opportunistic"
confidence: low-to-moderate


Right now your classification layer is ignoring your numeric model.

❌ 3. Freshness = 0 but Not Reflected in Risk Severity
socialAgeHours: 68.5
freshnessScore: 0
status: stale


Yet:

riskLevel: critical


If freshnessScore is part of the weighted model (0.1 weight), it must influence final severity classification.

Right now your severity ignores freshness.

❌ 4. Signal Contamination

You are ingesting irrelevant posts:

Apartment fire

Elephant birth

APR staking campaign

Quiz about zero-days

Your structured layer did not filter noise.

This inflates:

socialIntensity

totalPosts

themes

You need a relevance filter before extraction.

❌ 5. Metrics Block is Artificial
totalSignals: 3
criticalCount: 2
highCount: 1


There is no logic shown that generates these counts.

They appear decorative.

If they are not derived from scoring logic, remove them.