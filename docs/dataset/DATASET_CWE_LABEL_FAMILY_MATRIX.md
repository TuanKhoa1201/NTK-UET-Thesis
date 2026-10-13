# DATASET CWE x LABEL x FAMILY COVERAGE MATRIX
**Audit Target:** NTK-IRIS-STAGE3-AUGMENTED-V3-20261012

## 1. Coverage Overview Table
| CWE | Label Type | Total Rows | Unique Families | Dominant Families |
|---|---|:---:|:---:|---|
| CWE-022 | `none` | 150 | 51 | kotlin.collections (16), java.util (11), org.apache.commons (9) |
| CWE-022 | `sink` | 150 | 31 | java.io (37), java.nio (15), org.apache.commons (11) |
| CWE-022 | `source` | 150 | 50 | javax.servlet (16), org.apache.commons (11), org.springframework.web (10) |
| CWE-022 | `taint-propagator` | 150 | 48 | org.apache.struts2 (37), org.apache.commons (19), hudson.model (9) |
| CWE-078 | `none` | 100 | 38 | kotlin.collections (9), java.util (8), java.lang (8) |
| CWE-078 | `sink` | 38 | 7 | java.lang (24), org.apache.commons (6), hudson (4) |
| CWE-078 | `source` | 100 | 37 | javax.servlet (13), org.apache.commons (9), com.rabbitmq.client (8) |
| CWE-078 | `taint-propagator` | 100 | 40 | org.apache.struts2 (27), java.util (6), com.opensymphony.xwork2 (6) |
| CWE-079 | `none` | 60 | 27 | java.util (10), kotlin.collections (6), java.time (4) |
| CWE-079 | `sink` | 19 | 10 | hudson.util (4), javax.servlet (3), jakarta.faces.context (2) |
| CWE-079 | `source` | 60 | 32 | org.springframework.web (7), org.apache.commons (6), javax.servlet (6) |
| CWE-079 | `taint-propagator` | 60 | 29 | org.apache.struts2 (12), org.apache.commons (5), java.nio (3) |
| CWE-089 | `none` | 150 | 50 | java.util (17), kotlin.collections (14), hudson.model (13) |
| CWE-089 | `sink` | 104 | 37 | org.springframework.jdbc (32), java.sql (23), org.hibernate.query (6) |
| CWE-089 | `source` | 150 | 46 | javax.servlet (19), org.springframework.web (14), org.apache.commons (12) |
| CWE-089 | `taint-propagator` | 150 | 49 | org.apache.struts2 (44), org.apache.commons (10), hudson.model (10) |
| CWE-502 | `none` | 25 | 15 | org.apache.struts2 (5), java.time (5), hudson.cli (2) |
| CWE-502 | `sink` | 25 | 12 | org.ho.yaml (7), org.apache.commons (4), com.caucho.hessian (2) |
| CWE-502 | `source` | 25 | 18 | com.rabbitmq.client (3), javax.servlet (2), javax.jms (2) |
| CWE-502 | `taint-propagator` | 0 | 0 |  |
| CWE-611 | `none` | 15 | 9 | org.apache.commons (4), java.util (3), java.time (2) |
| CWE-611 | `sink` | 12 | 4 | javax.xml (7), org.jdom2.input (2), org.dom4j.io (2) |
| CWE-611 | `source` | 0 | 0 |  |
| CWE-611 | `taint-propagator` | 0 | 0 |  |

## 2. Analysis of Distribution Imbalance
- **CWE-022 and CWE-089 Dominance:** Path Traversal and SQL Injection represent 60.1% of the entire dataset (1154 / 1793 rows).
- **CWE-611 Representation Scarcity:** XXE contains only 27 samples across all splits, with merely 2 samples in the held-out test set, rendering statistical significance for XXE evaluation negligible.
- **Repository Family Clustering:** Heavily concentrated in `java.io`, `java.lang`, `java.util`, `javax.servlet`, and `org.apache.commons`.
