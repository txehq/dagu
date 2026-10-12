# Licensing

Dagu source code is distributed under the GNU General Public License version 3 or later (`GPL-3.0-or-later`). See [LICENSE](./LICENSE).

This document does not relicense any source file. Files that currently carry `SPDX-License-Identifier: GPL-3.0-or-later` remain GPL-licensed unless a separate written agreement says otherwise.

## Embedded Go API

The Go package `github.com/dagucloud/dagu/v2` exposes an experimental embedded API. Applications that import or link this package and distribute the resulting binary should evaluate GPL obligations for the combined work.

For proprietary products that need to distribute Dagu as part of a non-GPL application, contact `contact@dagu.sh` to discuss a separate commercial embedding license.

Commercial embedding rights are not granted by this repository, this document, or the public GPL license. They require a separate written agreement with the copyright holder or authorized licensor.

## Current Public License

Under the public GPL license, users may use, modify, and distribute Dagu under the GPL terms. The GPL permits commercial activity, including selling copies or services, but distribution must comply with GPL obligations.

Using the Dagu CLI or server as a separate program is different from importing the embedded Go API into another distributed binary. Projects embedding Dagu should review their distribution model and license obligations.

## Dependencies

Third-party libraries linked into Dagu binaries must be available under a license compatible with `GPL-3.0-or-later` that also permits the separate embedding license above: permissive licenses such as BSD, MIT, or Apache-2.0, or file-level copyleft licenses such as MPL-2.0, which some existing dependencies use. Strong copyleft dependencies (GPL, LGPL, AGPL) are not accepted. The spreadsheet engine `github.com/xuri/excelize/v2` (BSD-3-Clause) follows this rule.

## TXE Fork Feature Policy

This repository is a fork maintained by TXE. It adds an optional setting, `license.fork_policy`, that is off unless an operator configures it. With nothing configured, every feature gate behaves as it does upstream.

When configured, the policy can do two things on that server:

- Open the gates for the features it lists, from `sso`, `rbac` and `audit`, without a Dagu license being loaded.
- Set how many API keys may exist when no license is active, in place of the community limit (`max_api_keys`; `0` means no limit).

The code behind those gates is part of the GPL-licensed source in this repository. The policy is a modification of that source, made and distributed under the same `GPL-3.0-or-later` terms. The modified and added files keep their SPDX identifiers and the original copyright notices.

The policy is not a Dagu license, and a build that uses it is not an upstream-supported or commercially entitled build:

- It claims no plan and loads no license claims. License status keeps reporting the server as running without a license and names the policy as the source of the enabled features.
- It does not open anything else that an active Dagu license unlocks. Incident management stays unavailable without one.
- It does not change license discovery, activation, verification or heartbeat, and it makes no call to the Dagu license service.
- It grants no rights beyond the GPL, including none of the commercial embedding rights described above, and no support from the Dagu maintainers.
