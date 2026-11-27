# capacitygate test data (TXE-8043)

**Every file here is derived data, sanitized for a public repository** (root's TXE-8043 D4 ruling). The raw
originals, the literal mapping and the raw-to-sanitized hash map are kept only in the private TXE-8043 evidence.

## `s-run/`: the TXE-8034 S run's capacity reads

**Source:** the capacity reads of TXE-8034's S run. That run's I9c gate passed with these readings: free 56 %, VM
available 26290 MiB, disk 189 GiB.

| File | sha256 (sanitized, published) | Transform from the raw capture |
|---|---|---|
| `memory-pressure.txt` | `c7fd4162b8b3cf257fd69f23111e949861775d096566963d4d0cb3745cc0cbea` | identity. No name, path or id; the sanitized hash equals the raw hash |
| `vm-stat.txt` | `03123980fba03bada9a13c6adbbf912b53471ab2cc3898398c51a2c39d2aeb7e` | identity, as above |
| `docker-info.txt` | `7b16f0dc4adfacd3f69a408c6f6b297019fda83a88280e96896354a1bb3d4d6e` | identity, as above |
| `docker-stats.txt` | `7fdffa03633c96acec6d3c320ac0f44946666e921e4bb66ddbb82f721eb1c466` | see below |
| `docker-ps.txt` | `575fff762805636e6c0a0ad42bc40cc60e4b8f751ccf4b63361c60a5a8cb8731` | **synthetic.** The S run had no `docker ps` read. One row per container: `<synthetic id>\tctr-NN\t` with an empty reservation label |

**The `docker-stats.txt` transform:**
1. Each internal container name was replaced, in row order, by `ctr-01` … `ctr-07`.
2. The name column was then replaced by a synthetic full id: row N's id is the two hex digits of N, repeated 32 times.
   This puts the file in the module's `{{.ID}}\t{{.MemUsage}}` format; the S run used `{{.Name}}`.
3. Every MemUsage figure (`<used> / <limit>`) is byte-for-byte the raw value, so the arithmetic is unchanged.

**Not shipped:** the S run's `df` capture. The disk tests inject its one number instead: 199161080 KiB available, all
paths on one device.

**Synthetic, and built in `test_capacity_gate.py`:** every budget, every inventory, the `docker inspect` rows, the
load text, and the injected `statvfs` and walk results. **The expected byte totals there were computed by hand** from
the MemUsage figures (README §2.6), not by the code under test.

`test_capacity_gate.py` asserts each file's hash against this table, and asserts that the public fixtures hold none of
the internal names.
