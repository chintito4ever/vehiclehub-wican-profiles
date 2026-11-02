# VehicleHub WiCAN vehicle profiles

Versioned AutoPID configurations for WiCAN PRO devices used with VehicleHub. The WiCAN
firmware Web UI reads this catalog from **Automate → VehicleHub Profiles**, previews a
profile against the device's current AutoPID groups and applies it only after the user
confirms. Profiles carry polling groups, OBD requests, decoding expressions and
VehicleHub field names. They carry no credentials, vehicle identity, device addresses or
MQTT topic bases (the device's own base is written as `{topic_base}`).

## Profiles

| Profile | Version | Status |
|---|---|---|
| Honda Accord 2017 EX | 1.0.0 | complete |
| Toyota Prius Gen 2 (NHW20) | 1.1.0 | complete |
| Toyota Camry 2020 XSE (ICE) | 0.1.0-draft.1 | **draft: cannot be installed** |

The Camry entry is an incomplete draft. It has no polling periods, ECU headers, OBD
protocol or CAN bitrate, because no read-only device snapshot exists yet. The catalog
lists it with `"latest": null` and the firmware refuses to apply a draft. It becomes
installable only as a new, complete version built from a device snapshot.

## Layout

```
vehiclehub-profiles/
  catalog.json                       index: every version, its path, sha256 and size
  schema.json                        structural contract (vehiclehub.wican.vehicle-profile.v1)
  <make>/<model>/<version>.json      one immutable file per version
  tools/vh_profile_catalog.py        validate | add-versions | hash (standard-library Python)
```

The catalog URL is the raw URL of `vehiclehub-profiles/catalog.json` on the `main` branch.
The Web UI fetches a version file from the same directory using its catalog `path`, and
the device checks the file's sha256 against the catalog before it accepts it.

## Rules

- **Published versions are immutable.** A file listed in `catalog.json` on `main` is never
  edited, renamed or removed. A correction is a new version. CI enforces this with
  `validate --base-ref`.
- **Only `catalog.json` changes in place**, and only to add versions or move `latest` to a
  newer complete version. A draft is never `latest`.
- **Read-only diagnostics only.** Services 01, 02, 03, 07, 09, 0A, 21 and 22; a fixed
  allow-list of ELM327 init commands; expressions limited to the firmware evaluator's
  characters. The firmware enforces the same lists.
- **Local overrides stay local.** A device keeps its own enabled/period overrides across a
  profile update, and asks before replacing groups that were changed outside the profile
  page. Nothing here is applied without a preview and an explicit confirmation on the
  device.

## Validating

```bash
python3 vehiclehub-profiles/tools/vh_profile_catalog.py validate --base-ref origin/main
python3 vehiclehub-profiles/tools/vh_profile_catalog.py hash vehiclehub-profiles/<make>/<model>/<version>.json
```

## Offline use

Download a version file, compare its sha256 with the catalog entry (`shasum -a 256 <file>`
or the `hash` command above), and import it on the device with **Import a profile file (offline)** on the
VehicleHub Profiles page. The preview shows the sha256 the device computed. Drafts are
refused offline as well.

## Changes

Profiles are produced from read-only device snapshots in the private firmware repository
and exported here unchanged. Pull requests that edit a published version are rejected by
CI.
