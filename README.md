# DailyBeat's Google-free repository

This is **DailyBeat's own signed, F-Droid-compatible repository**, not the official
F-Droid repository and not an endorsement by F-Droid. DailyBeat was developed with
AI assistance; this alternative distribution channel does not disguise its origin.

## Install

Open the [repository and QR code](https://sampathmannam.github.io/dailybeat-fdroid/fdroid/repo/?fingerprint=5FFE8C00EA81C6B8639E958B2380D438D853C15A482798F53927699F35B57CD0)
on your Android phone, or add the following address in your F-Droid-compatible
client's repository settings:

```text
https://sampathmannam.github.io/dailybeat-fdroid/fdroid/repo?fingerprint=5FFE8C00EA81C6B8639E958B2380D438D853C15A482798F53927699F35B57CD0
```

Verify the repository certificate fingerprint before trusting it:

```text
5FFE8C00 EA81C6B8 639E958B 2380D438 D853C15A 482798F5 3927699F 35B57CD0
```

Refresh repositories, search for **DailyBeat**, and install. Android 8 or newer is
required. Only the unchanged upstream-signed **Google-free store APK** is served.

### Already using Obtainium?

You can keep using the existing [GitHub stable release channel](https://github.com/sampathmannam/dailybeat/releases/latest)
in Obtainium. You do **not** need to switch or uninstall. Uninstalling may erase
your local history. Make an export or backup before intentionally switching channels.

The standard and Google-free builds share a package name, APK signing certificate,
and version code. Version 4.3.5 / code 39 may therefore show **no update** if you
already have code 39. Future higher-code Google-free releases can replace an
existing standard installation; manage DailyBeat through one chosen update source.

## What is different in this build?

- No Google Play Services, advertising SDK or analytics SDK.
- Android platform location; battery behaviour can differ from the Google-backed build.
- The developer's managed cloud-backup configuration is not included.
- Online maps are **on by default**; map providers see your IP and requested areas.
  Disable them in Settings for downloaded maps or route-only previews.
- Cloud AI is optional and **off by default**. If enabled, selected text is sent
  to your configured provider, which can be a proprietary service.
- Optional Tamil Nadu offline maps are separate downloads from GitHub Releases.
  Device speech recognition may also use a network service.
- DailyBeat is not an evidence-custody, attendance-verification or emergency system.

See the [privacy information](https://github.com/sampathmannam/dailybeat/blob/7057b5ea44bdba12ef7224342afee17d3264f2f1/PRIVACY.md),
[exact v4.3.5 source](https://github.com/sampathmannam/dailybeat/tree/7057b5ea44bdba12ef7224342afee17d3264f2f1),
and [downloadable corresponding source](https://github.com/sampathmannam/dailybeat/archive/7057b5ea44bdba12ef7224342afee17d3264f2f1.tar.gz).
Original code is GPL-3.0-only; third-party components retain their own licences.

The separate [official F-Droid submission](https://gitlab.com/fdroid/fdroiddata/-/merge_requests/49457)
is under review. This repository is usable independently of that decision.

## How publishing works

`release.json` pins one approved APK URL, immutable source commit, APK SHA-256,
package, version, version code and APK signer. `repository.json` pins the separate
repository identity. The build script downloads and verifies the APK, generates
indexes with fdroidserver 2.4.5, signs the catalog with the repository key, and
verifies both signed index formats and the APK before allowing publication.
It never rebuilds or re-signs an APK.

Only the explicit `build/site` public tree goes to GitHub Pages. APKs, keystores,
private config and generated output are not committed to Git. The current site
serves one release; historical APKs remain in the app's GitHub Releases.

CI signing is restricted to `main` in the `repository-signing` environment.
The deploy job receives no signing credentials and uses GitHub Pages' OIDC trust.
Actions are pinned to commits, and CI's Python dependencies are version/hash-locked
in `requirements-ci.lock`. Pull requests run checks without signing secrets.
Superseded workflow runs cannot sign or deploy over a newer source revision.
The public catalog offers verified v1 and v2 indexes; legacy v0 is not published.

### Publish the next approved version

1. Finish and verify the upstream Google-free APK release. Keep its established
   application signing certificate; use a higher Android version code.
2. Update all fields in `release.json` from verified release evidence. Review the
   APK hash and signer independently; do not trust a checksum download alone.
3. Update `metadata/com.dailybeat.app.yml` current version/source/changelog links,
   the localized `changelogs/<versionCode>.txt`, and this README's version-specific source links.
4. Open a pull request and pass checks. Merge to `main` to publish, then verify the
   live index fingerprint and installation through an Android client.

There is **no blind polling of upstream releases**. Each manifest update must be
reviewed. A manual workflow run can re-publish the currently approved manifest.

### Local verification / recovery

Install Python with `pip install -r requirements.txt`, a JDK and Android SDK
build tools. Set `JAVA_HOME` and `ANDROID_HOME` as appropriate. Supply the existing
repository keystore outside the checkout, and read its password into the
`DAILYBEAT_REPO_PASSWORD` environment variable without putting it in shell history.

```sh
python -m unittest discover -s tests -v
python scripts/build_repository.py --output build --keystore /private/location/repository.p12
python scripts/build_repository.py --verify-only --output build
python scripts/verify_live_repository.py
```

The last command checks the public HTTPS endpoint with the pinned repository
fingerprint, verifies both signed index protocols, then downloads and verifies the
APK. It needs no signing credentials and never modifies the hosted repository.

`scripts/init_repository_key.py` is for **initial setup of a new identity only**.
Do not run it to replace the published key. The encrypted PKCS12 key and its
password need a private offline backup; losing them breaks continuity for all
subscribers. No application signing key belongs in this repository. A compromised
repository key must be treated as an incident and communicated to subscribers.

The standard generated catalog page supplies installation information and a QR
code. Hosting uses GitHub Pages and its availability/bandwidth limits; neither
store admission nor uninterrupted third-party hosting is guaranteed.
