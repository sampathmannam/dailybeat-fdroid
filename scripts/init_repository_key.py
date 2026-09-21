#!/usr/bin/env python3
"""Create a durable repository-only identity once, outside the public checkout.

Never use this for the Android application's signing key. Back up BOTH the
encrypted keystore and its password file offline before relying on this identity.
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    args = parser.parse_args()
    directory = args.private_directory.expanduser().resolve()
    checkout = Path(__file__).resolve().parents[1]
    if directory == checkout or checkout in directory.parents:
        parser.error("The private directory must be outside the source checkout")
    # Refuse to overwrite or regenerate an established signing identity.
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(directory, 0o700)
    password = secrets.token_urlsafe(48)
    with open(directory / "password.txt", "x", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        stream.write(password + "\n")
    keystore = directory / "repository.p12"
    env = dict(os.environ, DAILYBEAT_REPO_PASSWORD=password)
    subprocess.run([
        "keytool", "-genkeypair", "-alias", "dailybeat-repo",
        "-keyalg", "RSA", "-keysize", "4096", "-sigalg", "SHA256withRSA",
        "-validity", "10000", "-dname", "CN=DailyBeat Repository, OU=Distribution",
        "-storetype", "PKCS12", "-keystore", str(keystore),
        "-storepass:env", "DAILYBEAT_REPO_PASSWORD",
        "-keypass:env", "DAILYBEAT_REPO_PASSWORD",
    ], env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.chmod(keystore, 0o600)
    certificate = subprocess.run([
        "keytool", "-exportcert", "-alias", "dailybeat-repo",
        "-keystore", str(keystore), "-storepass:env", "DAILYBEAT_REPO_PASSWORD",
    ], env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    (directory / "repository-public.der").write_bytes(certificate)
    os.chmod(directory / "repository-public.der", 0o600)
    print("Repository certificate SHA256:", hashlib.sha256(certificate).hexdigest().upper())
    print("Private key and password created outside the checkout. Back them up offline.")


if __name__ == "__main__":
    main()
