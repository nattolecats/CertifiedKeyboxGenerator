#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET
import base64
from cryptography.hazmat.primitives import serialization

def trim(string: str) -> str:
    return "\n".join([line.strip() for line in string.strip().splitlines() if line.strip()])

def trim_pem_cert(pem: str) -> str:
    lines = [line.strip() for line in pem.strip().splitlines()]
    return ''.join(lines[1:-1])

def pem_convert_to_pkcs8_der_base64(pem: str) -> str:
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(der).decode('utf-8')

def main():
    path = 'keybox.xml'
    if not os.path.isfile(path):
        print("No keybox is found")
        sys.exit(1)

    tree = ET.parse(path)
    root = tree.getroot()

    keybox = root.find("Keybox")
    if keybox is None:
        print("No Keybox is found")
        sys.exit(1)

    # EC Private key
    ec_key = keybox.find('./Key[@algorithm="ecdsa"]')
    if ec_key is not None:
        ec_priv_raw = trim(ec_key.find('PrivateKey').text)
        ec_priv = pem_convert_to_pkcs8_der_base64(ec_priv_raw)

        # Get EC CertificateChain
        ec_certs = []
        for cert in ec_key.find('CertificateChain').findall('Certificate'):
            ec_certs.append(trim_pem_cert(cert.text))

    # RSA Private key
    rsa_key = keybox.find('./Key[@algorithm="rsa"]')
    if rsa_key is not None:
        rsa_priv_raw = trim(rsa_key.find('PrivateKey').text)
        rsa_priv = pem_convert_to_pkcs8_der_base64(rsa_priv_raw)

        # Get RSA CertificateChain
        rsa_certs = []
        for cert in rsa_key.find('CertificateChain').findall('Certificate'):
            rsa_certs.append(trim_pem_cert(cert.text))

    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<!--
    Copyright (C) 2025 The 2by2 Project
    SPDX-License-Identifier: Apache-2.0
-->
<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
    <!-- Keybox configuration for device certification -->
    <string-array name="config_certifiedKeybox" translatable="false">
        <item>EC.PRIV:{ec_priv}</item>
        <item>EC.CERT_1:{ec_certs[0]}</item>
        <item>EC.CERT_2:{ec_certs[1]}</item>
        <item>EC.CERT_3:{ec_certs[2]}</item>
        <item>RSA.PRIV:{rsa_priv}</item>
        <item>RSA.CERT_1:{rsa_certs[0]}</item>
        <item>RSA.CERT_2:{rsa_certs[1]}</item>
        <item>RSA.CERT_3:{rsa_certs[2]}</item>
    </string-array>
</resources>
'''
    os.makedirs("res/values")
    with open("res/values/strings.xml","w") as o:
        o.write(xml)

if __name__ == "__main__":
    main()
