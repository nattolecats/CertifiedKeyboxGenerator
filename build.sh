#!/bin/bash

# Generate key resource from keybox.xml
python3 generate.py

# Build apk
apktool b CertifiedKeyboxOverlay

# Try install to device
adb install CertifiedKeyboxOverlay/dist/CertifiedKeyboxOverlay.apk
