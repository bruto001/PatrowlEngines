#!/bin/bash
echo "[*] Starting ..."
if [ $# -ne 3 ]; then
    echo "[!] 3 arguments required;"
    echo " |  ./update_ver.sh <old_version> <new_version> <engine>"
    echo "[!] Quitting."
    exit
fi
echo "[+] Updating version ..."
cd ${3}
sed -i "s/${1}/${2}/g" VERSION
sed -i "s/${1}/${2}/g" Dockerfile
sed -i "s/${1}/${2}/g" __init__.py
sed -i "s/${1}/${2}/g" ${3}.json.sample


echo "[+] Adding to version control ..."
git add Dockerfile VERSION __init__.py ${3}.json.sample ../../VERSION
git commit -m "Updated VERSION (${3})"
cd ..
echo "[+] Updated ${3} to ${2}."
echo "[*] Done."
