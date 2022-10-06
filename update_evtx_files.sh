#!/bin/bash
find ../EVTX-ATTACK-SAMPLES/ -name "* *" -type d | rename 's/ /_/g'
for file in $(find ../EVTX-ATTACK-SAMPLES/ -type f -name "*.evtx"); do
    if [ -f "$file" ]; then
        echo "file $file"
        b=$(basename $file)
        #echo "$b"
        relpath=$(realpath --relative-to="../" "$file")
        #echo "rel $relpath"
        dirname=$(dirname $relpath)
        echo "dirname $dirname"
        mkdir -p ./EVTX-ATTACK-SAMPLES-plaso/$dirname
        sudo docker run -v ~/:/data log2timeline/plaso log2timeline --storage-file /data/timesketch-test-data/EVTX-ATTACK-SAMPLES-plaso/$relpath.plaso /data/$relpath
    fi
done

sudo docker run -v ~/:/data log2timeline/plaso log2timeline --storage-file /data/timesketch-test-data/evtx-baseline/Logs_Client.plaso /data/timesketch-test-data/evtx-baseline/Logs_Client
sudo docker run -v ~/:/data log2timeline/plaso log2timeline --storage-file /data/timesketch-test-data/evtx-baseline/Logs_Win11.plaso /data/timesketch-test-data/evtx-baseline/Logs_Win11
sudo docker run -v ~/:/data log2timeline/plaso log2timeline --storage-file /data/timesketch-test-data/evtx-baseline/win7-x86.plaso /data/timesketch-test-data/evtx-baseline/win7-x86
sudo docker run -v ~/:/data log2timeline/plaso log2timeline --storage-file /data/timesketch-test-data/evtx-baseline/win2022-0-20348-azure.plaso /data/timesketch-test-data/evtx-baseline/win2022-0-20348-azure
sudo docker run -v ~/:/data log2timeline/plaso log2timeline --storage-file /data/timesketch-test-data/evtx-baseline/Win2022-AD.plaso /data/timesketch-test-data/evtx-baseline/Win2022-AD
sudo docker run -v ~/:/data log2timeline/plaso log2timeline --storage-file /data/timesketch-test-data/evtx-baseline/win2022-evtx.plaso /data/timesketch-test-data/evtx-baseline/win2022-evtx