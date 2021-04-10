# timesketch-test-data

Various plaso files to test timesketch

# EVTX files from sbousseaden

To update the evtx files from sbousseaden and parse them with plaso:

```bash
git clone
https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
```

Then run the following script:

```
#!/bin/bash
find ./EVTX-ATTACK-SAMPLES/ -name "* *" -type d | rename 's/ /_/g'
for file in $(find ./EVTX-ATTACK-SAMPLES/ -type f -name "*.evtx"); do
    if [ -f "$file" ]; then
        echo "file $file"
        b=$(basename $file)
        #echo "$b"
        relpath=$(realpath --relative-to="./" "$file")
        #echo "rel $relpath"
        dirname=$(dirname $relpath)
        #echo "dirname $dirname"
        mkdir -p ./EVTX-ATTACK-SAMPLES-plaso/$dirname
        sudo docker run -v ../../dev/:/data log2timeline/plaso log2timeline /data/EVTX-ATTACK-SAMPLES-plaso/$relpath.plaso /data/$relpath
    fi
done
```
