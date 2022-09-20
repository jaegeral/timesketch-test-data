# timesketch-test-data

Various plaso files to test timesketch.

Just clone the repo to have a good set of already parsed plaso files to test your forensik pipeline.

Licenses: Please see the license in the corresponding folders.

## Contributing

If you want to contribute, either open an issue pointing to relevant raw data that can be processed and added to this repo.

The other thing is if you have already processed data, please make a PR and indicate where the source image is located.

## Plaso version used

```
/data/timesketch-test-data/EVTX-ATTACK-SAMPLES-plaso/EVTX-ATTACK-SAMPLES# pinfo.py UACME_59_Sysmon.evtx.plaso

************************** Plaso Storage Information ***************************
            Filename : UACME_59_Sysmon.evtx.plaso
      Format version : 20220716
Serialization format : json
--------------------------------------------------------------------------------

*********************************** Sessions ***********************************
d3bd298a-a641-4d1d-9816-332eb5d786b0 : 2022-09-20T12:07:57.771744+00:00
--------------------------------------------------------------------------------

******************************** Event sources *********************************
Total : 1
--------------------------------------------------------------------------------

************************* Events generated per parser **************************
Parser (plugin) name : Number of events
--------------------------------------------------------------------------------
            filestat : 3
             winevtx : 64
               Total : 67
--------------------------------------------------------------------------------

No events labels stored.

******************** Recovery warnings generated per parser ********************
Parser (plugin) name : Number of warnings
--------------------------------------------------------------------------------
             winevtx : 4
--------------------------------------------------------------------------------

*************** Path specifications with most recovery warnings ****************
Number of warnings : Pathspec
--------------------------------------------------------------------------------
                 4 : type: OS, location:
                     /data/EVTX-ATTACK-SAMPLES/UACME_59_Sysmon.evtx
--------------------------------------------------------------------------------

No analysis reports stored.
```

## EVTX files from sbousseaden

To update the evtx files from sbousseaden and parse them with plaso:

maybe install rename before

```bash
brew install rename
brew install coreutils
```

then

```bash
git clone
https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
```

Then run the following script:

```bash
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

To get the data in timesketch:

```
cp -r ./timesketch-test-data /tmp
```

