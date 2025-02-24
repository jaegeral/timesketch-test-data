# timesketch-test-data

Various plaso files to test timesketch.

Just clone the repo to have a good set of already parsed plaso files to test your forensik pipeline.

Licenses: Please see the license in the corresponding folders.

## Downloading

Some Plaso files are directly in the folder structure. Because of the size of some, they are stored in the releases section:
https://github.com/jaegeral/timesketch-test-data/releases/tag/main

## Contributing

If you want to contribute, either open an issue pointing to relevant raw data that can be processed and added to this repo.

The other thing is if you have already processed data, please make a PR and indicate where the source image is located.

## Updating plaso files

### Stolen_Szechuan_Sauce

- Download newest files to: `timesketch-test-data/Stolen_Szechuan_Sauce/images`
- `sudo docker run -v ~/:/data log2timeline/plaso log2timeline --partition all --storage-file /data/dev/timesketch-test-data/Stolen_Szechuan_Sauce/20200918_0417_DESKTOP-SDN1RPT.plaso /data/dev/timesketch-test-data/Stolen_Szechuan_Sauce/images/20200918_0417_DESKTOP-SDN1RPT/20200918_0417_DESKTOP-SDN1RPT.E01`
- ` sudo docker run -v ~/:/data log2timeline/plaso log2timeline --partition all --storage-file /data/dev/timesketch-test-data/circl/circl-dfir.plaso /data/dev/timesketch-test-data/circl/images/circl-dfir.dd`

### CIRCL
- Download file from https://www.circl.lu/services/forensic-training-materials/
- `sudo docker run -v ~/:/data log2timeline/plaso log2timeline --partition all --storage-file /data/dev/timesketch-test-data/Stolen_Szechuan_Sauce/20200918_0417_DESKTOP-SDN1RPT.plaso /data/dev/timesketch-test-data/Stolen_Szechuan_Sauce/images/20200918_0417_DESKTOP-SDN1RPT/20200918_0417_DESKTOP-SDN1RPT.E01


## Plaso version used

```
sudo docker run -v ~/:/data log2timeline/plaso pinfo.py /data/dev/EVTX-ATTACK-SAMPLES-plaso/EVTX-ATTACK-SAMPLES/UACME_59_Sysmon.evtx.plaso

************************** Plaso Storage Information ***************************
            Filename : UACME_59_Sysmon.evtx.plaso
      Format version : 20230107
Serialization format : json
--------------------------------------------------------------------------------

*********************************** Sessions ***********************************
c1b22072-ac3a-49fe-b44c-4d9be561ac60 : 2023-03-13T12:22:46.063963+00:00
--------------------------------------------------------------------------------

******************************** Event sources *********************************
Total : 1
--------------------------------------------------------------------------------

************************* Events generated per parser **************************
Parser (plugin) name : Number of events
--------------------------------------------------------------------------------
            filestat : 3
             winevtx : 62
               Total : 65
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

# Other valuable data

https://github.com/OTRF/Security-Datasets
