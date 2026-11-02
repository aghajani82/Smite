"""Preserve exact reviewed ZIP bytes; never rebuild or silently repin images."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

SOURCE='8edbd4032ae657fe2bb38cd9b3290de5f1e07a54'
ZIP_SHA='d250b0fd27ae362bc4008b9e62208f94ae92fb71273d66bee83c9bcdcd1f75d9'
MANIFEST_SHA='67672e362686b886a6e5653055ad808d1d878c514ee2e6c2f75f310eb77ef4cb'
FILES={'stage15-images.json':MANIFEST_SHA,
       'smite-panel-stage15.docker.tar.gz':'7b3d3172788d62f7d60f7103965e04db0df01606c4bc8d03760f904006ecf7c3',
       'smite-node-stage15.docker.tar.gz':'f4b4f1696582ba408ba85d581fa0dddd6ba04cd5d632e46eec95755f8d78e730'}

def digest(stream):
    h=hashlib.sha256()
    for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()

def verify(path):
    if path.is_symlink() or not path.is_file():raise ValueError('Untrusted ZIP path')
    with path.open('rb') as stream:
        if digest(stream)!=ZIP_SHA:raise ValueError('Original ZIP SHA mismatch')
    with zipfile.ZipFile(path) as archive:
        infos=archive.infolist()
        if len(infos)!=3 or {x.filename for x in infos}!=set(FILES):raise ValueError('Unexpected ZIP members')
        for entry in infos:
            if entry.is_dir() or entry.file_size>500_000_000 or entry.external_attr>>16&0o170000==0o120000:
                raise ValueError('Untrusted ZIP member')
            with archive.open(entry) as stream:
                if digest(stream)!=FILES[entry.filename]:raise ValueError('Artifact content mismatch')
        manifest=json.loads(archive.read('stage15-images.json'))
        if manifest['source_commit']!=SOURCE or manifest['source_repo']!='aghajani82/Smite' or manifest['activation_allowed'] is not False:
            raise ValueError('Wrong build origin or activation contract')
    return dict(source_commit=SOURCE,source_run=40921424209,source_artifact=12919495217,
                original_zip_sha256=ZIP_SHA,manifest_sha256=MANIFEST_SHA,
                preserved_without_rebuild=True,activation_allowed=False)

def main():
    original,out=map(Path,sys.argv[1:]);proof=verify(original)
    out.mkdir(exist_ok=False)
    shutil.copyfile(original,out/'stage15-reviewed-8edbd403.zip')
    (out/'preservation.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print('EXACT_ORIGINAL_ARTIFACT_PRESERVED=PASS')

if __name__=='__main__':main()
