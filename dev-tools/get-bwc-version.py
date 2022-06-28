# Licensed to Elasticsearch under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance  with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on
# an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

'''
Downloads and extracts elasticsearch for backwards compatibility tests.
'''

import argparse
import os
import platform
import shutil
import subprocess
import urllib.request
import zipfile

def parse_config():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--path', metavar='DIR', default='./backwards',
                      help='Where to extract elasticsearch')
  parser.add_argument('--force', action='store_true', default=False,
                      help='Delete and redownload if the version already exists')
  parser.add_argument('version', metavar='X.Y.Z',
                      help='Version of elasticsearch to grab')
  return parser.parse_args()

def main():
  c = parse_config()

  if not os.path.exists(c.path):
    print(f'Creating {c.path}')
    os.mkdir(c.path)

  is_windows = platform.system() == 'Windows'

  os.chdir(c.path)
  version_dir = f'elasticsearch-{c.version}'
  if os.path.exists(version_dir):
    if c.force:
      print(f'Removing old download {version_dir}')
      shutil.rmtree(version_dir)
    else:
      print(f'Version {c.version} exists at {version_dir}')
      return

  # before 1.4.0, the zip file contains windows scripts, and tar.gz contained *nix scripts
  filename = f'{version_dir}.zip' if is_windows else f'{version_dir}.tar.gz'
  if c.version == '1.2.0':
    # 1.2.0 was pulled from download.elasticsearch.org because of routing bug:
    url = f'http://central.maven.org/maven2/org/elasticsearch/elasticsearch/1.2.0/{filename}'
  elif c.version.startswith('0.') or c.version.startswith('1.') or c.version.startswith('2.'):
    url = f'https://download.elasticsearch.org/elasticsearch/elasticsearch/{filename}'
  else:
    url = f'https://artifacts.elastic.co/downloads/elasticsearch/{filename}'
  print(f'Downloading {url}')
  urllib.request.urlretrieve(url, filename)

  print(f'Extracting to {version_dir}')
  if is_windows:
    archive = zipfile.ZipFile(filename)
    archive.extractall()
  else:
    # for some reason python's tarfile module has trouble with ES tgz?
    subprocess.check_call(f'tar -xzf {filename}', shell=True)

  print(f'Cleaning up {filename}')
  os.remove(filename)

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print('Ctrl-C caught, exiting')
