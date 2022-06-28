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

# Smoke-tests a release candidate
#
# 1. Downloads the tar.gz, deb, RPM and zip file from the staging URL
# 2. Verifies it's sha1 hashes and GPG signatures against the release key
# 3. Installs all official plugins
# 4. Starts one node for tar.gz and zip packages and checks:
#    -- if it runs with Java 1.8
#    -- if the build hash given is the one that is returned by the status response
#    -- if the build is a release version and not a snapshot version
#    -- if all plugins are loaded
#    -- if the status response returns the correct version
#
# USAGE:
#
# python3 -B ./dev-tools/smoke_test_rc.py --version 2.0.0-beta1 --hash bfa3e47
#
# to also test other plugins try run
#
# python3 -B ./dev-tools/smoke_test_rc.py --version 2.0.0-beta1 --hash bfa3e47 --plugins license,shield,watcher
#
# Note: Ensure the script is run from the elasticsearch top level directory
#
# For testing a release from sonatype try this:
#
# python3 -B dev-tools/smoke_test_rc.py --version 2.0.0-beta1 --hash bfa3e47 --fetch_url https://oss.sonatype.org/content/repositories/releases/
#

import argparse
import tempfile
import os
from os.path import basename, dirname, isdir, join
import signal
import shutil
import urllib
import urllib.request
import hashlib
import time
import socket
import json
import base64
from urllib.parse import urlparse

from http.client import HTTPConnection

def find_official_plugins():
    plugins_dir = join(dirname(dirname(__file__)), 'plugins')
    return [
        plugin
        for plugin in os.listdir(plugins_dir)
        if isdir(join(plugins_dir, plugin))
    ]
DEFAULT_PLUGINS = find_official_plugins()

try:
  JAVA_HOME = os.environ['JAVA_HOME']
except KeyError:
  raise RuntimeError("""
  Please set JAVA_HOME in the env before running release tool
  On OSX use: export JAVA_HOME=`/usr/libexec/java_home -v '1.8*'`""")

# console colors
COLOR_OK = '\033[92m'
COLOR_END = '\033[0m'

def run(command, env_vars=None):
    if env_vars:
      for key, value in env_vars.items():
        os.putenv(key, value)
    print(f'*** Running: {COLOR_OK}{command}{COLOR_END}')
    if os.system(command):
        raise RuntimeError(f'    FAILED: {command}')

def java_exe():
  path = JAVA_HOME
  return 'export JAVA_HOME="%s" PATH="%s/bin:$PATH" JAVACMD="%s/bin/java"' % (path, path, path)

def verify_java_version(version):
    s = os.popen(f'{java_exe()}; java -version 2>&1').read()
    if ' version "%s.' % version not in s:
      raise RuntimeError('got wrong version for java %s:\n%s' % (version, s))

def sha1(file):
  with open(file, 'rb') as f:
    return hashlib.sha1(f.read()).hexdigest()

def read_fully(file):
  with open(file, encoding='utf-8') as f:
     return f.read()

def wait_for_node_startup(es_dir, timeout=60, header={}):
    print(
        f'     Waiting until node becomes available for at most {timeout} seconds'
    )

    for _ in range(timeout):
      conn = None
      try:
        time.sleep(1)
        host = get_host_from_ports_file(es_dir)
        conn = HTTPConnection(host, timeout=1)
        conn.request('GET', '/', headers=header)
        res = conn.getresponse()
        if res.status == 200:
          return True
      except IOError as e:
        pass
        #that is ok it might not be there yet
      finally:
        if conn:
          conn.close()
    return False

def download_and_verify(version, hash, files, base_url, plugins=DEFAULT_PLUGINS):
    print(f'Downloading and verifying release {version} from {base_url}')
    tmp_dir = tempfile.mkdtemp()
    try:
        downloaded_files = []
        print('  ' + '*' * 80)
        # here we create a temp gpg home where we download the release key as the only key into
        # when we verify the signature it will fail if the signed key is not in the keystore and that
        # way we keep the executing host unmodified since we don't have to import the key into the default keystore
        gpg_home_dir = os.path.join(tmp_dir, "gpg_home_dir")
        os.makedirs(gpg_home_dir, 0o700)
        run(
            f'gpg --homedir {gpg_home_dir} --keyserver pool.sks-keyservers.net --recv-key D88E42B4'
        )


        for file in files:
            name = os.path.basename(file)
            print(f'  Smoketest file: {name}')
            url = f'{base_url}/{file}'
            print(f'  Downloading {url}')
            artifact_path = os.path.join(tmp_dir, file)
            downloaded_files.append(artifact_path)
            current_artifact_dir = os.path.dirname(artifact_path)
            urllib.request.urlretrieve(url, os.path.join(tmp_dir, file))
            sha1_url = ''.join([url, '.sha1'])
            checksum_file = f"{artifact_path}.sha1"
            print(f'  Downloading {sha1_url}')
            urllib.request.urlretrieve(sha1_url, checksum_file)
            print(f'  Verifying checksum {checksum_file}')
            expected = read_fully(checksum_file)
            actual = sha1(artifact_path)
            if expected != actual :
              raise RuntimeError('sha1 hash for %s doesn\'t match %s != %s' % (name, expected, actual))
            gpg_url = ''.join([url, '.asc'])
            gpg_file = f"{artifact_path}.asc"
            print(f'  Downloading {gpg_url}')
            urllib.request.urlretrieve(gpg_url, gpg_file)
            print(f'  Verifying gpg signature {gpg_file}')
            run(
                f'cd {current_artifact_dir} && gpg --homedir {gpg_home_dir} --verify {os.path.basename(gpg_file)}'
            )

            print('  ' + '*' * 80)
            print()
        smoke_test_release(version, downloaded_files, hash, plugins)
        print('  SUCCESS')
    finally:
        shutil.rmtree(tmp_dir)

def get_host_from_ports_file(es_dir):
  return read_fully(os.path.join(es_dir, 'logs/http.ports')).splitlines()[0]

def smoke_test_release(release, files, hash, plugins):
    for release_file in files:
        if not os.path.isfile(release_file):
            raise RuntimeError(f'Smoketest failed missing file {release_file}')
        tmp_dir = tempfile.mkdtemp()
        if release_file.endswith('tar.gz'):
            run(f'tar -xzf {release_file} -C {tmp_dir}')
        elif release_file.endswith('zip'):
            run(f'unzip {release_file} -d {tmp_dir}')
        else:
            print(f'  Skip SmokeTest for [{release_file}]')
            continue # nothing to do here
        es_dir = os.path.join(tmp_dir, f'elasticsearch-{release}')
        es_run_path = os.path.join(es_dir, 'bin/elasticsearch')
        print(f'  Smoke testing package [{release_file}]')
        es_plugin_path = os.path.join(es_dir, 'bin/elasticsearch-plugin')
        plugin_names = {}
        for plugin in plugins:
            print(f'     Install plugin [{plugin}]')
            run('%s; export ES_JAVA_OPTS="-Des.plugins.staging=%s"; %s %s %s' % (java_exe(), hash, es_plugin_path, 'install -b', plugin))
            plugin_names[plugin] = True
        if 'x-pack' in plugin_names:
            headers = {
                'Authorization': f'Basic {base64.b64encode(b"es_admin:foobar").decode("UTF-8")}'
            }

            es_shield_path = os.path.join(es_dir, 'bin/x-pack/users')
            print("     Install dummy shield user")
            run(f'{java_exe()}; {es_shield_path}  useradd es_admin -r superuser -p foobar')
        else:
            headers = {}
        print(f'  Starting elasticsearch deamon from [{es_dir}]')
        try:
            run(
                f"{java_exe()}; {es_run_path} -Enode.name=smoke_tester -Ecluster.name=prepare_release -Erepositories.url.allowed_urls=http://snapshot.test* -d -Epidfile={os.path.join(es_dir, 'es-smoke.pid')} -Enode.portsfile=true"
            )

            if not wait_for_node_startup(es_dir, header=headers):
              print("elasticsearch logs:")
              print('*' * 80)
              logs = read_fully(os.path.join(es_dir, 'logs/prepare_release.log'))
              print(logs)
              print('*' * 80)
              raise RuntimeError('server didn\'t start up')
            try: # we now get / and /_nodes to fetch basic infos like hashes etc and the installed plugins
                host = get_host_from_ports_file(es_dir)
                conn = HTTPConnection(host, timeout=20)
                conn.request('GET', '/', headers=headers)
                res = conn.getresponse()
                if res.status != 200:
                    raise RuntimeError(f'Expected HTTP 200 but got {res.status}')
                version = json.loads(res.read().decode("utf-8"))['version']
                if release != version['number']:
                    raise RuntimeError(
                        f"Expected version [{release}] but was [{version['number']}]"
                    )

                if version['build_snapshot']:
                  raise RuntimeError('Expected non snapshot version')
                print('  Verify if plugins are listed in _nodes')
                conn.request('GET', '/_nodes/plugins?pretty=true', headers=headers)
                res = conn.getresponse()
                if res.status != 200:
                    raise RuntimeError(f'Expected HTTP 200 but got {res.status}')
                nodes = json.loads(res.read().decode("utf-8"))['nodes']
                for _, node in nodes.items():
                    node_plugins = node['plugins']
                    for node_plugin in node_plugins:
                        if not plugin_names.get(node_plugin['name'].strip(), False):
                            raise RuntimeError(f"Unexpected plugin {node_plugin['name']}")
                        del plugin_names[node_plugin['name']]
                if plugin_names:
                    raise RuntimeError(f'Plugins not loaded {list(plugin_names.keys())}')

            finally:
                conn.close()
        finally:
            pid_path = os.path.join(es_dir, 'es-smoke.pid')
            if os.path.exists(pid_path): # try reading the pid and kill the node
              pid = int(read_fully(pid_path))
              os.kill(pid, signal.SIGKILL)
            shutil.rmtree(tmp_dir)
        print('  ' + '*' * 80)
        print()


def parse_list(string):
  return [x.strip() for x in string.split(',')]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SmokeTests a Release Candidate from S3 staging repo')
    parser.add_argument('--version', '-v', dest='version', default=None,
                        help='The Elasticsearch Version to smoke-tests', required=True)
    parser.add_argument('--hash', '-s', dest='hash', default=None, required=True,
                        help='The hash of the unified release')
    parser.add_argument('--plugins', '-p', dest='plugins', default=[], required=False, type=parse_list,
                        help='A list of additional plugins to smoketest')
    parser.add_argument('--fetch_url', '-u', dest='url', default=None,
                        help='Fetched from the specified URL')
    parser.set_defaults(hash=None)
    parser.set_defaults(plugins=[])
    parser.set_defaults(version=None)
    parser.set_defaults(url=None)
    args = parser.parse_args()
    plugins = args.plugins
    version = args.version
    hash = args.hash
    url = args.url
    files = [ x % {'version': version} for x in [
      'elasticsearch-%(version)s.tar.gz',
      'elasticsearch-%(version)s.zip',
      'elasticsearch-%(version)s.deb',
      'elasticsearch-%(version)s.rpm'
    ]]
    verify_java_version('1.8')
    download_url = (
        url
        or f'https://staging.elastic.co/{version}-{hash}/downloads/elasticsearch'
    )

    download_and_verify(version, hash, files, download_url, plugins=DEFAULT_PLUGINS + plugins)
