import logging
import requests
from datetime import datetime

from mwdb.core.plugins import PluginAppContext, PluginHookHandler
from mwdb.model import File
from mwdblib import MWDB

__author__ = "Askar Dyussekeyev"
__version__ = "0.0.1"
__doc__ = "Simple plugin for mwdb-core that integrates with AVEDR"

logger = logging.getLogger("mwdb.plugin.avedr")

config_api_url = ""
config_api_key = ""

SCANNER_ENDPOINTS = [
    {"name": "ClamAV", "url": "http://127.0.0.1:8000/scan"},
]

def AvedrAddTag(file, av_name: str, av_result: str):
    for tag in file.tags:
        if tag.startswith(f"{av_name}:"):
            file.remove_tag(tag)

    file.add_tag(f"{av_name}:{av_result}")

def AvedrProcessFile(hash_value):
    mwdb = MWDB(api_url=config_api_url, api_key=config_api_key)
    
    file = mwdb.query_file(hash_value)
    
    temp_file_path = f"/tmp/{hash_value}"
    with open(temp_file_path, "wb") as f:
        f.write(file.content)

    comment = ""
    for endpoint in SCANNER_ENDPOINTS:
        with open(temp_file_path, 'rb') as f:
            response = requests.post(endpoint["url"], files={'file': (hash_value, f, 'application/octet-stream')})
            if response.status_code == 200:
                result = response.json()
                comment += f"{endpoint['name']} result: {result['result']} (Version: {result['version']})\n"
                AvedrAddTag(file, endpoint['name'], result['result'])
            else:
                comment += f"{endpoint['name']} error: {response.status_code}\n"

    file.add_comment(comment.strip())

class AvedrHookHandler(PluginHookHandler):
    def on_created_file(self, file: File):
        logger.info("on_created_file(): AV scan requested for sha256 = %s", file.sha256)
        AvedrProcessFile(file.sha256)

    def on_reuploaded_file(self, file: File):
        logger.info("on_reuploaded_file(): AV scan requested for sha256 = %s", file.sha256)
        AvedrProcessFile(file.sha256)

def entrypoint(app_context: PluginAppContext):
    """
    Register plugin hook handler.

    This will be called on app load.
    """
    app_context.register_hook_handler(AvedrHookHandler)
    logger.info("Plugin hook handler is registered.")

__plugin_entrypoint__ = entrypoint
