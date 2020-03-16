import logging
import uuid

from .DeviceType_pb2 import DeviceType


class ClientConfig:
    def __init__(self, servers, access_key, uid, service="conn", method=1, mobi_app="android", build=5483100, version="5.48.3", package_name="tv.danmaku.bili", dev_id=str(uuid.uuid4()), token="", heartbeat=True, notify_callback=None, latest_seqno=-1, logger=logging.getLogger(__name__)):
        self.servers = servers
        self.access_key = access_key
        self.service = service
        self.method = method
        self.mobi_app = mobi_app
        self.build = build
        self.package_name = package_name
        self.uid = uid
        self.dev_type = self.__calculate_dev_type()
        self.dev_id = dev_id
        self.version = version
        self.token = token
        self.heartbeat = heartbeat
        self.notify_callback = notify_callback
        self.latest_seqno = latest_seqno
        self.logger = logger

    def __calculate_dev_type(self):
        if self.mobi_app != "android":
            raise NotImplementedError
        device_type = DeviceType.EN_DEV_TYPE_ANDROID
        if self.package_name == "com.bilibili.app.blue":
            package_id = 2
        elif self.package_name == "tv.danmaku.bili":
            package_id = 3
        else:
            package_id = 1
        return (package_id << 16) + device_type
