import json
import logging
import readline
import sys

import requests

from blink import Client, ClientConfig, MsgType, ReqMsgSync

ACCESS_KEY = ""
UID = 0
MESSAGE_RECEIVER_UID = 0


def notify_handler(instance, p):
    if p.notify_info:
        req = ReqMsgSync(
            client_seqno=instance.latest_seqno,
            dev_id=instance.config.dev_id,
            has_self=False,
            uid=instance.config.uid
        )
        rsp = instance.request(req)
        for i in rsp.messages:
            content = json.loads(i.content)
            if i.msg_type == MsgType.EN_MSG_TYPE_TEXT:
                print(content["content"])
            elif i.msg_type == MsgType.EN_MSG_TYPE_PIC:
                print(content["url"])
            else:
                print(content)
        instance.latest_seqno = p.lastest_seqno


if __name__ == "__main__":
    #logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="[%(asctime)s][%(levelname)s][%(module)s.%(funcName)s] %(message)s")
    resp = requests.get(
        "https://api.vc.bilibili.com/link_alloc/v1/alloc/get_list?access_key=" + ACCESS_KEY).json()
    config = ClientConfig(
        servers=resp["data"], access_key=ACCESS_KEY, uid=UID, notify_callback=notify_handler)
    with Client(config) as instance:
        print(instance.login())
        instance.start()
        while True:
            instance.send_message(MESSAGE_RECEIVER_UID, input(""))
