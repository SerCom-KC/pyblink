# A simple inspect script designed to work with packets captured by HttpCanary (https://play.google.com/store/apps/details?id=com.guoshi.httpcanary).
# Tested with version 3.3.1. Previous versions might not work (we don't support hcy format).
#
# To use this script:
# 1. In HttpCanary, set target app to bilibili and then start capturing.
# 2. Do whatever IM-related operations in the bilibili app, then stop capturing.
# 3. Back to HttpCanary, tap menu (3-dots icon on the top-right), "Filter", under "Protocols" tap "TCP".
# 4. Tap any item with the port number 6537.
# 5. Tap menu, "Save", "Save Both", and enter a desired name.
# 6. `cd` into saved folder (by default it would be located at "/sdcard/HttpCanary/download/<NAME_YOU_ENTERED_IN_STEP_5>/"; you might want to `adb pull` to your PC).
# 7. Execute `python3 /path/to/inspector.py`. The script will try to find the packet with skey first, then it would began parsing & decrypting.
# 8. If you have multiple sessions just start from step 4 again.

import os
import traceback
import warnings

from google.protobuf import text_format

from blink.__proto__ import *
from blink.IMEncrypt import IMEncrypt


def get_message_by_cmdid(cmdid, is_request=False):
    if cmdid == CmdId.EN_CMD_ID_SESSION_SVR_MY_GROUP_UNREAD:
        if is_request:
            raise NotImplementedError("Unsupported CmdId", cmdid)
        else:
            return RspMyGroupUnread()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_ACK_ASSIS_MSG:
        if is_request:
            return ReqAckAssisMsg()
        else:
            return DummyRsp()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_BATCH_RM_SESSIONS:
        if is_request:
            return ReqBatRmSess()
        else:
            return DummyRsp()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_GET_SESSIONS:
        if is_request:
            return ReqGetSessions()
        else:
            return RspSessions()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_GROUP_ASSIS_MSG:
        if is_request:
            return ReqGroupAssisMsg()
        else:
            return RspSessionMsg()

    elif cmdid == CmdId.EN_CMD_ID_SHAKE_HAND:
        if is_request:
            return ReqHands()
        else:
            return RspHands()

    elif cmdid == CmdId.EN_CMD_ID_HEARTBEAT:
        if is_request:
            return ReqHeartbeat()
        else:
            return RspHeartbeat()

    elif cmdid == CmdId.EN_CMD_ID_LOGIN:
        if is_request:
            return ReqLogin()
        else:
            return RspLogin()

    elif cmdid == CmdId.EN_CMD_ID_LOGOUT:
        if is_request:
            return ReqLogout()
        else:
            return RspLogin()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_NEW_SESSIONS:
        if is_request:
            return ReqNewSessions()
        else:
            return RspSessions()

    elif cmdid == CmdId.EN_CMD_ID_SYNC_RELATION:
        if is_request:
            return ReqRelationSync()
        return RspRelationSync()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_REMOVE_SESSION:
        if is_request:
            return ReqRemoveSession()
        else:
            return DummyRsp()

    elif cmdid == CmdId.EN_CMD_ID_SEND_MSG:
        if is_request:
            return ReqSendMsg()
        else:
            return RspSendMsg()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_SESSION_DETAIL:
        if is_request:
            return ReqSessionDetail()
        else:
            return SessionInfo()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_BATCH_SESS_DETAIL:
        if is_request:
            return ReqSessionDetails()
        else:
            return RspSessions()

    elif cmdid == CmdId.EN_CMD_ID_SYNC_FETCH_SESSION_MSGS:
        if is_request:
            return ReqSessionMsg()
        else:
            return RspSessionMsg()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_SET_TOP:
        if is_request:
            return ReqSetTop()
        else:
            return DummyRsp()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_SINGLE_UNREAD:
        if is_request:
            return ReqSingleUnread()
        else:
            return RspSingleUnread()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_UPDATE_ACK:
        if is_request:
            return ReqUpdateAck()
        else:
            return DummyRsp()

    elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_UPDATE_UNFLW_READ:
        if is_request:
            raise NotImplementedError("Unsupported CmdId", cmdid)
        else:
            return DummyRsp()

    elif cmdid == CmdId.EN_CMD_ID_SYNC_MSG:
        if is_request:
            return ReqMsgSync()
        else:
            return RspMsgSync()

    else:
        raise NotImplementedError("Unsupported CmdId", cmdid)


if __name__ == "__main__":
    warnings.filterwarnings("error")
    files = os.listdir()
    files.remove("tcp.hcy")
    files.remove("tcp.json")
    files = [i.replace(".bin", "") for i in files]
    files.sort(key=int)

    skey = None
    for i in files:
        with open(i + ".bin", "rb") as f:
            body = MsgBody()
            body.ParseFromString(f.read())
        if body.cmd == CmdId.EN_CMD_ID_SHAKE_HAND and body.err_msg == "ok":
            payload = RspHands()
            payload.ParseFromString(body.payload)
            skey = payload.skey
            break

    if not skey:
        print("No skey was found")
        exit(-1)

    for i in files:
        try:
            print("========== Packet #%s ==========" % (i))
            with open(i + ".bin", "rb") as f:
                body = MsgBody()
                body.ParseFromString(f.read())
            print(text_format.MessageToString(body, as_utf8=True))
            if body.cmd != CmdId.EN_CMD_ID_SHAKE_HAND:
                body.payload = IMEncrypt.decode(skey, body.payload)
                payload = get_message_by_cmdid(body.cmd, body.err_msg != "ok")
                payload.ParseFromString(body.payload)
                print("Decrypted payload:")
                print(text_format.MessageToString(payload, as_utf8=True))
        except:
            traceback.print_exc()
        print()
