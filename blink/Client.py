import json
import random
import socket
import time
from threading import Thread

from .__proto__ import *
from .IMEncrypt import IMEncrypt


class Client:
    # TODO make it thread-safe
    def __init__(self, config):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.config = config
        # TODO auto switch server
        self.ip = self.config.servers[0]["ip"]
        self.port = self.config.servers[0]["port"]
        self.listener_stop = True
        self.heartbeat_stop = not self.config.heartbeat
        self.last_heartbeat_timestamp = int(time.time())
        self.heartbeat_timeout = 30
        self.skey = None
        self.rsp_list = []
        self.logger = self.config.logger
        self.logger.info("Initiated")

    def connect(self):
        self.logger.info("Connecting to %s:%s" % (self.ip, self.port))
        self.sock.connect((self.ip, self.port))
        self.sock.setblocking(False)
        self.heartbeat_thread = None

    def close(self):
        self.logger.info("Disconnecting")
        self.stop()
        self.heartbeat_stop = True
        if self.sock:
            self.sock.close()

    def start(self):
        while not self.skey:
            self.logger.debug("Waiting for handshake complete")
            time.sleep(1)
            pass
        self.rsp_list = []
        self.logger.info("Starting listener thread")
        self.listener = Thread(target=self.__listener)
        self.listener.start()

    def stop(self):
        self.logger.info("Stopping listener thread")
        self.listener_stop = True

    def idle(self):
        if not self.listener_stop:
            self.listener.join()

    def __heart(self):
        self.logger.info("Heartbeat thread started")
        while not self.heartbeat_stop:
            if (int(time.time()) - self.last_heartbeat_timestamp) > self.heartbeat_timeout:
                self.heartbeat()

    def __listener(self):
        self.logger.info("Listener thread started")
        self.listener_stop = False
        while not self.listener_stop:
            rsp = self.receive_raw_message(return_none=True)
            if rsp is not None:
                if rsp.cmd == CmdId.EN_CMD_ID_MSG_NOTIFY:
                    self.__notify_handler(rsp)
                    rsp = None
                elif isinstance(rsp, MsgBody):
                    self.rsp_list.append(rsp)

    def __enter__(self):
        self.connect()
        self.handshake()
        #self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def send_raw_message(self, body):
        self.logger.debug("Sending new message:\n%s" % (body))
        body = body.SerializeToString()
        head = MsgHead(len=len(body), crc=0)
        head = head.SerializeToString()
        sent = self.sock.sendall(head + body)
        if sent == 0:
            raise RuntimeError("socket connection broken")

    def receive_raw_message(self, return_none=False):
        head = MsgHead()
        while True:
            try:
                received = self.sock.recv(10) # MsgHead has a fixed length of 10 bytes
                break
            except socket.error as e:
                if e.errno == 11:
                    self.logger.debug("Waiting for message")
                    if return_none: return None
                    else:                        
                        time.sleep(0.1)
                        continue
                elif e.errno == 9:
                    self.logger.info("Socket is already closed, stopping listener thread")
                    self.thread_stop = True
                    return
                else:
                    raise e
        head.ParseFromString(received)
        body = MsgBody()
        received = self.sock.recv(head.len) # length of MsgBody can be retrieved from MsgHead.len
        if len(received) != head.len:
            raise RuntimeError("socket connection broken")
        body.ParseFromString(received)
        self.logger.debug("Received new message:\n%s" % (body))
        return body

    def __notify_handler(self, body):
        p = ReqServerNotify()
        p.ParseFromString(IMEncrypt.decode(self.skey, body.payload))
        self.logger.info("Received new notify message:\n%s" % (p))
        if self.config.notify_callback:
            self.logger.info("Calling notify message callback function")
            Thread(target=self.config.notify_callback, args=(self, p,)).start()

    def get_message_by_cmdid(self, cmdid):
        if cmdid == CmdId.EN_CMD_ID_SESSION_SVR_MY_GROUP_UNREAD:
            return RspMyGroupUnread()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_ACK_ASSIS_MSG:
            return DummyRsp()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_BATCH_RM_SESSIONS:
            return DummyRsp()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_GET_SESSIONS:
            return RspSessions()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_GROUP_ASSIS_MSG:
            return RspSessionMsg()
        
        elif cmdid == CmdId.EN_CMD_ID_SHAKE_HAND:
            return RspHands()
        
        elif cmdid == CmdId.EN_CMD_ID_HEARTBEAT:
            return RspHeartbeat()
        
        elif cmdid == CmdId.EN_CMD_ID_LOGIN:
            return RspLogin()
        
        elif cmdid == CmdId.EN_CMD_ID_LOGOUT:
            return RspLogin()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_NEW_SESSIONS:
            return RspSessions()
        
        elif cmdid == CmdId.EN_CMD_ID_SYNC_RELATION:
            return RspRelationSync()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_REMOVE_SESSION:
            return DummyRsp()
        
        elif cmdid == CmdId.EN_CMD_ID_SEND_MSG:
            return RspSendMsg()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_SESSION_DETAIL:
            return SessionInfo()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_BATCH_SESS_DETAIL:
            return RspSessions()
        
        elif cmdid == CmdId.EN_CMD_ID_SYNC_FETCH_SESSION_MSGS:
            return RspSessionMsg()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_SET_TOP:
            return DummyRsp()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_SINGLE_UNREAD:
            return RspSingleUnread()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_UPDATE_ACK:
            return DummyRsp()
        
        elif cmdid == CmdId.EN_CMD_ID_SESSION_SVR_UPDATE_UNFLW_READ:
            return DummyRsp()
        
        elif cmdid == CmdId.EN_CMD_ID_SYNC_MSG:
            return RspMsgSync()

        else:
            raise NotImplementedError("Unsupported CmdId", cmdid)

    def get_cmdid_by_message(self, message):
        if isinstance(message, ReqAckAssisMsg):
            return CmdId.EN_CMD_ID_SESSION_SVR_ACK_ASSIS_MSG

        elif isinstance(message, ReqBatRmSess):
            return CmdId.EN_CMD_ID_SESSION_SVR_BATCH_RM_SESSIONS

        elif isinstance(message, ReqGetSessions):
            return CmdId.EN_CMD_ID_SESSION_SVR_GET_SESSIONS

        elif isinstance(message, ReqGroupAssisMsg):
            return CmdId.EN_CMD_ID_SESSION_SVR_GROUP_ASSIS_MSG

        elif isinstance(message, ReqHands):
            return CmdId.EN_CMD_ID_SHAKE_HAND

        elif isinstance(message, ReqHeartbeat):
            return CmdId.EN_CMD_ID_HEARTBEAT

        elif isinstance(message, ReqLogin):
            return CmdId.EN_CMD_ID_LOGIN

        elif isinstance(message, ReqLogout):
            return CmdId.EN_CMD_ID_LOGOUT

        elif isinstance(message, ReqNewSessions):
            return CmdId.EN_CMD_ID_SESSION_SVR_NEW_SESSIONS

        elif isinstance(message, ReqRelationSync):
            return CmdId.EN_CMD_ID_SYNC_RELATION

        elif isinstance(message, ReqRemoveSession):
            return CmdId.EN_CMD_ID_SESSION_SVR_REMOVE_SESSION

        elif isinstance(message, ReqSendMsg):
            return CmdId.EN_CMD_ID_SEND_MSG

        elif isinstance(message, ReqSessionDetail):
            return CmdId.EN_CMD_ID_SESSION_SVR_SESSION_DETAIL

        elif isinstance(message, ReqSessionDetails):
            return CmdId.EN_CMD_ID_SESSION_SVR_BATCH_SESS_DETAIL

        elif isinstance(message, ReqSessionMsg):
            return CmdId.EN_CMD_ID_SYNC_FETCH_SESSION_MSGS

        elif isinstance(message, ReqSetTop):
            return CmdId.EN_CMD_ID_SESSION_SVR_SET_TOP

        elif isinstance(message, ReqSingleUnread):
            return CmdId.EN_CMD_ID_SESSION_SVR_SINGLE_UNREAD

        elif isinstance(message, ReqUpdateAck):
            return CmdId.EN_CMD_ID_SESSION_SVR_UPDATE_ACK

        elif isinstance(message, ReqMsgSync):
            return CmdId.EN_CMD_ID_SYNC_MSG

        else:
            raise NotImplementedError("Unsupported message type", type(message))

    def generate_random_long_int(self):
        return random.randrange(int(time.time()*1000000000))

    def request(self, payload):
        self.logger.debug("Request payload:\n%s" % (payload))
        if not isinstance(payload, ReqHands):
            self.logger.debug("Encrypting payload with skey: %s" % (self.skey))
            p = IMEncrypt.encode(self.skey, payload.SerializeToString())
        else:
            p = payload.SerializeToString()
        req_id = self.generate_random_long_int()
        self.logger.debug("Request ID is %s" % (req_id))
        req = MsgBody(
            cmd=self.get_cmdid_by_message(payload),
            cli_req_id=req_id,
            service=self.config.service,
            method=self.config.method,
            payload=p,
            mobi_app=self.config.mobi_app,
            build=self.config.build
        )
        self.send_raw_message(req)
        rsp = None
        while rsp is None:
            self.logger.debug("Wating for response")
            if self.listener_stop:
                rsp = self.receive_raw_message()
                if rsp.cmd == CmdId.EN_CMD_ID_MSG_NOTIFY:
                    self.__notify_handler(rsp)
                    rsp = None
                elif rsp.cli_req_id != req_id:
                    self.logger.debug("Unexpected response type, appending to response list")
                    self.rsp_list.append(rsp)
                    rsp = None
            else:
                self.logger.debug("Searching for response in response list")
                for i in self.rsp_list:
                    if i.cli_req_id == req_id:
                        rsp = i
                        self.rsp_list.remove(i)
        if rsp.err_code:
            raise RuntimeError(rsp.err_code, rsp.err_msg, rsp.cmd) # TODO Exception class
        if rsp.cmd == CmdId.EN_CMD_ID_KICK_OUT:
            self.logger.warning("Session is kicked out by the server, attempting to relogin and request again")
            self.login()
            return self.request(payload)
        else:
            p = self.get_message_by_cmdid(rsp.cmd)
        if not isinstance(p, RspHands):
            self.logger.debug("Decrypting payload with skey: %s" % (self.skey))
            p.ParseFromString(IMEncrypt.decode(self.skey, rsp.payload))
        else:
            p.ParseFromString(rsp.payload)
        self.logger.debug("Response payload:\n%s" % (p))
        return p

    def handshake(self):
        self.logger.info("Sending handshake request")
        rsp = self.request(ReqHands(uid=self.config.uid))
        if not isinstance(rsp, RspHands):
            raise RuntimeError("Unexpected handshake response")
        self.logger.info("Handshake success, skey is %s" % (rsp.skey))
        self.skey = rsp.skey
        if not self.heartbeat_stop and self.heartbeat_thread is None:
            self.logger.info("Starting heartbeat thread")
            self.heartbeat_thread = Thread(target=self.__heart).start()

    def login(self, force_relogin=False):
        if force_relogin or self.config.token == "":
            self.logger.info("Logging in without token")
            auto_login = 0
        else:
            self.logger.info("Logging in with token %s" % (self.config.token))
            auto_login = 1
        req = ReqLogin(
            uid=self.config.uid,
            access_key=self.config.access_key,
            dev_type=self.config.dev_type,
            dev_id=self.config.dev_id,
            version=self.config.version,
            auto_login=auto_login
        )
        if req.auto_login: req.fast_token = self.config.token
        try:
            rsp = self.request(req)
        except Exception as e:
            if e.args[0] == MsgRetCode.ERR_LOGIN_SERVICE_DEV_CONFLICT_FAILED:
                self.logger.warning("Other devices are already logged in, retrying without token")
                # Other devices might signed in - force_relogin will kick these devices out
                return self.login(force_relogin=True)
            else:
                raise e
        if isinstance(rsp, RspLogin):
            self.logger.info("Login success, new token is %s" % (rsp.next_token))
            self.config.token = rsp.next_token
            self.latest_seqno = rsp.server_latest_seqno if self.config.latest_seqno < 0 else self.config.latest_seqno
            return self.config.dev_id, rsp.next_token # returning dev_id and token so user can reuse these credentials

    def send_message(self, receiver_id, content, receiver_type=RecverType.EN_RECVER_TYPE_PEER, msg_type=MsgType.EN_MSG_TYPE_TEXT):
        if receiver_type != RecverType.EN_RECVER_TYPE_PEER: raise NotImplementedError
        if msg_type != MsgType.EN_MSG_TYPE_TEXT: raise NotImplementedError
        if isinstance(content, str): content = {"content": content}
        content = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
        self.logger.info("Sending private message to UID %s:\n%s" % (receiver_id, content))
        req = ReqSendMsg(msg=Msg(
            sender_uid=self.config.uid,
            receiver_type=receiver_type,
            receiver_id=receiver_id,
            cli_msg_id=self.generate_random_long_int(),
            msg_type=msg_type,
            content=content
        ))
        rsp = self.request(req)
        return rsp.msg_key

    def heartbeat(self, background=False):
        self.logger.info("Sending heartbeat request")
        req = ReqHeartbeat(
            background=1 if background else 0,
            msg_seqno=0,
            op_seqno=0
        )
        rsp = self.request(req)
        self.last_heartbeat_timestamp = int(time.time())
        self.logger.info("Setting heartbeat_timeout to %ss" % (rsp.heartbeat_timeout))
        self.heartbeat_timeout = rsp.heartbeat_timeout
