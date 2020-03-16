# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: RspSessionInfos.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import DbSingleSession_pb2 as DbSingleSession__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='RspSessionInfos.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x15RspSessionInfos.proto\x12\x05\x62link\x1a\x15\x44\x62SingleSession.proto\"@\n\x0fRspSessionInfos\x12-\n\rsession_infos\x18\x01 \x03(\x0b\x32\x16.blink.DbSingleSessionB \n\x1e\x63om.bilibili.bplus.im.protobuf'
  ,
  dependencies=[DbSingleSession__pb2.DESCRIPTOR,])




_RSPSESSIONINFOS = _descriptor.Descriptor(
  name='RspSessionInfos',
  full_name='blink.RspSessionInfos',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='session_infos', full_name='blink.RspSessionInfos.session_infos', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=55,
  serialized_end=119,
)

_RSPSESSIONINFOS.fields_by_name['session_infos'].message_type = DbSingleSession__pb2._DBSINGLESESSION
DESCRIPTOR.message_types_by_name['RspSessionInfos'] = _RSPSESSIONINFOS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

RspSessionInfos = _reflection.GeneratedProtocolMessageType('RspSessionInfos', (_message.Message,), {
  'DESCRIPTOR' : _RSPSESSIONINFOS,
  '__module__' : 'RspSessionInfos_pb2'
  # @@protoc_insertion_point(class_scope:blink.RspSessionInfos)
  })
_sym_db.RegisterMessage(RspSessionInfos)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
