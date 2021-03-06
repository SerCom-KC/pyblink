# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ReqAddMonitorLog.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import MonitorDataInner_pb2 as MonitorDataInner__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='ReqAddMonitorLog.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x16ReqAddMonitorLog.proto\x12\x05\x62link\x1a\x16MonitorDataInner.proto\"@\n\x10ReqAddMonitorLog\x12,\n\x0bmonitor_log\x18\x01 \x03(\x0b\x32\x17.blink.MonitorDataInnerB \n\x1e\x63om.bilibili.bplus.im.protobuf'
  ,
  dependencies=[MonitorDataInner__pb2.DESCRIPTOR,])




_REQADDMONITORLOG = _descriptor.Descriptor(
  name='ReqAddMonitorLog',
  full_name='blink.ReqAddMonitorLog',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='monitor_log', full_name='blink.ReqAddMonitorLog.monitor_log', index=0,
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
  serialized_start=57,
  serialized_end=121,
)

_REQADDMONITORLOG.fields_by_name['monitor_log'].message_type = MonitorDataInner__pb2._MONITORDATAINNER
DESCRIPTOR.message_types_by_name['ReqAddMonitorLog'] = _REQADDMONITORLOG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ReqAddMonitorLog = _reflection.GeneratedProtocolMessageType('ReqAddMonitorLog', (_message.Message,), {
  'DESCRIPTOR' : _REQADDMONITORLOG,
  '__module__' : 'ReqAddMonitorLog_pb2'
  # @@protoc_insertion_point(class_scope:blink.ReqAddMonitorLog)
  })
_sym_db.RegisterMessage(ReqAddMonitorLog)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
