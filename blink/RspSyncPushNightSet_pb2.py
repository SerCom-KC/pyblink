# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: RspSyncPushNightSet.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='RspSyncPushNightSet.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x19RspSyncPushNightSet.proto\x12\x05\x62link\"&\n\x13RspSyncPushNightSet\x12\x0f\n\x07\x61pp_ids\x18\x01 \x03(\x05\x42 \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_RSPSYNCPUSHNIGHTSET = _descriptor.Descriptor(
  name='RspSyncPushNightSet',
  full_name='blink.RspSyncPushNightSet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='app_ids', full_name='blink.RspSyncPushNightSet.app_ids', index=0,
      number=1, type=5, cpp_type=1, label=3,
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
  serialized_start=36,
  serialized_end=74,
)

DESCRIPTOR.message_types_by_name['RspSyncPushNightSet'] = _RSPSYNCPUSHNIGHTSET
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

RspSyncPushNightSet = _reflection.GeneratedProtocolMessageType('RspSyncPushNightSet', (_message.Message,), {
  'DESCRIPTOR' : _RSPSYNCPUSHNIGHTSET,
  '__module__' : 'RspSyncPushNightSet_pb2'
  # @@protoc_insertion_point(class_scope:blink.RspSyncPushNightSet)
  })
_sym_db.RegisterMessage(RspSyncPushNightSet)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)