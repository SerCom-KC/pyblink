# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: SwooleHttp.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import SwooleHead_pb2 as SwooleHead__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='SwooleHttp.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x10SwooleHttp.proto\x12\x05\x62link\x1a\x10SwooleHead.proto\"/\n\nSwooleHttp\x12!\n\x06header\x18\x01 \x01(\x0b\x32\x11.blink.SwooleHeadB \n\x1e\x63om.bilibili.bplus.im.protobuf'
  ,
  dependencies=[SwooleHead__pb2.DESCRIPTOR,])




_SWOOLEHTTP = _descriptor.Descriptor(
  name='SwooleHttp',
  full_name='blink.SwooleHttp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='header', full_name='blink.SwooleHttp.header', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=45,
  serialized_end=92,
)

_SWOOLEHTTP.fields_by_name['header'].message_type = SwooleHead__pb2._SWOOLEHEAD
DESCRIPTOR.message_types_by_name['SwooleHttp'] = _SWOOLEHTTP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SwooleHttp = _reflection.GeneratedProtocolMessageType('SwooleHttp', (_message.Message,), {
  'DESCRIPTOR' : _SWOOLEHTTP,
  '__module__' : 'SwooleHttp_pb2'
  # @@protoc_insertion_point(class_scope:blink.SwooleHttp)
  })
_sym_db.RegisterMessage(SwooleHttp)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)