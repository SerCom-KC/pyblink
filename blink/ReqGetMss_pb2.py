# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ReqGetMss.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='ReqGetMss.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x0fReqGetMss.proto\x12\x05\x62link\"\x17\n\tReqGetMss\x12\n\n\x02ts\x18\x01 \x01(\x04\x42 \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_REQGETMSS = _descriptor.Descriptor(
  name='ReqGetMss',
  full_name='blink.ReqGetMss',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ts', full_name='blink.ReqGetMss.ts', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
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
  serialized_start=26,
  serialized_end=49,
)

DESCRIPTOR.message_types_by_name['ReqGetMss'] = _REQGETMSS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ReqGetMss = _reflection.GeneratedProtocolMessageType('ReqGetMss', (_message.Message,), {
  'DESCRIPTOR' : _REQGETMSS,
  '__module__' : 'ReqGetMss_pb2'
  # @@protoc_insertion_point(class_scope:blink.ReqGetMss)
  })
_sym_db.RegisterMessage(ReqGetMss)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
