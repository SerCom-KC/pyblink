# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: HttpHeader.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='HttpHeader.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x10HttpHeader.proto\x12\x05\x62link\"(\n\nHttpHeader\x12\x0b\n\x03key\x18\x01 \x02(\t\x12\r\n\x05value\x18\x02 \x02(\tB \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_HTTPHEADER = _descriptor.Descriptor(
  name='HttpHeader',
  full_name='blink.HttpHeader',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='blink.HttpHeader.key', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='blink.HttpHeader.value', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
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
  serialized_start=27,
  serialized_end=67,
)

DESCRIPTOR.message_types_by_name['HttpHeader'] = _HTTPHEADER
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

HttpHeader = _reflection.GeneratedProtocolMessageType('HttpHeader', (_message.Message,), {
  'DESCRIPTOR' : _HTTPHEADER,
  '__module__' : 'HttpHeader_pb2'
  # @@protoc_insertion_point(class_scope:blink.HttpHeader)
  })
_sym_db.RegisterMessage(HttpHeader)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
