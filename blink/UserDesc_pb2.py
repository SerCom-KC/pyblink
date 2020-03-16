# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: UserDesc.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='UserDesc.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x0eUserDesc.proto\x12\x05\x62link\"7\n\x08UserDesc\x12\x0c\n\x04\x66\x61\x63\x65\x18\x03 \x01(\t\x12\x10\n\x08nickname\x18\x02 \x01(\t\x12\x0b\n\x03uid\x18\x01 \x02(\x04\x42 \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_USERDESC = _descriptor.Descriptor(
  name='UserDesc',
  full_name='blink.UserDesc',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='face', full_name='blink.UserDesc.face', index=0,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nickname', full_name='blink.UserDesc.nickname', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='uid', full_name='blink.UserDesc.uid', index=2,
      number=1, type=4, cpp_type=4, label=2,
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
  serialized_start=25,
  serialized_end=80,
)

DESCRIPTOR.message_types_by_name['UserDesc'] = _USERDESC
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

UserDesc = _reflection.GeneratedProtocolMessageType('UserDesc', (_message.Message,), {
  'DESCRIPTOR' : _USERDESC,
  '__module__' : 'UserDesc_pb2'
  # @@protoc_insertion_point(class_scope:blink.UserDesc)
  })
_sym_db.RegisterMessage(UserDesc)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
