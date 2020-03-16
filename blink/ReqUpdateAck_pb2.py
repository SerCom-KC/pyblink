# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ReqUpdateAck.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='ReqUpdateAck.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x12ReqUpdateAck.proto\x12\x05\x62link\"J\n\x0cReqUpdateAck\x12\x11\n\tack_seqno\x18\x03 \x02(\x04\x12\x14\n\x0csession_type\x18\x02 \x02(\r\x12\x11\n\ttalker_id\x18\x01 \x02(\x04\x42 \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_REQUPDATEACK = _descriptor.Descriptor(
  name='ReqUpdateAck',
  full_name='blink.ReqUpdateAck',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ack_seqno', full_name='blink.ReqUpdateAck.ack_seqno', index=0,
      number=3, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='session_type', full_name='blink.ReqUpdateAck.session_type', index=1,
      number=2, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='talker_id', full_name='blink.ReqUpdateAck.talker_id', index=2,
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
  serialized_start=29,
  serialized_end=103,
)

DESCRIPTOR.message_types_by_name['ReqUpdateAck'] = _REQUPDATEACK
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ReqUpdateAck = _reflection.GeneratedProtocolMessageType('ReqUpdateAck', (_message.Message,), {
  'DESCRIPTOR' : _REQUPDATEACK,
  '__module__' : 'ReqUpdateAck_pb2'
  # @@protoc_insertion_point(class_scope:blink.ReqUpdateAck)
  })
_sym_db.RegisterMessage(ReqUpdateAck)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)