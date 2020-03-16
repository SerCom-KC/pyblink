# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ReqGetSessions.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='ReqGetSessions.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x14ReqGetSessions.proto\x12\x05\x62link\"\xab\x01\n\x0eReqGetSessions\x12\x10\n\x08\x62\x65gin_ts\x18\x01 \x01(\x04\x12\x0e\n\x06\x65nd_ts\x18\x02 \x01(\x04\x12\x12\n\ngroup_fold\x18\x06 \x01(\r\x12\x14\n\x0csession_type\x18\x04 \x02(\r\x12\x0c\n\x04size\x18\x03 \x01(\r\x12\x11\n\tsort_rule\x18\x07 \x02(\r\x12\x15\n\rteenager_mode\x18\x08 \x01(\r\x12\x15\n\runfollow_fold\x18\x05 \x01(\rB \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_REQGETSESSIONS = _descriptor.Descriptor(
  name='ReqGetSessions',
  full_name='blink.ReqGetSessions',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='begin_ts', full_name='blink.ReqGetSessions.begin_ts', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='end_ts', full_name='blink.ReqGetSessions.end_ts', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='group_fold', full_name='blink.ReqGetSessions.group_fold', index=2,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='session_type', full_name='blink.ReqGetSessions.session_type', index=3,
      number=4, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='size', full_name='blink.ReqGetSessions.size', index=4,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sort_rule', full_name='blink.ReqGetSessions.sort_rule', index=5,
      number=7, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='teenager_mode', full_name='blink.ReqGetSessions.teenager_mode', index=6,
      number=8, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='unfollow_fold', full_name='blink.ReqGetSessions.unfollow_fold', index=7,
      number=5, type=13, cpp_type=3, label=1,
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
  serialized_start=32,
  serialized_end=203,
)

DESCRIPTOR.message_types_by_name['ReqGetSessions'] = _REQGETSESSIONS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ReqGetSessions = _reflection.GeneratedProtocolMessageType('ReqGetSessions', (_message.Message,), {
  'DESCRIPTOR' : _REQGETSESSIONS,
  '__module__' : 'ReqGetSessions_pb2'
  # @@protoc_insertion_point(class_scope:blink.ReqGetSessions)
  })
_sym_db.RegisterMessage(ReqGetSessions)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)