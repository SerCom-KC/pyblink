# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ReqGetMsgDndSetting.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='ReqGetMsgDndSetting.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x19ReqGetMsgDndSetting.proto\x12\x05\x62link\"p\n\x13ReqGetMsgDndSetting\x12\x11\n\tgroup_ids\x18\x03 \x03(\x04\x12\x15\n\rgroup_ids_str\x18\x05 \x01(\t\x12\x0f\n\x07own_uid\x18\x01 \x02(\x04\x12\x0c\n\x04uids\x18\x02 \x03(\x04\x12\x10\n\x08uids_str\x18\x04 \x01(\tB \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_REQGETMSGDNDSETTING = _descriptor.Descriptor(
  name='ReqGetMsgDndSetting',
  full_name='blink.ReqGetMsgDndSetting',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='group_ids', full_name='blink.ReqGetMsgDndSetting.group_ids', index=0,
      number=3, type=4, cpp_type=4, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='group_ids_str', full_name='blink.ReqGetMsgDndSetting.group_ids_str', index=1,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='own_uid', full_name='blink.ReqGetMsgDndSetting.own_uid', index=2,
      number=1, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='uids', full_name='blink.ReqGetMsgDndSetting.uids', index=3,
      number=2, type=4, cpp_type=4, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='uids_str', full_name='blink.ReqGetMsgDndSetting.uids_str', index=4,
      number=4, type=9, cpp_type=9, label=1,
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
  serialized_start=36,
  serialized_end=148,
)

DESCRIPTOR.message_types_by_name['ReqGetMsgDndSetting'] = _REQGETMSGDNDSETTING
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ReqGetMsgDndSetting = _reflection.GeneratedProtocolMessageType('ReqGetMsgDndSetting', (_message.Message,), {
  'DESCRIPTOR' : _REQGETMSGDNDSETTING,
  '__module__' : 'ReqGetMsgDndSetting_pb2'
  # @@protoc_insertion_point(class_scope:blink.ReqGetMsgDndSetting)
  })
_sym_db.RegisterMessage(ReqGetMsgDndSetting)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
