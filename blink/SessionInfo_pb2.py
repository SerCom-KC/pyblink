# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: SessionInfo.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import Msg_pb2 as Msg__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='SessionInfo.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x11SessionInfo.proto\x12\x05\x62link\x1a\tMsg.proto\"\xff\x02\n\x0bSessionInfo\x12\x11\n\tack_seqno\x18\t \x02(\x04\x12\x0e\n\x06\x61\x63k_ts\x18\n \x02(\x04\x12\x10\n\x08\x61t_seqno\x18\x03 \x01(\x04\x12\x10\n\x08\x63\x61n_fold\x18\x0f \x01(\r\x12\x13\n\x0bgroup_cover\x18\x06 \x01(\t\x12\x12\n\ngroup_name\x18\x05 \x01(\t\x12\x12\n\ngroup_type\x18\x0e \x01(\r\x12\x0e\n\x06is_dnd\x18\x08 \x02(\r\x12\x11\n\tis_follow\x18\x07 \x01(\r\x12\x1c\n\x08last_msg\x18\r \x01(\x0b\x32\n.blink.Msg\x12\x11\n\tmax_seqno\x18\x11 \x01(\x04\x12\x14\n\x0cnew_push_msg\x18\x12 \x01(\r\x12\x12\n\nsession_ts\x18\x0b \x02(\x04\x12\x14\n\x0csession_type\x18\x02 \x02(\r\x12\x0f\n\x07setting\x18\x13 \x01(\r\x12\x0e\n\x06status\x18\x10 \x01(\r\x12\x11\n\ttalker_id\x18\x01 \x02(\x04\x12\x0e\n\x06top_ts\x18\x04 \x02(\x04\x12\x14\n\x0cunread_count\x18\x0c \x02(\rB \n\x1e\x63om.bilibili.bplus.im.protobuf'
  ,
  dependencies=[Msg__pb2.DESCRIPTOR,])




_SESSIONINFO = _descriptor.Descriptor(
  name='SessionInfo',
  full_name='blink.SessionInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ack_seqno', full_name='blink.SessionInfo.ack_seqno', index=0,
      number=9, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ack_ts', full_name='blink.SessionInfo.ack_ts', index=1,
      number=10, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='at_seqno', full_name='blink.SessionInfo.at_seqno', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='can_fold', full_name='blink.SessionInfo.can_fold', index=3,
      number=15, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='group_cover', full_name='blink.SessionInfo.group_cover', index=4,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='group_name', full_name='blink.SessionInfo.group_name', index=5,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='group_type', full_name='blink.SessionInfo.group_type', index=6,
      number=14, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='is_dnd', full_name='blink.SessionInfo.is_dnd', index=7,
      number=8, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='is_follow', full_name='blink.SessionInfo.is_follow', index=8,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='last_msg', full_name='blink.SessionInfo.last_msg', index=9,
      number=13, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='max_seqno', full_name='blink.SessionInfo.max_seqno', index=10,
      number=17, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='new_push_msg', full_name='blink.SessionInfo.new_push_msg', index=11,
      number=18, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='session_ts', full_name='blink.SessionInfo.session_ts', index=12,
      number=11, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='session_type', full_name='blink.SessionInfo.session_type', index=13,
      number=2, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='setting', full_name='blink.SessionInfo.setting', index=14,
      number=19, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='status', full_name='blink.SessionInfo.status', index=15,
      number=16, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='talker_id', full_name='blink.SessionInfo.talker_id', index=16,
      number=1, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='top_ts', full_name='blink.SessionInfo.top_ts', index=17,
      number=4, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='unread_count', full_name='blink.SessionInfo.unread_count', index=18,
      number=12, type=13, cpp_type=3, label=2,
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
  serialized_start=40,
  serialized_end=423,
)

_SESSIONINFO.fields_by_name['last_msg'].message_type = Msg__pb2._MSG
DESCRIPTOR.message_types_by_name['SessionInfo'] = _SESSIONINFO
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SessionInfo = _reflection.GeneratedProtocolMessageType('SessionInfo', (_message.Message,), {
  'DESCRIPTOR' : _SESSIONINFO,
  '__module__' : 'SessionInfo_pb2'
  # @@protoc_insertion_point(class_scope:blink.SessionInfo)
  })
_sym_db.RegisterMessage(SessionInfo)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
