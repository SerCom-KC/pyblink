# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: Msg.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='Msg.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\tMsg.proto\x12\x05\x62link\"\xc4\x02\n\x03Msg\x12\x0f\n\x07\x61t_uids\x18\t \x03(\x04\x12\x12\n\ncli_msg_id\x18\x04 \x01(\x04\x12\x0f\n\x07\x63ontent\x18\x06 \x01(\t\x12\x15\n\ris_multi_chat\x18\x0e \x01(\r\x12\x0f\n\x07msg_key\x18\x0b \x01(\x04\x12\x11\n\tmsg_seqno\x18\x07 \x01(\x04\x12\x12\n\nmsg_status\x18\x0c \x01(\r\x12\x10\n\x08msg_type\x18\x05 \x01(\x05\x12\x13\n\x0bnotify_code\x18\x10 \x01(\t\x12\x13\n\x0breceiver_id\x18\x03 \x01(\x04\x12\x15\n\rreceiver_type\x18\x02 \x01(\x05\x12\x12\n\nrecver_ids\x18\n \x03(\x04\x12\x12\n\nsender_uid\x18\x01 \x01(\x04\x12\x12\n\nsys_cancel\x18\r \x01(\x08\x12\x11\n\ttimestamp\x18\x08 \x01(\x04\x12\x16\n\x0ewithdraw_seqno\x18\x0f \x01(\x04\x42 \n\x1e\x63om.bilibili.bplus.im.protobuf'
)




_MSG = _descriptor.Descriptor(
  name='Msg',
  full_name='blink.Msg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='at_uids', full_name='blink.Msg.at_uids', index=0,
      number=9, type=4, cpp_type=4, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cli_msg_id', full_name='blink.Msg.cli_msg_id', index=1,
      number=4, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='content', full_name='blink.Msg.content', index=2,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='is_multi_chat', full_name='blink.Msg.is_multi_chat', index=3,
      number=14, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='msg_key', full_name='blink.Msg.msg_key', index=4,
      number=11, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='msg_seqno', full_name='blink.Msg.msg_seqno', index=5,
      number=7, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='msg_status', full_name='blink.Msg.msg_status', index=6,
      number=12, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='msg_type', full_name='blink.Msg.msg_type', index=7,
      number=5, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='notify_code', full_name='blink.Msg.notify_code', index=8,
      number=16, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver_id', full_name='blink.Msg.receiver_id', index=9,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver_type', full_name='blink.Msg.receiver_type', index=10,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='recver_ids', full_name='blink.Msg.recver_ids', index=11,
      number=10, type=4, cpp_type=4, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sender_uid', full_name='blink.Msg.sender_uid', index=12,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sys_cancel', full_name='blink.Msg.sys_cancel', index=13,
      number=13, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='blink.Msg.timestamp', index=14,
      number=8, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='withdraw_seqno', full_name='blink.Msg.withdraw_seqno', index=15,
      number=15, type=4, cpp_type=4, label=1,
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
  serialized_start=21,
  serialized_end=345,
)

DESCRIPTOR.message_types_by_name['Msg'] = _MSG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Msg = _reflection.GeneratedProtocolMessageType('Msg', (_message.Message,), {
  'DESCRIPTOR' : _MSG,
  '__module__' : 'Msg_pb2'
  # @@protoc_insertion_point(class_scope:blink.Msg)
  })
_sym_db.RegisterMessage(Msg)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
