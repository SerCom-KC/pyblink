# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: RspRelationSync.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import GroupRelation_pb2 as GroupRelation__pb2
from . import FriendRelation_pb2 as FriendRelation__pb2
from . import RelationLog_pb2 as RelationLog__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='RspRelationSync.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x15RspRelationSync.proto\x12\x05\x62link\x1a\x13GroupRelation.proto\x1a\x14\x46riendRelation.proto\x1a\x11RelationLog.proto\"\xc5\x01\n\x0fRspRelationSync\x12*\n\x0b\x66riend_list\x18\x03 \x03(\x0b\x32\x15.blink.FriendRelation\x12\x0c\n\x04\x66ull\x18\x01 \x02(\x05\x12(\n\ngroup_list\x18\x05 \x03(\x0b\x32\x14.blink.GroupRelation\x12)\n\rrelation_logs\x18\x02 \x03(\x0b\x32\x12.blink.RelationLog\x12#\n\x1bserver_relation_oplog_seqno\x18\x04 \x02(\x04\x42 \n\x1e\x63om.bilibili.bplus.im.protobuf'
  ,
  dependencies=[GroupRelation__pb2.DESCRIPTOR,FriendRelation__pb2.DESCRIPTOR,RelationLog__pb2.DESCRIPTOR,])




_RSPRELATIONSYNC = _descriptor.Descriptor(
  name='RspRelationSync',
  full_name='blink.RspRelationSync',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='friend_list', full_name='blink.RspRelationSync.friend_list', index=0,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='full', full_name='blink.RspRelationSync.full', index=1,
      number=1, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='group_list', full_name='blink.RspRelationSync.group_list', index=2,
      number=5, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='relation_logs', full_name='blink.RspRelationSync.relation_logs', index=3,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='server_relation_oplog_seqno', full_name='blink.RspRelationSync.server_relation_oplog_seqno', index=4,
      number=4, type=4, cpp_type=4, label=2,
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
  serialized_start=95,
  serialized_end=292,
)

_RSPRELATIONSYNC.fields_by_name['friend_list'].message_type = FriendRelation__pb2._FRIENDRELATION
_RSPRELATIONSYNC.fields_by_name['group_list'].message_type = GroupRelation__pb2._GROUPRELATION
_RSPRELATIONSYNC.fields_by_name['relation_logs'].message_type = RelationLog__pb2._RELATIONLOG
DESCRIPTOR.message_types_by_name['RspRelationSync'] = _RSPRELATIONSYNC
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

RspRelationSync = _reflection.GeneratedProtocolMessageType('RspRelationSync', (_message.Message,), {
  'DESCRIPTOR' : _RSPRELATIONSYNC,
  '__module__' : 'RspRelationSync_pb2'
  # @@protoc_insertion_point(class_scope:blink.RspRelationSync)
  })
_sym_db.RegisterMessage(RspRelationSync)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
