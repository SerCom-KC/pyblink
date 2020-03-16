# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ProfileContexts.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import CallerProfileContext_pb2 as CallerProfileContext__pb2
from . import UserProfileContext_pb2 as UserProfileContext__pb2
from . import RequestProfileContext_pb2 as RequestProfileContext__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='ProfileContexts.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x15ProfileContexts.proto\x12\x05\x62link\x1a\x1a\x43\x61llerProfileContext.proto\x1a\x18UserProfileContext.proto\x1a\x1bRequestProfileContext.proto\"\xaa\x01\n\x0fProfileContexts\x12\x33\n\x0e\x63\x61ller_profile\x18\x03 \x01(\x0b\x32\x1b.blink.CallerProfileContext\x12\x31\n\x0breq_profile\x18\x02 \x01(\x0b\x32\x1c.blink.RequestProfileContext\x12/\n\x0cuser_profile\x18\x01 \x01(\x0b\x32\x19.blink.UserProfileContextB \n\x1e\x63om.bilibili.bplus.im.protobuf'
  ,
  dependencies=[CallerProfileContext__pb2.DESCRIPTOR,UserProfileContext__pb2.DESCRIPTOR,RequestProfileContext__pb2.DESCRIPTOR,])




_PROFILECONTEXTS = _descriptor.Descriptor(
  name='ProfileContexts',
  full_name='blink.ProfileContexts',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='caller_profile', full_name='blink.ProfileContexts.caller_profile', index=0,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='req_profile', full_name='blink.ProfileContexts.req_profile', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='user_profile', full_name='blink.ProfileContexts.user_profile', index=2,
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
  serialized_start=116,
  serialized_end=286,
)

_PROFILECONTEXTS.fields_by_name['caller_profile'].message_type = CallerProfileContext__pb2._CALLERPROFILECONTEXT
_PROFILECONTEXTS.fields_by_name['req_profile'].message_type = RequestProfileContext__pb2._REQUESTPROFILECONTEXT
_PROFILECONTEXTS.fields_by_name['user_profile'].message_type = UserProfileContext__pb2._USERPROFILECONTEXT
DESCRIPTOR.message_types_by_name['ProfileContexts'] = _PROFILECONTEXTS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ProfileContexts = _reflection.GeneratedProtocolMessageType('ProfileContexts', (_message.Message,), {
  'DESCRIPTOR' : _PROFILECONTEXTS,
  '__module__' : 'ProfileContexts_pb2'
  # @@protoc_insertion_point(class_scope:blink.ProfileContexts)
  })
_sym_db.RegisterMessage(ProfileContexts)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
