# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: RequestProfileContext.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import TracePoint_pb2 as TracePoint__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='RequestProfileContext.proto',
  package='blink',
  syntax='proto2',
  serialized_options=b'\n\036com.bilibili.bplus.im.protobuf',
  serialized_pb=b'\n\x1bRequestProfileContext.proto\x12\x05\x62link\x1a\x10TracePoint.proto\"\xc0\x01\n\x15RequestProfileContext\x12\x11\n\tflag_test\x18\x06 \x01(\x05\x12\x14\n\x0csource_color\x18\x04 \x01(\t\x12\x14\n\x0csource_group\x18\x03 \x01(\t\x12\x13\n\x0bss_trace_id\x18\x01 \x02(\x04\x12\x15\n\rss_trace_id_s\x18\x02 \x02(\t\x12\'\n\x0ctrace_points\x18\x07 \x03(\x0b\x32\x11.blink.TracePoint\x12\x13\n\x0bttl_timeout\x18\x05 \x01(\x05\x42 \n\x1e\x63om.bilibili.bplus.im.protobuf'
  ,
  dependencies=[TracePoint__pb2.DESCRIPTOR,])




_REQUESTPROFILECONTEXT = _descriptor.Descriptor(
  name='RequestProfileContext',
  full_name='blink.RequestProfileContext',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='flag_test', full_name='blink.RequestProfileContext.flag_test', index=0,
      number=6, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='source_color', full_name='blink.RequestProfileContext.source_color', index=1,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='source_group', full_name='blink.RequestProfileContext.source_group', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ss_trace_id', full_name='blink.RequestProfileContext.ss_trace_id', index=3,
      number=1, type=4, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ss_trace_id_s', full_name='blink.RequestProfileContext.ss_trace_id_s', index=4,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='trace_points', full_name='blink.RequestProfileContext.trace_points', index=5,
      number=7, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ttl_timeout', full_name='blink.RequestProfileContext.ttl_timeout', index=6,
      number=5, type=5, cpp_type=1, label=1,
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
  serialized_start=57,
  serialized_end=249,
)

_REQUESTPROFILECONTEXT.fields_by_name['trace_points'].message_type = TracePoint__pb2._TRACEPOINT
DESCRIPTOR.message_types_by_name['RequestProfileContext'] = _REQUESTPROFILECONTEXT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

RequestProfileContext = _reflection.GeneratedProtocolMessageType('RequestProfileContext', (_message.Message,), {
  'DESCRIPTOR' : _REQUESTPROFILECONTEXT,
  '__module__' : 'RequestProfileContext_pb2'
  # @@protoc_insertion_point(class_scope:blink.RequestProfileContext)
  })
_sym_db.RegisterMessage(RequestProfileContext)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
