// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(PartialEq,Clone,Default)]
pub struct AuditTimestamp {
    // message fields
    timestamp: ::std::option::Option<i64>,
    timestamp_frac: ::std::option::Option<i64>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for AuditTimestamp {}

impl AuditTimestamp {
    pub fn new() -> AuditTimestamp {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static AuditTimestamp {
        static mut instance: ::protobuf::lazy::Lazy<AuditTimestamp> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const AuditTimestamp,
        };
        unsafe {
            instance.get(AuditTimestamp::new)
        }
    }

    // required int64 timestamp = 1;

    pub fn clear_timestamp(&mut self) {
        self.timestamp = ::std::option::Option::None;
    }

    pub fn has_timestamp(&self) -> bool {
        self.timestamp.is_some()
    }

    // Param is passed by value, moved
    pub fn set_timestamp(&mut self, v: i64) {
        self.timestamp = ::std::option::Option::Some(v);
    }

    pub fn get_timestamp(&self) -> i64 {
        self.timestamp.unwrap_or(0)
    }

    fn get_timestamp_for_reflect(&self) -> &::std::option::Option<i64> {
        &self.timestamp
    }

    fn mut_timestamp_for_reflect(&mut self) -> &mut ::std::option::Option<i64> {
        &mut self.timestamp
    }

    // required int64 timestamp_frac = 2;

    pub fn clear_timestamp_frac(&mut self) {
        self.timestamp_frac = ::std::option::Option::None;
    }

    pub fn has_timestamp_frac(&self) -> bool {
        self.timestamp_frac.is_some()
    }

    // Param is passed by value, moved
    pub fn set_timestamp_frac(&mut self, v: i64) {
        self.timestamp_frac = ::std::option::Option::Some(v);
    }

    pub fn get_timestamp_frac(&self) -> i64 {
        self.timestamp_frac.unwrap_or(0)
    }

    fn get_timestamp_frac_for_reflect(&self) -> &::std::option::Option<i64> {
        &self.timestamp_frac
    }

    fn mut_timestamp_frac_for_reflect(&mut self) -> &mut ::std::option::Option<i64> {
        &mut self.timestamp_frac
    }
}

impl ::protobuf::Message for AuditTimestamp {
    fn is_initialized(&self) -> bool {
        if self.timestamp.is_none() {
            return false;
        }
        if self.timestamp_frac.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int64()?;
                    self.timestamp = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int64()?;
                    self.timestamp_frac = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.timestamp {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.timestamp_frac {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.timestamp {
            os.write_int64(1, v)?;
        }
        if let Some(v) = self.timestamp_frac {
            os.write_int64(2, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for AuditTimestamp {
    fn new() -> AuditTimestamp {
        AuditTimestamp::new()
    }

    fn descriptor_static(_: ::std::option::Option<AuditTimestamp>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt64>(
                    "timestamp",
                    AuditTimestamp::get_timestamp_for_reflect,
                    AuditTimestamp::mut_timestamp_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt64>(
                    "timestamp_frac",
                    AuditTimestamp::get_timestamp_frac_for_reflect,
                    AuditTimestamp::mut_timestamp_frac_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<AuditTimestamp>(
                    "AuditTimestamp",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for AuditTimestamp {
    fn clear(&mut self) {
        self.clear_timestamp();
        self.clear_timestamp_frac();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for AuditTimestamp {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for AuditTimestamp {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ProgramRun {
    // message fields
    timestamp: ::protobuf::SingularPtrField<AuditTimestamp>,
    arch: ::protobuf::SingularField<::std::string::String>,
    syscall: ::std::option::Option<i32>,
    success: ::std::option::Option<bool>,
    exit: ::std::option::Option<i32>,
    pid: ::std::option::Option<i32>,
    ppid: ::std::option::Option<i32>,
    uid: ::std::option::Option<i32>,
    gid: ::std::option::Option<i32>,
    auid: ::std::option::Option<i32>,
    euid: ::std::option::Option<i32>,
    egid: ::std::option::Option<i32>,
    suid: ::std::option::Option<i32>,
    sgid: ::std::option::Option<i32>,
    fsuid: ::std::option::Option<i32>,
    fsgid: ::std::option::Option<i32>,
    tty: ::protobuf::SingularField<::std::string::String>,
    comm: ::protobuf::SingularField<::std::string::String>,
    exe: ::protobuf::SingularField<::std::string::String>,
    key: ::protobuf::SingularField<::std::string::String>,
    subj: ::protobuf::SingularField<::std::string::String>,
    args: ::protobuf::RepeatedField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ProgramRun {}

impl ProgramRun {
    pub fn new() -> ProgramRun {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ProgramRun {
        static mut instance: ::protobuf::lazy::Lazy<ProgramRun> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ProgramRun,
        };
        unsafe {
            instance.get(ProgramRun::new)
        }
    }

    // required .AuditTimestamp timestamp = 1;

    pub fn clear_timestamp(&mut self) {
        self.timestamp.clear();
    }

    pub fn has_timestamp(&self) -> bool {
        self.timestamp.is_some()
    }

    // Param is passed by value, moved
    pub fn set_timestamp(&mut self, v: AuditTimestamp) {
        self.timestamp = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_timestamp(&mut self) -> &mut AuditTimestamp {
        if self.timestamp.is_none() {
            self.timestamp.set_default();
        }
        self.timestamp.as_mut().unwrap()
    }

    // Take field
    pub fn take_timestamp(&mut self) -> AuditTimestamp {
        self.timestamp.take().unwrap_or_else(|| AuditTimestamp::new())
    }

    pub fn get_timestamp(&self) -> &AuditTimestamp {
        self.timestamp.as_ref().unwrap_or_else(|| AuditTimestamp::default_instance())
    }

    fn get_timestamp_for_reflect(&self) -> &::protobuf::SingularPtrField<AuditTimestamp> {
        &self.timestamp
    }

    fn mut_timestamp_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<AuditTimestamp> {
        &mut self.timestamp
    }

    // required string arch = 2;

    pub fn clear_arch(&mut self) {
        self.arch.clear();
    }

    pub fn has_arch(&self) -> bool {
        self.arch.is_some()
    }

    // Param is passed by value, moved
    pub fn set_arch(&mut self, v: ::std::string::String) {
        self.arch = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_arch(&mut self) -> &mut ::std::string::String {
        if self.arch.is_none() {
            self.arch.set_default();
        }
        self.arch.as_mut().unwrap()
    }

    // Take field
    pub fn take_arch(&mut self) -> ::std::string::String {
        self.arch.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_arch(&self) -> &str {
        match self.arch.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_arch_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.arch
    }

    fn mut_arch_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.arch
    }

    // required int32 syscall = 3;

    pub fn clear_syscall(&mut self) {
        self.syscall = ::std::option::Option::None;
    }

    pub fn has_syscall(&self) -> bool {
        self.syscall.is_some()
    }

    // Param is passed by value, moved
    pub fn set_syscall(&mut self, v: i32) {
        self.syscall = ::std::option::Option::Some(v);
    }

    pub fn get_syscall(&self) -> i32 {
        self.syscall.unwrap_or(0)
    }

    fn get_syscall_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.syscall
    }

    fn mut_syscall_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.syscall
    }

    // required bool success = 4;

    pub fn clear_success(&mut self) {
        self.success = ::std::option::Option::None;
    }

    pub fn has_success(&self) -> bool {
        self.success.is_some()
    }

    // Param is passed by value, moved
    pub fn set_success(&mut self, v: bool) {
        self.success = ::std::option::Option::Some(v);
    }

    pub fn get_success(&self) -> bool {
        self.success.unwrap_or(false)
    }

    fn get_success_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.success
    }

    fn mut_success_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.success
    }

    // required int32 exit = 5;

    pub fn clear_exit(&mut self) {
        self.exit = ::std::option::Option::None;
    }

    pub fn has_exit(&self) -> bool {
        self.exit.is_some()
    }

    // Param is passed by value, moved
    pub fn set_exit(&mut self, v: i32) {
        self.exit = ::std::option::Option::Some(v);
    }

    pub fn get_exit(&self) -> i32 {
        self.exit.unwrap_or(0)
    }

    fn get_exit_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.exit
    }

    fn mut_exit_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.exit
    }

    // required int32 pid = 6;

    pub fn clear_pid(&mut self) {
        self.pid = ::std::option::Option::None;
    }

    pub fn has_pid(&self) -> bool {
        self.pid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_pid(&mut self, v: i32) {
        self.pid = ::std::option::Option::Some(v);
    }

    pub fn get_pid(&self) -> i32 {
        self.pid.unwrap_or(0)
    }

    fn get_pid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.pid
    }

    fn mut_pid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.pid
    }

    // required int32 ppid = 7;

    pub fn clear_ppid(&mut self) {
        self.ppid = ::std::option::Option::None;
    }

    pub fn has_ppid(&self) -> bool {
        self.ppid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_ppid(&mut self, v: i32) {
        self.ppid = ::std::option::Option::Some(v);
    }

    pub fn get_ppid(&self) -> i32 {
        self.ppid.unwrap_or(0)
    }

    fn get_ppid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.ppid
    }

    fn mut_ppid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.ppid
    }

    // required int32 uid = 8;

    pub fn clear_uid(&mut self) {
        self.uid = ::std::option::Option::None;
    }

    pub fn has_uid(&self) -> bool {
        self.uid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_uid(&mut self, v: i32) {
        self.uid = ::std::option::Option::Some(v);
    }

    pub fn get_uid(&self) -> i32 {
        self.uid.unwrap_or(0)
    }

    fn get_uid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.uid
    }

    fn mut_uid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.uid
    }

    // required int32 gid = 9;

    pub fn clear_gid(&mut self) {
        self.gid = ::std::option::Option::None;
    }

    pub fn has_gid(&self) -> bool {
        self.gid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_gid(&mut self, v: i32) {
        self.gid = ::std::option::Option::Some(v);
    }

    pub fn get_gid(&self) -> i32 {
        self.gid.unwrap_or(0)
    }

    fn get_gid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.gid
    }

    fn mut_gid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.gid
    }

    // required int32 auid = 10;

    pub fn clear_auid(&mut self) {
        self.auid = ::std::option::Option::None;
    }

    pub fn has_auid(&self) -> bool {
        self.auid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_auid(&mut self, v: i32) {
        self.auid = ::std::option::Option::Some(v);
    }

    pub fn get_auid(&self) -> i32 {
        self.auid.unwrap_or(0)
    }

    fn get_auid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.auid
    }

    fn mut_auid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.auid
    }

    // required int32 euid = 11;

    pub fn clear_euid(&mut self) {
        self.euid = ::std::option::Option::None;
    }

    pub fn has_euid(&self) -> bool {
        self.euid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_euid(&mut self, v: i32) {
        self.euid = ::std::option::Option::Some(v);
    }

    pub fn get_euid(&self) -> i32 {
        self.euid.unwrap_or(0)
    }

    fn get_euid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.euid
    }

    fn mut_euid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.euid
    }

    // required int32 egid = 12;

    pub fn clear_egid(&mut self) {
        self.egid = ::std::option::Option::None;
    }

    pub fn has_egid(&self) -> bool {
        self.egid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_egid(&mut self, v: i32) {
        self.egid = ::std::option::Option::Some(v);
    }

    pub fn get_egid(&self) -> i32 {
        self.egid.unwrap_or(0)
    }

    fn get_egid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.egid
    }

    fn mut_egid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.egid
    }

    // required int32 suid = 13;

    pub fn clear_suid(&mut self) {
        self.suid = ::std::option::Option::None;
    }

    pub fn has_suid(&self) -> bool {
        self.suid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_suid(&mut self, v: i32) {
        self.suid = ::std::option::Option::Some(v);
    }

    pub fn get_suid(&self) -> i32 {
        self.suid.unwrap_or(0)
    }

    fn get_suid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.suid
    }

    fn mut_suid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.suid
    }

    // required int32 sgid = 14;

    pub fn clear_sgid(&mut self) {
        self.sgid = ::std::option::Option::None;
    }

    pub fn has_sgid(&self) -> bool {
        self.sgid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_sgid(&mut self, v: i32) {
        self.sgid = ::std::option::Option::Some(v);
    }

    pub fn get_sgid(&self) -> i32 {
        self.sgid.unwrap_or(0)
    }

    fn get_sgid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.sgid
    }

    fn mut_sgid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.sgid
    }

    // required int32 fsuid = 15;

    pub fn clear_fsuid(&mut self) {
        self.fsuid = ::std::option::Option::None;
    }

    pub fn has_fsuid(&self) -> bool {
        self.fsuid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_fsuid(&mut self, v: i32) {
        self.fsuid = ::std::option::Option::Some(v);
    }

    pub fn get_fsuid(&self) -> i32 {
        self.fsuid.unwrap_or(0)
    }

    fn get_fsuid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.fsuid
    }

    fn mut_fsuid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.fsuid
    }

    // required int32 fsgid = 16;

    pub fn clear_fsgid(&mut self) {
        self.fsgid = ::std::option::Option::None;
    }

    pub fn has_fsgid(&self) -> bool {
        self.fsgid.is_some()
    }

    // Param is passed by value, moved
    pub fn set_fsgid(&mut self, v: i32) {
        self.fsgid = ::std::option::Option::Some(v);
    }

    pub fn get_fsgid(&self) -> i32 {
        self.fsgid.unwrap_or(0)
    }

    fn get_fsgid_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.fsgid
    }

    fn mut_fsgid_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.fsgid
    }

    // optional string tty = 17;

    pub fn clear_tty(&mut self) {
        self.tty.clear();
    }

    pub fn has_tty(&self) -> bool {
        self.tty.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tty(&mut self, v: ::std::string::String) {
        self.tty = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_tty(&mut self) -> &mut ::std::string::String {
        if self.tty.is_none() {
            self.tty.set_default();
        }
        self.tty.as_mut().unwrap()
    }

    // Take field
    pub fn take_tty(&mut self) -> ::std::string::String {
        self.tty.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_tty(&self) -> &str {
        match self.tty.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_tty_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.tty
    }

    fn mut_tty_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.tty
    }

    // optional string comm = 18;

    pub fn clear_comm(&mut self) {
        self.comm.clear();
    }

    pub fn has_comm(&self) -> bool {
        self.comm.is_some()
    }

    // Param is passed by value, moved
    pub fn set_comm(&mut self, v: ::std::string::String) {
        self.comm = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_comm(&mut self) -> &mut ::std::string::String {
        if self.comm.is_none() {
            self.comm.set_default();
        }
        self.comm.as_mut().unwrap()
    }

    // Take field
    pub fn take_comm(&mut self) -> ::std::string::String {
        self.comm.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_comm(&self) -> &str {
        match self.comm.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_comm_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.comm
    }

    fn mut_comm_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.comm
    }

    // optional string exe = 19;

    pub fn clear_exe(&mut self) {
        self.exe.clear();
    }

    pub fn has_exe(&self) -> bool {
        self.exe.is_some()
    }

    // Param is passed by value, moved
    pub fn set_exe(&mut self, v: ::std::string::String) {
        self.exe = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_exe(&mut self) -> &mut ::std::string::String {
        if self.exe.is_none() {
            self.exe.set_default();
        }
        self.exe.as_mut().unwrap()
    }

    // Take field
    pub fn take_exe(&mut self) -> ::std::string::String {
        self.exe.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_exe(&self) -> &str {
        match self.exe.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_exe_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.exe
    }

    fn mut_exe_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.exe
    }

    // optional string key = 20;

    pub fn clear_key(&mut self) {
        self.key.clear();
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    // Param is passed by value, moved
    pub fn set_key(&mut self, v: ::std::string::String) {
        self.key = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_key(&mut self) -> &mut ::std::string::String {
        if self.key.is_none() {
            self.key.set_default();
        }
        self.key.as_mut().unwrap()
    }

    // Take field
    pub fn take_key(&mut self) -> ::std::string::String {
        self.key.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_key(&self) -> &str {
        match self.key.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_key_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.key
    }

    fn mut_key_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.key
    }

    // optional string subj = 21;

    pub fn clear_subj(&mut self) {
        self.subj.clear();
    }

    pub fn has_subj(&self) -> bool {
        self.subj.is_some()
    }

    // Param is passed by value, moved
    pub fn set_subj(&mut self, v: ::std::string::String) {
        self.subj = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_subj(&mut self) -> &mut ::std::string::String {
        if self.subj.is_none() {
            self.subj.set_default();
        }
        self.subj.as_mut().unwrap()
    }

    // Take field
    pub fn take_subj(&mut self) -> ::std::string::String {
        self.subj.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_subj(&self) -> &str {
        match self.subj.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_subj_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.subj
    }

    fn mut_subj_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.subj
    }

    // repeated string args = 22;

    pub fn clear_args(&mut self) {
        self.args.clear();
    }

    // Param is passed by value, moved
    pub fn set_args(&mut self, v: ::protobuf::RepeatedField<::std::string::String>) {
        self.args = v;
    }

    // Mutable pointer to the field.
    pub fn mut_args(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.args
    }

    // Take field
    pub fn take_args(&mut self) -> ::protobuf::RepeatedField<::std::string::String> {
        ::std::mem::replace(&mut self.args, ::protobuf::RepeatedField::new())
    }

    pub fn get_args(&self) -> &[::std::string::String] {
        &self.args
    }

    fn get_args_for_reflect(&self) -> &::protobuf::RepeatedField<::std::string::String> {
        &self.args
    }

    fn mut_args_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.args
    }
}

impl ::protobuf::Message for ProgramRun {
    fn is_initialized(&self) -> bool {
        if self.timestamp.is_none() {
            return false;
        }
        if self.arch.is_none() {
            return false;
        }
        if self.syscall.is_none() {
            return false;
        }
        if self.success.is_none() {
            return false;
        }
        if self.exit.is_none() {
            return false;
        }
        if self.pid.is_none() {
            return false;
        }
        if self.ppid.is_none() {
            return false;
        }
        if self.uid.is_none() {
            return false;
        }
        if self.gid.is_none() {
            return false;
        }
        if self.auid.is_none() {
            return false;
        }
        if self.euid.is_none() {
            return false;
        }
        if self.egid.is_none() {
            return false;
        }
        if self.suid.is_none() {
            return false;
        }
        if self.sgid.is_none() {
            return false;
        }
        if self.fsuid.is_none() {
            return false;
        }
        if self.fsgid.is_none() {
            return false;
        }
        for v in &self.timestamp {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.timestamp)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.arch)?;
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.syscall = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.success = ::std::option::Option::Some(tmp);
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.exit = ::std::option::Option::Some(tmp);
                },
                6 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.pid = ::std::option::Option::Some(tmp);
                },
                7 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.ppid = ::std::option::Option::Some(tmp);
                },
                8 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.uid = ::std::option::Option::Some(tmp);
                },
                9 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.gid = ::std::option::Option::Some(tmp);
                },
                10 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.auid = ::std::option::Option::Some(tmp);
                },
                11 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.euid = ::std::option::Option::Some(tmp);
                },
                12 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.egid = ::std::option::Option::Some(tmp);
                },
                13 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.suid = ::std::option::Option::Some(tmp);
                },
                14 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.sgid = ::std::option::Option::Some(tmp);
                },
                15 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.fsuid = ::std::option::Option::Some(tmp);
                },
                16 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.fsgid = ::std::option::Option::Some(tmp);
                },
                17 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.tty)?;
                },
                18 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.comm)?;
                },
                19 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.exe)?;
                },
                20 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.key)?;
                },
                21 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.subj)?;
                },
                22 => {
                    ::protobuf::rt::read_repeated_string_into(wire_type, is, &mut self.args)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.timestamp.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(ref v) = self.arch.as_ref() {
            my_size += ::protobuf::rt::string_size(2, &v);
        }
        if let Some(v) = self.syscall {
            my_size += ::protobuf::rt::value_size(3, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.success {
            my_size += 2;
        }
        if let Some(v) = self.exit {
            my_size += ::protobuf::rt::value_size(5, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.pid {
            my_size += ::protobuf::rt::value_size(6, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.ppid {
            my_size += ::protobuf::rt::value_size(7, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.uid {
            my_size += ::protobuf::rt::value_size(8, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.gid {
            my_size += ::protobuf::rt::value_size(9, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.auid {
            my_size += ::protobuf::rt::value_size(10, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.euid {
            my_size += ::protobuf::rt::value_size(11, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.egid {
            my_size += ::protobuf::rt::value_size(12, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.suid {
            my_size += ::protobuf::rt::value_size(13, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.sgid {
            my_size += ::protobuf::rt::value_size(14, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.fsuid {
            my_size += ::protobuf::rt::value_size(15, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.fsgid {
            my_size += ::protobuf::rt::value_size(16, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.tty.as_ref() {
            my_size += ::protobuf::rt::string_size(17, &v);
        }
        if let Some(ref v) = self.comm.as_ref() {
            my_size += ::protobuf::rt::string_size(18, &v);
        }
        if let Some(ref v) = self.exe.as_ref() {
            my_size += ::protobuf::rt::string_size(19, &v);
        }
        if let Some(ref v) = self.key.as_ref() {
            my_size += ::protobuf::rt::string_size(20, &v);
        }
        if let Some(ref v) = self.subj.as_ref() {
            my_size += ::protobuf::rt::string_size(21, &v);
        }
        for value in &self.args {
            my_size += ::protobuf::rt::string_size(22, &value);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.timestamp.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(ref v) = self.arch.as_ref() {
            os.write_string(2, &v)?;
        }
        if let Some(v) = self.syscall {
            os.write_int32(3, v)?;
        }
        if let Some(v) = self.success {
            os.write_bool(4, v)?;
        }
        if let Some(v) = self.exit {
            os.write_int32(5, v)?;
        }
        if let Some(v) = self.pid {
            os.write_int32(6, v)?;
        }
        if let Some(v) = self.ppid {
            os.write_int32(7, v)?;
        }
        if let Some(v) = self.uid {
            os.write_int32(8, v)?;
        }
        if let Some(v) = self.gid {
            os.write_int32(9, v)?;
        }
        if let Some(v) = self.auid {
            os.write_int32(10, v)?;
        }
        if let Some(v) = self.euid {
            os.write_int32(11, v)?;
        }
        if let Some(v) = self.egid {
            os.write_int32(12, v)?;
        }
        if let Some(v) = self.suid {
            os.write_int32(13, v)?;
        }
        if let Some(v) = self.sgid {
            os.write_int32(14, v)?;
        }
        if let Some(v) = self.fsuid {
            os.write_int32(15, v)?;
        }
        if let Some(v) = self.fsgid {
            os.write_int32(16, v)?;
        }
        if let Some(ref v) = self.tty.as_ref() {
            os.write_string(17, &v)?;
        }
        if let Some(ref v) = self.comm.as_ref() {
            os.write_string(18, &v)?;
        }
        if let Some(ref v) = self.exe.as_ref() {
            os.write_string(19, &v)?;
        }
        if let Some(ref v) = self.key.as_ref() {
            os.write_string(20, &v)?;
        }
        if let Some(ref v) = self.subj.as_ref() {
            os.write_string(21, &v)?;
        }
        for v in &self.args {
            os.write_string(22, &v)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ProgramRun {
    fn new() -> ProgramRun {
        ProgramRun::new()
    }

    fn descriptor_static(_: ::std::option::Option<ProgramRun>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<AuditTimestamp>>(
                    "timestamp",
                    ProgramRun::get_timestamp_for_reflect,
                    ProgramRun::mut_timestamp_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "arch",
                    ProgramRun::get_arch_for_reflect,
                    ProgramRun::mut_arch_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "syscall",
                    ProgramRun::get_syscall_for_reflect,
                    ProgramRun::mut_syscall_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "success",
                    ProgramRun::get_success_for_reflect,
                    ProgramRun::mut_success_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "exit",
                    ProgramRun::get_exit_for_reflect,
                    ProgramRun::mut_exit_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "pid",
                    ProgramRun::get_pid_for_reflect,
                    ProgramRun::mut_pid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "ppid",
                    ProgramRun::get_ppid_for_reflect,
                    ProgramRun::mut_ppid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "uid",
                    ProgramRun::get_uid_for_reflect,
                    ProgramRun::mut_uid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "gid",
                    ProgramRun::get_gid_for_reflect,
                    ProgramRun::mut_gid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "auid",
                    ProgramRun::get_auid_for_reflect,
                    ProgramRun::mut_auid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "euid",
                    ProgramRun::get_euid_for_reflect,
                    ProgramRun::mut_euid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "egid",
                    ProgramRun::get_egid_for_reflect,
                    ProgramRun::mut_egid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "suid",
                    ProgramRun::get_suid_for_reflect,
                    ProgramRun::mut_suid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "sgid",
                    ProgramRun::get_sgid_for_reflect,
                    ProgramRun::mut_sgid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "fsuid",
                    ProgramRun::get_fsuid_for_reflect,
                    ProgramRun::mut_fsuid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "fsgid",
                    ProgramRun::get_fsgid_for_reflect,
                    ProgramRun::mut_fsgid_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "tty",
                    ProgramRun::get_tty_for_reflect,
                    ProgramRun::mut_tty_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "comm",
                    ProgramRun::get_comm_for_reflect,
                    ProgramRun::mut_comm_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "exe",
                    ProgramRun::get_exe_for_reflect,
                    ProgramRun::mut_exe_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "key",
                    ProgramRun::get_key_for_reflect,
                    ProgramRun::mut_key_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "subj",
                    ProgramRun::get_subj_for_reflect,
                    ProgramRun::mut_subj_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "args",
                    ProgramRun::get_args_for_reflect,
                    ProgramRun::mut_args_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ProgramRun>(
                    "ProgramRun",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ProgramRun {
    fn clear(&mut self) {
        self.clear_timestamp();
        self.clear_arch();
        self.clear_syscall();
        self.clear_success();
        self.clear_exit();
        self.clear_pid();
        self.clear_ppid();
        self.clear_uid();
        self.clear_gid();
        self.clear_auid();
        self.clear_euid();
        self.clear_egid();
        self.clear_suid();
        self.clear_sgid();
        self.clear_fsuid();
        self.clear_fsgid();
        self.clear_tty();
        self.clear_comm();
        self.clear_exe();
        self.clear_key();
        self.clear_subj();
        self.clear_args();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ProgramRun {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ProgramRun {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct SnitchReport {
    // message fields
    message_type: ::std::option::Option<i32>,
    payload: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for SnitchReport {}

impl SnitchReport {
    pub fn new() -> SnitchReport {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static SnitchReport {
        static mut instance: ::protobuf::lazy::Lazy<SnitchReport> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const SnitchReport,
        };
        unsafe {
            instance.get(SnitchReport::new)
        }
    }

    // required int32 message_type = 1;

    pub fn clear_message_type(&mut self) {
        self.message_type = ::std::option::Option::None;
    }

    pub fn has_message_type(&self) -> bool {
        self.message_type.is_some()
    }

    // Param is passed by value, moved
    pub fn set_message_type(&mut self, v: i32) {
        self.message_type = ::std::option::Option::Some(v);
    }

    pub fn get_message_type(&self) -> i32 {
        self.message_type.unwrap_or(0)
    }

    fn get_message_type_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.message_type
    }

    fn mut_message_type_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.message_type
    }

    // required bytes payload = 2;

    pub fn clear_payload(&mut self) {
        self.payload.clear();
    }

    pub fn has_payload(&self) -> bool {
        self.payload.is_some()
    }

    // Param is passed by value, moved
    pub fn set_payload(&mut self, v: ::std::vec::Vec<u8>) {
        self.payload = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_payload(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.payload.is_none() {
            self.payload.set_default();
        }
        self.payload.as_mut().unwrap()
    }

    // Take field
    pub fn take_payload(&mut self) -> ::std::vec::Vec<u8> {
        self.payload.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_payload(&self) -> &[u8] {
        match self.payload.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_payload_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.payload
    }

    fn mut_payload_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.payload
    }
}

impl ::protobuf::Message for SnitchReport {
    fn is_initialized(&self) -> bool {
        if self.message_type.is_none() {
            return false;
        }
        if self.payload.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.message_type = ::std::option::Option::Some(tmp);
                },
                2 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.payload)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.message_type {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.payload.as_ref() {
            my_size += ::protobuf::rt::bytes_size(2, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.message_type {
            os.write_int32(1, v)?;
        }
        if let Some(ref v) = self.payload.as_ref() {
            os.write_bytes(2, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for SnitchReport {
    fn new() -> SnitchReport {
        SnitchReport::new()
    }

    fn descriptor_static(_: ::std::option::Option<SnitchReport>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "message_type",
                    SnitchReport::get_message_type_for_reflect,
                    SnitchReport::mut_message_type_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "payload",
                    SnitchReport::get_payload_for_reflect,
                    SnitchReport::mut_payload_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<SnitchReport>(
                    "SnitchReport",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for SnitchReport {
    fn clear(&mut self) {
        self.clear_message_type();
        self.clear_payload();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for SnitchReport {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SnitchReport {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x0baudit.proto\"U\n\x0eAuditTimestamp\x12\x1c\n\ttimestamp\x18\x01\
    \x20\x02(\x03R\ttimestamp\x12%\n\x0etimestamp_frac\x18\x02\x20\x02(\x03R\
    \rtimestampFrac\"\xe3\x03\n\nProgramRun\x12-\n\ttimestamp\x18\x01\x20\
    \x02(\x0b2\x0f.AuditTimestampR\ttimestamp\x12\x12\n\x04arch\x18\x02\x20\
    \x02(\tR\x04arch\x12\x18\n\x07syscall\x18\x03\x20\x02(\x05R\x07syscall\
    \x12\x18\n\x07success\x18\x04\x20\x02(\x08R\x07success\x12\x12\n\x04exit\
    \x18\x05\x20\x02(\x05R\x04exit\x12\x10\n\x03pid\x18\x06\x20\x02(\x05R\
    \x03pid\x12\x12\n\x04ppid\x18\x07\x20\x02(\x05R\x04ppid\x12\x10\n\x03uid\
    \x18\x08\x20\x02(\x05R\x03uid\x12\x10\n\x03gid\x18\t\x20\x02(\x05R\x03gi\
    d\x12\x12\n\x04auid\x18\n\x20\x02(\x05R\x04auid\x12\x12\n\x04euid\x18\
    \x0b\x20\x02(\x05R\x04euid\x12\x12\n\x04egid\x18\x0c\x20\x02(\x05R\x04eg\
    id\x12\x12\n\x04suid\x18\r\x20\x02(\x05R\x04suid\x12\x12\n\x04sgid\x18\
    \x0e\x20\x02(\x05R\x04sgid\x12\x14\n\x05fsuid\x18\x0f\x20\x02(\x05R\x05f\
    suid\x12\x14\n\x05fsgid\x18\x10\x20\x02(\x05R\x05fsgid\x12\x10\n\x03tty\
    \x18\x11\x20\x01(\tR\x03tty\x12\x12\n\x04comm\x18\x12\x20\x01(\tR\x04com\
    m\x12\x10\n\x03exe\x18\x13\x20\x01(\tR\x03exe\x12\x10\n\x03key\x18\x14\
    \x20\x01(\tR\x03key\x12\x12\n\x04subj\x18\x15\x20\x01(\tR\x04subj\x12\
    \x12\n\x04args\x18\x16\x20\x03(\tR\x04args\"K\n\x0cSnitchReport\x12!\n\
    \x0cmessage_type\x18\x01\x20\x02(\x05R\x0bmessageType\x12\x18\n\x07paylo\
    ad\x18\x02\x20\x02(\x0cR\x07payload\
";

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
