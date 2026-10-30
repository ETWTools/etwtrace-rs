//! The classic (MOF) event GUIDs and opcodes EtwTrace records, reads and writes.  Kernel events are identified by
//! their event class GUID (the EVENT_RECORD's ProviderId) and opcode (the event type).

use etw::Guid;

pub const EVENT_TRACE: Guid = Guid::from_u128(0x68fd_d900_4a3e_11d1_84f4_0000_f804_64e3);
pub const PROCESS: Guid = Guid::from_u128(0x3d6f_a8d0_fe05_11d0_9dda_00c0_4fd7_ba7c);
pub const THREAD: Guid = Guid::from_u128(0x3d6f_a8d1_fe05_11d0_9dda_00c0_4fd7_ba7c);
/// Page faults, hard faults, VirtualAlloc, memory info and reference set events.
pub const PAGE_FAULT: Guid = Guid::from_u128(0x3d6f_a8d3_fe05_11d0_9dda_00c0_4fd7_ba7c);
pub const DISK_IO: Guid = Guid::from_u128(0x3d6f_a8d4_fe05_11d0_9dda_00c0_4fd7_ba7c);
pub const IMAGE: Guid = Guid::from_u128(0x2cb1_5d1d_5fc1_11d2_abe1_00a0_c911_f518);
pub const PERF_INFO: Guid = Guid::from_u128(0xce1d_bfb4_137e_4da6_87b0_3f59_aa10_2cbc);
pub const STACK_WALK: Guid = Guid::from_u128(0xdef2_fe46_7bd6_4b80_bd94_f57f_e20d_0ce3);
pub const LAST_BRANCH: Guid = Guid::from_u128(0x9913_4383_5248_43fc_834b_5294_54e7_5df3);
pub const REGISTRY: Guid = Guid::from_u128(0xae53_722e_c863_11d2_8659_00c0_4fa3_21a1);
pub const FILE_IO: Guid = Guid::from_u128(0x90cb_dc39_4a3e_11d1_84f4_0000_f804_64e3);
pub const TCP_IP: Guid = Guid::from_u128(0x9a28_0ac0_c8e0_11d1_84e2_00c0_4fb9_98a2);
pub const UDP_IP: Guid = Guid::from_u128(0xbf3a_50c5_a9c9_4988_a005_2df0_b7c8_0f80);
pub const OBJECT: Guid = Guid::from_u128(0x8949_7f50_effe_4440_8cf2_ce6b_1cdc_aca7);
/// The system configuration events KernelTraceControl adds when it merges a trace (drive letters, system paths).
pub const SYS_CONFIG_EX: Guid = Guid::from_u128(0x9b79_ee91_b5fd_41c0_a243_4248_e266_e9d0);
/// Image identity (ImageID, opcode 0) and PDB identity (DbgID_RSDS, opcode 36) events, as KernelTraceControl writes.
pub const KERNEL_TRACE_CONTROL: Guid = Guid::from_u128(0xb3e6_75d7_2554_4f18_830b_2762_7325_60de);
/// Event schemas (TRACE_EVENT_INFO, opcode 32), so traces decode on machines without the providers' manifests.
pub const EVENT_METADATA: Guid = Guid::from_u128(0xbbcc_f6c1_6cd1_48c4_80ff_8394_82e3_7671);
/// Microsoft-Windows-DNS-Client, a manifest provider.
pub const DNS_CLIENT: Guid = Guid::from_u128(0x1c95_126e_7eea_49a9_a3fe_a378_b03d_db4d);

pub const SAMPLED_PROFILE_OPCODE: u8 = 0x2E;
pub const PMC_INTERRUPT_OPCODE: u8 = 0x2F;
pub const CSWITCH_OPCODE: u8 = 0x24;
pub const READY_THREAD_OPCODE: u8 = 0x32;
pub const START_OPCODE: u8 = 0x01;
/// Image loads are hooked (for stacks) in the process group, though they are logged with the image GUID.
pub const IMAGE_LOAD_OPCODE: u8 = 0x0A;
pub const VIRTUAL_ALLOC_OPCODE: u8 = 0x62;
pub const VIRTUAL_FREE_OPCODE: u8 = 0x63;
