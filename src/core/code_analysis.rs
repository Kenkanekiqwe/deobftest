use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
use std::collections::HashSet;
use super::formats::analyze_pe;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableSectionAnalysis {
    pub name: String,
    pub rva: u32,
    pub raw_size: u32,
    pub instruction_count: u64,
    pub invalid_instruction_count: u64,
    pub direct_branch_count: u64,
    pub basic_block_count: u64,
    pub resolved_direct_branch_count: u64,
    pub fallthrough_edge_count: u64,
    pub branch_targets_outside_executable_sections: u64,
    pub branch_targets_not_on_instruction_boundary: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeCodeAnalysis {
    pub machine: u16,
    pub bitness: u32,
    pub executable_sections: Vec<ExecutableSectionAnalysis>,
    pub instruction_count: u64,
    pub invalid_instruction_count: u64,
    pub direct_branch_count: u64,
    pub basic_block_count: u64,
    pub resolved_direct_branch_count: u64,
    pub fallthrough_edge_count: u64,
    pub branch_targets_outside_executable_sections: u64,
    pub branch_targets_not_on_instruction_boundary: u64,
    pub notes: Vec<String>,
}

#[derive(Debug)]
struct SectionPass {
    report: ExecutableSectionAnalysis,
    instruction_offsets: HashSet<u64>,
    direct_targets: Vec<u64>,
}

/// Bounded linear-sweep disassembly of initialized executable PE sections.
/// Analysis only: the input is never modified. Embedded data, padding, jump tables,
/// and overlapping code can affect linear-sweep counts, so findings are diagnostic.
pub fn analyze_pe_code(data: &[u8]) -> Result<PeCodeAnalysis> {
    let pe = analyze_pe(data).context("PE structural analysis failed")?;
    let bitness = match pe.info.machine {
        IMAGE_FILE_MACHINE_I386 => 32,
        IMAGE_FILE_MACHINE_AMD64 => 64,
        machine => bail!("instruction analysis supports x86/x64 PE only; machine=0x{machine:04x}"),
    };

    let mut passes = Vec::new();
    for section in pe.sections.iter().filter(|s| {
        s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && s.raw_size != 0
    }) {
        let start = section.raw_offset as usize;
        let end = start.checked_add(section.raw_size as usize)
            .context("executable section range overflow")?;
        let bytes = data.get(start..end)
            .with_context(|| format!("executable section {} extends beyond file", section.name))?;
        let mut decoder = Decoder::with_ip(
            bitness, bytes, section.virtual_address as u64, DecoderOptions::NONE,
        );
        let mut report = ExecutableSectionAnalysis {
            name: section.name.clone(), rva: section.virtual_address, raw_size: section.raw_size,
            instruction_count: 0, invalid_instruction_count: 0, direct_branch_count: 0,
            basic_block_count: 0, resolved_direct_branch_count: 0, fallthrough_edge_count: 0,
            branch_targets_outside_executable_sections: 0,
            branch_targets_not_on_instruction_boundary: 0,
        };
        let mut instruction_offsets = HashSet::new();
        let mut direct_targets = Vec::new();
        let mut instructions = Vec::new();

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.len() == 0 {
                bail!("decoder made no progress in executable section {}", section.name);
            }
            report.instruction_count += 1;
            instruction_offsets.insert(instruction.ip());
            if instruction.is_invalid() {
                report.invalid_instruction_count += 1;
                instructions.push((instruction.ip(), instruction.next_ip(), FlowControl::Next, None));
                continue;
            }
            let flow = instruction.flow_control();
            let has_direct_target = matches!(
                flow, FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) && matches!(
                instruction.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            );
            let target = if has_direct_target {
                report.direct_branch_count += 1;
                let target = instruction.near_branch_target();
                direct_targets.push(target);
                Some(target)
            } else { None };
            instructions.push((instruction.ip(), instruction.next_ip(), flow, target));
        }
        let local_boundaries: HashSet<u64> = instructions.iter().map(|i| i.0).collect();
        let mut leaders = HashSet::new();
        if let Some(first) = instructions.first() { leaders.insert(first.0); }
        for (idx, (_, next_ip, flow, target)) in instructions.iter().enumerate() {
            if let Some(target) = target {
                if local_boundaries.contains(target) { leaders.insert(*target); }
            }
            if matches!(flow, FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Return | FlowControl::IndirectBranch) {
                if instructions.get(idx + 1).is_some() { leaders.insert(*next_ip); }
            }
            if matches!(flow, FlowControl::ConditionalBranch | FlowControl::Call | FlowControl::IndirectCall) && instructions.get(idx + 1).is_some() {
                report.fallthrough_edge_count += 1;
            }
        }
        report.basic_block_count = leaders.len() as u64;
        passes.push(SectionPass { report, instruction_offsets, direct_targets });
    }

    let all_boundaries: HashSet<u64> = passes.iter()
        .flat_map(|pass| pass.instruction_offsets.iter().copied()).collect();
    let executable_ranges: Vec<(u64, u64)> = passes.iter().map(|pass| {
        let start = pass.report.rva as u64;
        (start, start.saturating_add(pass.report.raw_size as u64))
    }).collect();

    for pass in &mut passes {
        for target in &pass.direct_targets {
            let in_executable_section = executable_ranges.iter()
                .any(|(start, end)| *target >= *start && *target < *end);
            if !in_executable_section {
                pass.report.branch_targets_outside_executable_sections += 1;
            } else if !all_boundaries.contains(target) {
                pass.report.branch_targets_not_on_instruction_boundary += 1;
            } else {
                pass.report.resolved_direct_branch_count += 1;
            }
        }
    }

    let mut notes = vec![
        "linear-sweep disassembly of initialized executable section bytes; input is not modified".to_owned(),
        "embedded data, alignment padding, jump tables, and overlapping code can affect linear-sweep counts".to_owned(),
        "branch-target findings are diagnostics, not proof of invalid code or runtime failure".to_owned(),
    ];
    if passes.is_empty() {
        notes.push("no initialized executable sections found".to_owned());
    }
    let executable_sections: Vec<_> = passes.into_iter().map(|pass| pass.report).collect();
    let sum = |f: fn(&ExecutableSectionAnalysis) -> u64| executable_sections.iter().map(f).sum::<u64>();

    Ok(PeCodeAnalysis {
        machine: pe.info.machine, bitness,
        instruction_count: sum(|s| s.instruction_count),
        invalid_instruction_count: sum(|s| s.invalid_instruction_count),
        direct_branch_count: sum(|s| s.direct_branch_count),
        basic_block_count: sum(|s| s.basic_block_count),
        resolved_direct_branch_count: sum(|s| s.resolved_direct_branch_count),
        fallthrough_edge_count: sum(|s| s.fallthrough_edge_count),
        branch_targets_outside_executable_sections: sum(|s| s.branch_targets_outside_executable_sections),
        branch_targets_not_on_instruction_boundary: sum(|s| s.branch_targets_not_on_instruction_boundary),
        executable_sections, notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_x86_pe() -> Vec<u8> {
        let pe = 0x80usize;
        let optional_size = 0xE0usize;
        let section_table = pe + 24 + optional_size;
        let raw_offset = section_table + 40;
        let mut data = vec![0u8; raw_offset + 0x200];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        data[pe..pe + 4].copy_from_slice(b"PE\0\0");
        data[pe + 4..pe + 6].copy_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
        data[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        data[pe + 20..pe + 22].copy_from_slice(&(optional_size as u16).to_le_bytes());
        data[pe + 22..pe + 24].copy_from_slice(&0x0002u16.to_le_bytes());
        let opt = pe + 24;
        data[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        data[opt + 60..opt + 64].copy_from_slice(&(section_table as u32 + 40).to_le_bytes());
        data[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        let section = section_table;
        data[section..section + 8].copy_from_slice(b".text\0\0\0");
        data[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        data[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[section + 20..section + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
        data[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        data[raw_offset..raw_offset + 8].copy_from_slice(&[0x90, 0x90, 0xE9, 0, 0, 0, 0, 0xC3]);
        data
    }

    #[test]
    fn analyzes_x86_executable_section_without_mutating_input() {
        let data = minimal_x86_pe();
        let original = data.clone();
        let report = analyze_pe_code(&data).unwrap();
        assert_eq!(data, original);
        assert_eq!(report.bitness, 32);
        assert_eq!(report.executable_sections.len(), 1);
        assert!(report.instruction_count > 0);
        assert!(report.direct_branch_count >= 1);
        assert!(report.basic_block_count >= 1);
        assert!(report.resolved_direct_branch_count >= 1);
    }

    #[test]
    fn rejects_unsupported_machine_instead_of_guessing_bitness() {
        let mut data = minimal_x86_pe();
        data[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());
        assert!(analyze_pe_code(&data).is_err());
    }
}
