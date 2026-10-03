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
    pub branch_targets_outside_executable_sections: u64,
    pub branch_targets_not_on_instruction_boundary: u64,
    pub notes: Vec<String>,
}

#[derive(Debug)]
struct SectionPass {
    report: ExecutableSectionAnalysis,
    instruction_offsets: HashSet<u64>,
    direct_targets: Vec<u64>,
    start: u64,
    end: u64,
}

/// Perform a bounded linear-sweep disassembly of initialized executable PE sections.
///
/// This is analysis only: it never modifies the input. Linear sweep is not a full
/// control-flow-graph reconstruction and may interpret embedded data or padding as
/// instructions; the report deliberately exposes counts rather than claiming proof
/// that every decoded instruction is reachable.
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

        let mut decoder = Decoder::with_ip(bitness, bytes, section.virtual_address as u64, DecoderOptions::NONE);
        let mut report = ExecutableSectionAnalysis {
            name: section.name.clone(),
            rva: section.virtual_address,
            raw_size: section.raw_size,
            instruction_count: 0,
            invalid_instruction_count: 0,
            direct_branch_count: 0,
            branch_targets_outside_executable_sections: 0,
            branch_targets_not_on_instruction_boundary: 0,
        };
        let mut instruction_offsets = HashSet::new();
        let mut direct_targets = Vec::new();

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.len() == 0 {
                bail!("decoder made no progress in executable section {}", section.name);
            }
            report.instruction_count += 1;
            instruction_offsets.insert(instruction.ip());

            if instruction.is_invalid() {
                report.invalid_instruction_count += 1;
                continue;
            }

            let flow = instruction.flow_control();
            let has_direct_target = matches!(
                flow,
                FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) && matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            );

            if has_direct_target {
                report.direct_branch_count += 1;
                direct_targets.push(instruction.near_branch_target());
            }
        }

        passes.push(SectionPass {
            report,
            instruction_offsets,
            direct_targets,
            start: section.virtual_address as u64,
            end: (section.virtual_address as u64).saturating_add(section.raw_size as u64),
        });
    }

    let all_boundaries: HashSet<u64> = passes.iter()
        .flat_map(|pass| pass.instruction_offsets.iter().copied())
        .collect();

    for pass in &mut passes {
        for target in &pass.direct_targets {
            let in_executable_section = passes_range_contains(&passes, *target);
            if !in_executable_section {
                pass.report.branch_targets_outside_executable_sections += 1;
            } else if !all_boundaries.contains(target) {
                pass.report.branch_targets_not_on_instruction_boundary += 1;
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
    let sum = |f: fn(&ExecutableSectionAnalysis) -> u64| {
        executable_sections.iter().map(f).sum::<u64>()
    };

    Ok(PeCodeAnalysis {
        machine: pe.info.machine,
        bitness,
        instruction_count: sum(|s| s.instruction_count),
        invalid_instruction_count: sum(|s| s.invalid_instruction_count),
        direct_branch_count: sum(|s| s.direct_branch_count),
        branch_targets_outside_executable_sections: sum(|s| s.branch_targets_outside_executable_sections),
        branch_targets_not_on_instruction_boundary: sum(|s| s.branch_targets_not_on_instruction_boundary),
        executable_sections,
        notes,
    })
}

fn passes_range_contains(passes: &[SectionPass], target: u64) -> bool {
    passes.iter().any(|pass| target >= pass.start && target < pass.end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::formats::pe_debug_tests::minimal_pe;

    #[test]
    fn analyzes_x86_executable_section_without_mutating_input() {
        let mut data = minimal_pe(false);
        let section_table = 0x80 + 24 + 0xE0;
        let raw_offset = u32::from_le_bytes(data[section_table + 20..section_table + 24].try_into().unwrap()) as usize;
        data[raw_offset..raw_offset + 8].copy_from_slice(&[0x90, 0x90, 0xE9, 0, 0, 0, 0, 0xC3]);
        let original = data.clone();

        let report = analyze_pe_code(&data).unwrap();

        assert_eq!(data, original);
        assert_eq!(report.bitness, 32);
        assert_eq!(report.executable_sections.len(), 1);
        assert!(report.instruction_count > 0);
        assert!(report.direct_branch_count >= 1);
    }

    #[test]
    fn rejects_unsupported_machine_instead_of_guessing_bitness() {
        let mut data = minimal_pe(false);
        data[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());
        assert!(analyze_pe_code(&data).is_err());
    }
}
