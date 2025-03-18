#!/usr/bin/env python3

import re
import sys
import os
import argparse
from collections import defaultdict

def parse_linker_script(file_path):
    """
    Parse a linker script to determine which sections are mapped to which memory regions.
    
    Args:
        file_path: Path to the linker script file
        
    Returns:
        dict: Memory regions and their sizes
        dict: Memory regions and their sections
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None, None, None
    
    # Extract memory regions
    memory_regions = {}
    memory_pattern = re.compile(r'MEMORY\s*{(.*?)}', re.DOTALL)
    memory_match = memory_pattern.search(content)
    
    if memory_match:
        memory_defs = memory_match.group(1)
        region_pattern = re.compile(r'(\w+)\s*\(([\w]+)\)\s*:\s*ORIGIN\s*=\s*(0x[0-9A-Fa-f]+),\s*LENGTH\s*=\s*(\d+[KMG]?)')
        
        for match in region_pattern.finditer(memory_defs):
            name, attributes, origin, length = match.groups()
            
            # Convert length to bytes
            if length.endswith('K'):
                size = int(length[:-1]) * 1024
            elif length.endswith('M'):
                size = int(length[:-1]) * 1024 * 1024
            elif length.endswith('G'):
                size = int(length[:-1]) * 1024 * 1024 * 1024
            else:
                size = int(length)
                
            memory_regions[name] = {
                'attributes': attributes,
                'origin': origin,
                'size': size
            }
    
    # Extract sections and their memory regions
    sections = defaultdict(list)
    section_pattern = re.compile(r'\.([a-zA-Z0-9_]+)\s*(?::|\s+[^>\n]*:)(?:.*?)>([A-Za-z0-9_]+)(?:\s+AT>\s+([A-Za-z0-9_]+))?', re.DOTALL)
    
    for match in section_pattern.finditer(content):
        section_name, target_region, at_region = match.groups()
        if at_region:
            # This section is loaded to one region but stored in another
            sections[target_region].append({
                'name': f".{section_name}",
                'stored_in': at_region,
                'type': 'initialized data'
            })
            # Also add to the stored_in region
            sections[at_region].append({
                'name': f".{section_name}",
                'stored_in': target_region,
                'type': 'initialized data (source)'
            })
        else:
            # This section is only in one region
            sections[target_region].append({
                'name': f".{section_name}",
                'stored_in': None,
                'type': 'code/data'
            })
    
    # Create a flat list of section configurations
    section_configs = {}
    for region, section_list in sections.items():
        for section in section_list:
            section_name = section['name']
            if section_name not in section_configs:
                section_configs[section_name] = {
                    'flash': False,
                    'ram': False
                }
            
            # Mark this section as being in Flash or RAM
            if region == 'FLASH' or section['stored_in'] == 'FLASH':
                section_configs[section_name]['flash'] = True
            if region == 'RAM' or section['stored_in'] == 'RAM':
                section_configs[section_name]['ram'] = True
    
    return memory_regions, dict(sections), section_configs

def parse_objdump_output(objdump_text):
    """Parse the output of arm-none-eabi-objdump -h command."""
    sections = []
    
    # More flexible pattern to match different objdump formats
    section_pattern = re.compile(
        r'\s*\d+\s+'             # Index (any number of spaces, then digits, then spaces)
        r'([.]\S+)\s+'           # Section name (starts with dot)
        r'([0-9a-f]+)\s+'        # Size (hex)
        r'([0-9a-f]+)\s+'        # VMA (hex)
        r'([0-9a-f]+)\s+'        # LMA (hex)
        r'(?:[0-9a-f]+\s+)'      # File offset (hex, non-capturing)
        r'(?:2\*\*\d+\s+)?'      # Optional alignment info (non-capturing)
        r'(.*?)$',               # Flags (everything else)
        re.MULTILINE
    )
    
    matches = list(section_pattern.finditer(objdump_text))
    if not matches:
        print("Warning: No sections matched in objdump output. Using fallback pattern...")
        
        # Fallback pattern - more lenient
        section_pattern = re.compile(
            r'\s*\d+\s+'           # Index
            r'(\.\S+)\s+'          # Section name
            r'([0-9a-f]+)\s+'      # Size
            r'([0-9a-f]+)\s+'      # VMA
            r'([0-9a-f]+)\s+'      # LMA
            r'.*?'                 # Anything in between
            r'([A-Z, ]+)$',        # Flags at end of line
            re.MULTILINE
        )
        matches = list(section_pattern.finditer(objdump_text))
    
    if not matches:
        # Print a portion of the objdump text to help diagnose the issue
        print("Error: Still no sections matched. Sample of objdump text:")
        print(objdump_text[:500])  # Print first 500 chars for debugging
        return []
    
    for match in matches:
        name, size_hex, vma_hex, lma_hex, flags = match.groups()
        
        try:
            # Convert hex to decimal
            size = int(size_hex, 16)
            vma = int(vma_hex, 16)
            lma = int(lma_hex, 16)
            
            # Parse flags
            flags_list = [flag.strip() for flag in flags.split(',')]
            
            sections.append({
                'name': name,
                'size': size,
                'vma': vma,
                'lma': lma,
                'flags': flags_list
            })
        except ValueError as e:
            print(f"Warning: Could not parse section {name}: {e}")
    
    return sections

def calculate_memory_usage(objdump_sections, section_configs, memory_regions):
    """Calculate memory usage based on parsed sections and linker script configurations."""
    # Get total memory sizes
    flash_size = memory_regions.get('FLASH', {}).get('size', 128 * 1024)  # Default 128KB
    ram_size = memory_regions.get('RAM', {}).get('size', 36 * 1024)      # Default 36KB
    
    # Initialize counters
    flash_used = 0
    ram_used = 0
    
    # Track sections by region
    flash_sections = []
    ram_sections = []
    dual_sections = []
    
    # Go through each objdump section
    for section in objdump_sections:
        section_name = section['name']
        section_size = section['size']
        
        # Skip sections that are not allocated
        if 'ALLOC' not in section['flags']:
            continue
        
        # Check if we have configuration for this section
        config = section_configs.get(section_name, {'flash': False, 'ram': False})
        
        # If no config is found, use VMA/LMA address to determine location
        if not config['flash'] and not config['ram']:
            if 0x8000000 <= section['lma'] < 0x8100000:
                config['flash'] = True
            if 0x20000000 <= section['vma'] < 0x20100000:
                config['ram'] = True
        
        # Add to appropriate counters
        if config['flash']:
            flash_used += section_size
            flash_sections.append((section_name, section_size))
        
        if config['ram']:
            ram_used += section_size
            ram_sections.append((section_name, section_size))
        
        if config['flash'] and config['ram']:
            dual_sections.append((section_name, section_size))
    
    # Calculate percentages and free space
    flash_used_percent = (flash_used / flash_size) * 100 if flash_size > 0 else 0
    flash_free = flash_size - flash_used
    flash_free_percent = 100 - flash_used_percent
    
    ram_used_percent = (ram_used / ram_size) * 100 if ram_size > 0 else 0
    ram_free = ram_size - ram_used
    ram_free_percent = 100 - ram_used_percent
    
    return {
        'flash': {
            'total': flash_size,
            'used': flash_used,
            'used_percent': flash_used_percent,
            'free': flash_free,
            'free_percent': flash_free_percent,
            'sections': flash_sections
        },
        'ram': {
            'total': ram_size,
            'used': ram_used,
            'used_percent': ram_used_percent,
            'free': ram_free,
            'free_percent': ram_free_percent,
            'sections': ram_sections
        },
        'dual_sections': dual_sections
    }

def display_memory_layout(memory_regions, sections):
    """Display memory layout information from linker script."""
    print("\n=== MEMORY REGIONS (FROM LINKER SCRIPT) ===")
    for name, details in memory_regions.items():
        print(f"{name} ({details['attributes']}): {details['origin']}, Size: {details['size']/1024:.2f} KB")
    
    print("\n=== SECTIONS MAPPING (FROM LINKER SCRIPT) ===")
    for region, section_list in sections.items():
        print(f"\nRegion: {region}")
        for section in section_list:
            if section['stored_in']:
                print(f"  {section['name']} -> {region} (loaded from {section['stored_in']})")
            else:
                print(f"  {section['name']} -> {region}")

def display_memory_usage(memory_usage):
    """Display memory usage statistics."""
    # Flash usage
    flash = memory_usage['flash']
    print("\n=== FLASH MEMORY USAGE ===")
    print(f"Total: {flash['total']/1024:.2f} KB")
    print(f"Used:  {flash['used']/1024:.2f} KB ({flash['used_percent']:.2f}%)")
    print(f"Free:  {flash['free']/1024:.2f} KB ({flash['free_percent']:.2f}%)")
    
    # RAM usage
    ram = memory_usage['ram']
    print("\n=== RAM MEMORY USAGE ===")
    print(f"Total: {ram['total']/1024:.2f} KB")
    print(f"Used:  {ram['used']/1024:.2f} KB ({ram['used_percent']:.2f}%)")
    print(f"Free:  {ram['free']/1024:.2f} KB ({ram['free_percent']:.2f}%)")
    
    # Visual representation
    print("\n=== MEMORY USAGE VISUALIZATION ===")
    
    # Flash bar
    flash_bar_width = 50
    flash_used_width = int(flash['used_percent'] * flash_bar_width / 100)
    flash_bar = "o" * flash_used_width + "-" * (flash_bar_width - flash_used_width)
    print(f"FLASH: {flash_bar} {flash['used_percent']:.2f}%")
    
    # RAM bar
    ram_bar_width = 50
    ram_used_width = int(ram['used_percent'] * ram_bar_width / 100)
    ram_bar = "o" * ram_used_width + "-" * (ram_bar_width - ram_used_width)
    print(f"RAM:   {ram_bar} {ram['used_percent']:.2f}%")
    
    # Detailed section breakdown
    print("\n=== DETAILED SECTION BREAKDOWN ===")
    print("Section                Size (KB)       Memory Region")
    print("-" * 60)
    
    # Sort sections by size
    all_sections = []
    for section_name, size in memory_usage['flash']['sections']:
        if (section_name, size) in memory_usage['dual_sections']:
            all_sections.append((section_name, size, "FLASH+RAM"))
        else:
            all_sections.append((section_name, size, "FLASH"))
    
    for section_name, size in memory_usage['ram']['sections']:
        if (section_name, size) not in memory_usage['dual_sections']:
            all_sections.append((section_name, size, "RAM"))
    
    # Sort by size, largest first
    all_sections.sort(key=lambda x: x[1], reverse=True)
    
    if all_sections:
        for section_name, size, region in all_sections:
            print(f"{section_name:<20} {size/1024:<15.2f} {region}")
    else:
        print("No sections found or parsed from objdump output")

def main():
    parser = argparse.ArgumentParser(description='Analyze memory usage from linker script and objdump output')
    parser.add_argument('--linker', required=True, help='Path to the linker script')
    parser.add_argument('--objdump', required=True, help='Path to objdump output file')
    parser.add_argument('--debug', action='store_true', help='Show debugging information')
    
    args = parser.parse_args()
    
    # Read linker script
    memory_regions, sections, section_configs = parse_linker_script(args.linker)
    if not memory_regions:
        print("Error parsing linker script")
        return 1
    
    # Display linker script analysis
    display_memory_layout(memory_regions, sections)
    
    # Read objdump output
    try:
        with open(args.objdump, 'r') as f:
            objdump_text = f.read()
    except Exception as e:
        print(f"Error reading objdump file: {e}")
        return 1
    
    # Parse objdump output
    objdump_sections = parse_objdump_output(objdump_text)
    
    if args.debug:
        print("\n=== DEBUG: PARSED OBJDUMP SECTIONS ===")
        for section in objdump_sections:
            print(f"{section['name']}: Size={section['size']}, VMA=0x{section['vma']:x}, LMA=0x{section['lma']:x}, Flags={section['flags']}")
    
    # Calculate and display memory usage
    memory_usage = calculate_memory_usage(objdump_sections, section_configs, memory_regions)
    display_memory_usage(memory_usage)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())