from elftools.elf.elffile import ELFFile

from sys import argv
from collections import defaultdict

from util import u16, u32, c_str, hexdump
from indent import indent, iprint
from elf import ElfParser
from core import CoreParser

str_stop_reason = defaultdict(str, {
    0: "No reason",
    0x30004: "Data abort exception",
})

str_status = defaultdict(str, {
    1: "Running",
    8: "Waiting",
})

str_attr = defaultdict(str, {
    5: "RX",
    6: "RW",
})

reg_names = {
    13: "SP",
    14: "LR",
    15: "PC",
}

core = None

def print_module_info(module):
    iprint(module.name)
    with indent():
        for x, segment in enumerate(module.segments):
            iprint("Segment {}".format(x + 1))
            with indent():
                iprint("Start: 0x{:x}".format(segment.start))
                iprint("Size: 0x{:x} bytes".format(segment.size))
                iprint("Attributes: 0x{:x} ({})".format(segment.attr, str_attr[segment.attr & 0xF]))
                iprint("Alignment: 0x{:x}".format(segment.align))


def print_thread_info(thread):
    iprint(thread.name)
    with indent():
        iprint("ID: 0x{:x}".format(thread.uid))
        iprint("Stop reason: 0x{:x} ({})".format(thread.stop_reason, str_stop_reason[thread.stop_reason]))
        iprint("Status: 0x{:x} ({})".format(thread.status, str_status[thread.status]))
        module, segment, addr = core.vaddr_to_offset(thread.pc)
        iprint("PC: 0x{:x} ({}@{} + 0x{:x})".format(thread.pc, module.name, segment.num, addr))


def main():
    global core
    elf = ElfParser(argv[2])
    core = CoreParser(argv[1])
    # iprint("=== MODULES ===")
    # with indent():
    #     for module in core.modules:
    #         print_module_info(module)
    # iprint()
    iprint("=== THREADS ===")
    crashed = []
    with indent():
        for thread in core.threads:
            if thread.stop_reason != 0:
                crashed.append(thread)
            print_thread_info(thread)
    iprint()
    for thread in crashed:
        iprint('=== THREAD "{}" <0x{:x}> CRASHED ({}) ==='.format(thread.name, thread.uid, str_stop_reason[thread.stop_reason]))

        module, segment, addr = core.vaddr_to_offset(thread.pc)

        if module.name.endswith(".elf"):
            iprint()
            iprint('DISASSEMBLY AROUND 0x{:x}:'.format(thread.pc))
            elf.disas_around_addr(addr)
        else:
            iprint("DISASSEMBLY IS NOT AVAILABLE")

        iprint("REGISTERS:")
        with indent():
            for x in range(15):
                reg = reg_names.get(x, "R{}".format(x))
                iprint("{}: 0x{:x}".format(reg, thread.regs.gpr[x]))
            iprint("PC: 0x{:x} ({}@{} + 0x{:x})".format(thread.pc, module.name, segment.num, addr))
        iprint()

        iprint("STACK CONTENTS AROUND SP:")
        with indent():
            sp = thread.regs.gpr[13]
            for x in range(-4, 0x18):
                addr = 4 * x + sp
                data = core.read_vaddr(addr, 4)
                if data:
                    data = u32(data, 0)
                    prefix = "     "
                    if addr == sp:
                        prefix = "SP =>"
                    suffix = ""
                    module, segment, off = core.vaddr_to_offset(data)
                    if module:
                        suffix = "=> {}@{} + 0x{:x}".format(module.name, segment.num, off)
                        if module.name.endswith(".elf") and segment.num == 1:
                            suffix += " => {}".format(elf.addr2line(off))

                    iprint("{} 0x{:x}: 0x{:x} {}".format(prefix, addr, data, suffix))


if __name__ == "__main__":
    main()
