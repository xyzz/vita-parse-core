from elftools.elf.elffile import ELFFile

from collections import defaultdict
from argparse import ArgumentParser

from util import u16, u32, c_str, hexdump
from indent import indent, iprint
from elf import ElfParser
from core import CoreParser

str_stop_reason = defaultdict(str, {
    0: "No reason",
    0x30002: "Undefined instruction exception",
    0x30003: "Prefetch abort exception",
    0x30004: "Data abort exception",
    0x60080: "Division by zero",
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

isPC = True

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
        if module:
            iprint("PC: 0x{:x} ({}@{} + 0x{:x})".format(thread.pc, module.name, segment.num, addr))
        else:
            module, segment, addr = core.vaddr_to_offset(thread.regs.gpr[14])
            iprint("PC: 0x{:x} ".format(thread.pc))
            if module:            
                iprint("LR: 0x{:x} ({}@{} + 0x{:x})".format(thread.regs.gpr[14], module.name, segment.num, addr))

def main():
    global core

    parser = ArgumentParser()
    parser.add_argument("-s", "--stack-size-to-print", dest="stacksize",
                        type=int, help="Number of addresses of the stack to print", metavar="SIZE", default=24)
    parser.add_argument("corefile")
    parser.add_argument("elffile")
    args = parser.parse_args()
    stackSize = args.stacksize

    elf = ElfParser(args.elffile)
    core = CoreParser(args.corefile)
    isPC = True
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

        if module and module.name.endswith(".elf"):
            iprint()
            iprint('DISASSEMBLY AROUND PC: 0x{:x}:'.format(thread.pc))
            elf.disas_around_addr(addr)
        module, segment, addr = core.vaddr_to_offset(thread.regs.gpr[14])
        if module and module.name.endswith(".elf"):
            iprint()
            iprint('DISASSEMBLY AROUND LR: 0x{:x}:'.format(thread.regs.gpr[14]))
            elf.disas_around_addr(addr)
            isPC = False
        else:
            iprint("DISASSEMBLY IS NOT AVAILABLE")

        iprint("REGISTERS:")
        with indent():
            for x in range(14):
                reg = reg_names.get(x, "R{}".format(x))
                iprint("{}: 0x{:x}".format(reg, thread.regs.gpr[x]))
            if module and isPC:
                reg = reg_names.get(14, "R{}".format(14))
                iprint("{}: 0x{:x}".format(reg, thread.regs.gpr[14]))
                iprint("PC: 0x{:x} ({}@{} + 0x{:x})".format(thread.pc, module.name, segment.num, addr))
            elif module:
                reg = reg_names.get(14, "R{}".format(14))
                iprint("{}: 0x{:x} ({}@{} + 0x{:x})".format(reg, thread.regs.gpr[14], module.name, segment.num, addr))
                iprint("PC: 0x{:x} ".format(thread.pc))
            else:
                reg = reg_names.get(14, "R{}".format(14))
                iprint("{}: 0x{:x} ".format(reg, thread.regs.gpr[14]))
                iprint("PC: 0x{:x} ".format(thread.pc))
                
                
        iprint()

        iprint("STACK CONTENTS AROUND SP:")
        with indent():
            sp = thread.regs.gpr[13]
            for x in range(-16, stackSize):
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
