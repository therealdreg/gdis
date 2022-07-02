#!/usr/bin/env python3

# MIT LICENSE - gdis
# -
# Copyright (c) 2022 - Dreg - dreg@fr33project.org
# https://www.fr33project.org - https://github.com/therealdreg
# -
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# -
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# -
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# -
# WARNING: the crappiest code in the world

import gdb
import sys


def get_print_fnc():
    if "gef_print" in globals():
        return gef_print
    return print


class GaidAddresses:
    addresses = []

    @staticmethod
    def to_string():
        str = ""
        for e in GaidAddresses.addresses:
            str += (
                gdb.execute("x/1b 0x%X" % e, False, True).strip().replace(":", " :")
                + "\n"
            )
        return str

    @staticmethod
    def add(addresses):
        GaidAddresses.addresses = list(set(GaidAddresses.addresses) | set(addresses))
        GaidAddresses.addresses.sort()

    @staticmethod
    def delete(addresses):
        GaidAddresses.addresses = list(set(GaidAddresses.addresses) - set(addresses))
        GaidAddresses.addresses.sort()


class Ghelp(gdb.Command):
    def __init__(self):
        super(Ghelp, self).__init__("ghelp", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        help = """
ghelp : shows this help
gdis : disas from $pc
gdis address/symbol : disas from address. ex: gdis _start
gdis address/symbol 0xNR_LINES : disas NR_LINES from address. NR_LINES must be in hex.  ex: gdis 0x401007 0x1C
strz address/symbol : mark string as data. (it search 0x00 as end). 
strz address/symbol -u : delete string as data. (it search 0x00 as end) 
strz : mark the string next to the current instruction ($pc) as data. (it search 0x00 as end). Useful when $pc is on CALL and the string is below 
aws : list all addresses selected as data
awd address/symbol 0xSIZE : mark addresses as data. Size must be in hex. 
awr address/symbol 0xSIZE : delete addresses as data. Size must be in hex. 
awc : delete all addresses from internal db
zsetl 0xNR_LINES : change default lines for gdis command. NR_LINES must be in hex. 
zsetl : restore default lines for gdis command
gtx : shows some context, very handy for raw gdb
finstr 0xMIN_SIZE_STR address/symbol 0xSIZE_TO_SCAN : it searchs all string-null-end, ex: finstr 0x4 $pc 0x100
finstrnz 0xMIN_SIZE_STR address/symbol 0xSIZE_TO_SCAN : it searchs all strings, ex: finstrnz 0x4 $pc 0x100
autostr 0xMIN_SIZE_STR address/symbol 0xSIZE_TO_SCAN : it search and mark as data all strings-null-end. ex: autostr 0x4 $pc 0x100
autostrnz 0xMIN_SIZE_STR address/symbol 0xSIZE_TO_SCAN : it search and mark as data all strings. ex: autostr 0x4 $pc 0x100"""
        if get_print_fnc() == print:
            help += """
unh : remove stop event hook
unh -r : restore stop event hook
hxd address/symbol SIZE : hexdump bytes of address/symbol. SIZE must be in hex. It uses xxd command: sudo apt-get install xxd
pxd address/symbol 0xBYTE1 0xBYTE2 ... : patch address/symbol with BYTES. BYTES must be in 0x hex format """
        get_print_fnc()(help)


class Aws(gdb.Command):
    def __init__(self):
        super(Aws, self).__init__("aws", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        get_print_fnc()(GaidAddresses.to_string())


class Awd(gdb.Command):
    def __init__(self):
        super(Awd, self).__init__("awd", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        addr, size = arg.split(" ")
        addr = Gdis.thing_to_addr(addr)
        size = int(size, 16)
        GaidAddresses.add(list(range(addr, addr + size)))


class Awr(gdb.Command):
    def __init__(self):
        super(Awr, self).__init__("awr", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        addr, size = arg.split(" ")
        addr = Gdis.thing_to_addr(addr)
        size = int(size, 16)
        GaidAddresses.delete(list(range(addr, addr + size)))


class Awc(gdb.Command):
    def __init__(self):
        super(Awc, self).__init__("awc", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        GaidAddresses.addresses = []


class Unh(gdb.Command):
    hook = False

    def __init__(self):
        super(Unh, self).__init__("unh", gdb.COMMAND_USER)

    @staticmethod
    def resh():
        if Unh.hook == False:
            Unh.hook = True
            gdb.events.stop.connect(Gdis.hookev)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        if len(arg):
            if "-r" in arg:
                Unh.resh()
        elif Unh.hook == True:
            gdb.events.stop.disconnect(Gdis.hookev)
            Unh.hook = False


class Strz(gdb.Command):
    def __init__(self):
        super(Strz, self).__init__("strz", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        ins = None
        addr = None
        if len(arg):
            ins = Gdis.disas_ins(arg.strip().split(" ")[0])
            addr = ins["first_addr"]
        else:
            ins = Gdis.disas_ins(None)
            addr = ins["first_addr"] + ins["size_ins"]
        get_print_fnc()("ok, search end string at addr: 0x%X " % addr)
        intiaddr = addr
        curr_b = 0x69
        cnt = 0
        while curr_b != b"\x00":
            curr_b = gdb.inferiors()[0].read_memory(addr, 1).tobytes()
            cnt += 1
            addr += 1
        get_print_fnc()(
            "intiaddr: 0x%X - size str: 0x%X ( end addr 0x%X )" % (intiaddr, cnt, addr)
        )
        if "-u" in arg:
            get_print_fnc()("unselecting area as data")
            gdb.execute("awr 0x%X 0x%X" % (intiaddr, cnt))
        else:
            get_print_fnc()("selecting area as data")
            gdb.execute("awd 0x%X 0x%X" % (intiaddr, cnt))

        get_print_fnc()("new disas after data:")
        gdb.execute("gdis 0x%X" % (intiaddr + cnt))


class Zsetl(gdb.Command):
    def __init__(self):
        super(Zsetl, self).__init__("zsetl", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        if len(arg):
            Gdis.set_lines(int(arg.split(" ")[0], 16))
        else:
            Gdis.set_lines(Gdis.defval)


class Autostr(gdb.Command):
    def __init__(self):
        super(Autostr, self).__init__("autostr", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        out = Finstr.gen(arg)
        get_print_fnc()("mark as data:")
        Finstr.print(out)
        for e in out:
            gdb.execute("awd 0x%X 0x%X" % (e[0], e[2]))
        get_print_fnc()("done!")


class Autostrnz(gdb.Command):
    def __init__(self):
        super(Autostrnz, self).__init__(
            "autostrnz", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL
        )

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        out = Finstrnz.gen(arg)
        get_print_fnc()("mark as data:")
        Finstrnz.print(out)
        for e in out:
            gdb.execute("awd 0x%X 0x%X" % (e[0], e[1]))
        get_print_fnc()("done!")


class Finstrnz(gdb.Command):
    def __init__(self):
        super(Finstrnz, self).__init__(
            "finstrnz", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL
        )

    @staticmethod
    def print(out):
        for e in out:
            size_read = e[1]
            if e[1] > 0x10:
                size_read = 0x10
            preview = gdb.inferiors()[0].read_memory(e[0], size_read).tobytes()
            get_print_fnc()("0x%X 0x%X -> %s...." % (e[0], e[1], preview))

    @staticmethod
    def gen(arg):
        textchars = bytearray(set(range(0x20, 0x7E)))
        addr = ""
        size = 0
        min_size = int(arg.split(" ")[0], 16)
        if len(arg.split(" ")) == 2:
            addr = Gdis.thing_to_addr("$pc")
            size = int(arg.split(" ")[1], 16)
        else:
            addr = Gdis.thing_to_addr(arg.split(" ")[1])
            size = int(arg.split(" ")[2], 16)
        i = 0
        last_cand = addr
        out = []
        while i < size:
            curr_b = gdb.inferiors()[0].read_memory(addr, 1).tobytes()
            if curr_b not in textchars:
                if last_cand == addr:
                    last_cand += 1
                else:
                    if addr - last_cand >= min_size:
                        out.append([last_cand, addr - last_cand])
                    last_cand = addr + 1
            addr += 1
            i += 1
        if addr - last_cand >= min_size:
            out.append([last_cand, addr - last_cand])
        return out

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        out = Finstrnz.gen(arg)
        Finstrnz.print(out)


class Finstr(gdb.Command):
    def __init__(self):
        super(Finstr, self).__init__("finstr", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    @staticmethod
    def print(out):
        for e in out:
            size_read = e[1]
            if e[1] > 0x10:
                size_read = 0x10
            preview = gdb.inferiors()[0].read_memory(e[0], size_read).tobytes()
            get_print_fnc()("0x%X 0x%X 0x%X -> %s...." % (e[0], e[1], e[2], preview))

    @staticmethod
    def gen(arg):
        textchars = bytearray(set(range(0x20, 0x7E)))
        addr = ""
        size = 0
        min_size = int(arg.split(" ")[0], 16)
        if len(arg.split(" ")) == 2:
            addr = Gdis.thing_to_addr("$pc")
            size = int(arg.split(" ")[1], 16)
        else:
            addr = Gdis.thing_to_addr(arg.split(" ")[1])
            size = int(arg.split(" ")[2], 16)
        i = 0
        last_cand = addr
        out = []
        while i < size:
            curr_b = gdb.inferiors()[0].read_memory(addr, 1).tobytes()
            if curr_b == b"\x00":
                if last_cand == addr:
                    last_cand += 1
                else:
                    if addr - last_cand + 1 >= min_size:
                        out.append([last_cand, addr - last_cand, addr - last_cand + 1])
                    last_cand = addr + 1
            elif curr_b not in textchars:
                last_cand += addr + 1
            addr += 1
            i += 1
        return out

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        out = Finstr.gen(arg)
        Finstr.print(out)


class Gtx(gdb.Command):
    def __init__(self):
        super(Gtx, self).__init__("gtx", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        gdb.execute("i r")
        gdb.execute("x/14a $sp")
        Gdis.disas(None)


class Gdis(gdb.Command):

    defval = 12
    lines_asm = 12

    def __init__(self):
        super(Gdis, self).__init__("gdis", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    @staticmethod
    def thing_to_addr(thing):
        return int(
            gdb.execute("x " + thing, False, True)
            .replace(":", " :")
            .strip()
            .split("0x")[1]
            .split(" ")[0],
            16,
        )

    @staticmethod
    def set_lines(lines):
        Gdis.lines_asm = lines

    @staticmethod
    def disas_ins(wht):
        if wht is None:
            wht = "$pc"
        curr_addr = Gdis.thing_to_addr(wht)
        disas = (
            gdb.execute("x/2i " + "0x%X" % curr_addr, False, True)
            .replace(":", " :")
            .strip()
            .split("\n")
        )
        first_addr = int(disas[0][disas[0].find("0x") :].split(" ")[0], 16)
        second_addr = int(disas[1][disas[1].find("0x") :].split(" ")[0], 16)
        size_ins = second_addr - first_addr
        opcodes_bin = gdb.inferiors()[0].read_memory(curr_addr, size_ins).tobytes()
        opcodes = "".join(" 0x%02X" % b for b in opcodes_bin)
        return {
            "disas": disas,
            "first_addr": first_addr,
            "second_addr": second_addr,
            "size_ins": size_ins,
            "opcodes_bin": opcodes_bin,
            "opcodes": opcodes,
        }

    @staticmethod
    def hookev(ev):
        if get_print_fnc() == print:
            gdb.execute("gtx")
        else:
            Gdis.disas(None)

    @staticmethod
    def disstr(wht, nrs):
        if nrs is None:
            nrs = Gdis.lines_asm
        ins = Gdis.disas_ins(wht)
        curr_addr = ins["first_addr"]
        out = ""
        x = nrs
        while nrs > 0:
            ins = Gdis.disas_ins("0x%X" % curr_addr)
            disas = ins["disas"]
            size_ins = ins["size_ins"]
            opcodes_bin = ins["opcodes_bin"]
            opcodes = ins["opcodes"]
            out += disas[0] + "\t | " + opcodes + " --> " + str(opcodes_bin) + "\n"
            curr_addr += size_ins
            last_curr = curr_addr
            while curr_addr in GaidAddresses.addresses:
                curr_addr += 1
            if last_curr != curr_addr:
                if nrs == 1:
                    break
                data = gdb.inferiors()[0].read_memory(last_curr, 20).tobytes()
                out += (
                    "***** skipped data from 0x%X to 0x%X --> %s...."
                    % (last_curr, curr_addr, str(data))
                    + "\n"
                )
                nrs -= 1
            nrs -= 1
        out = "\n".join([ll.rstrip() for ll in out.splitlines() if ll.strip()])
        return out

    @staticmethod
    def disas(wht):
        get_print_fnc()(Gdis.disstr(wht, None))

    @staticmethod
    def gpane():
        get_print_fnc()(Gdis.disstr(None, None))

    @staticmethod
    def gpane_title():
        return "gdis"

    def invoke(self, arg, from_tty):
        if len(arg):
            arg = " ".join(arg.split())

        if len(arg):
            if len(arg.split(" ")) == 1:
                self.disas(arg.split(" ")[0])
            else:
                last = Gdis.lines_asm
                Gdis.set_lines(int(arg.split(" ")[1], 16))
                self.disas(arg.split(" ")[0])
                Gdis.set_lines(last)
        else:
            self.disas(None)


if __name__ == "__main__":
    if sys.version_info[0] == 2:
        get_print_fnc()("Python2 is not supported")
        exit(1)
    if get_print_fnc() == print:
        gdb.execute("set disassembly-flavor intel")
        gdb.execute("set history save on")
        gdb.execute("set history remove-duplicates unlimited")
        gdb.execute("set history size unlimited")
        gdb.execute("set python print-stack full")
        gdb.execute("set print pretty")
        gdb.execute("set pagination off")
        gdb.execute(
            "define hxd\n"
            "dump binary memory dump.bin $arg0 $arg0+$arg1\n"
            "shell xxd -g 1 dump.bin\n"
            "end\n"
        )
        gdb.execute(
            "define pxd\n"
            "print $argc - 1\n"
            "set $i = 1\n"
            "set $cur_addr = $arg0\n"
            "while $i < $argc\n"
            'eval "set {char[1]} $cur_addr = {$arg%d}", $i\n'
            "set $i = $i + 1\n"
            "set $cur_addr = $cur_addr + 1\n"
            "end\n"
            "end\n"
        )
        Unh.resh()
    else:
        register_external_context_pane("gdis", Gdis.gpane, Gdis.gpane_title)

    Ghelp()
    Gdis()
    Aws()
    Awd()
    Awr()
    Awc()
    Strz()
    Zsetl()
    Gtx()
    Unh()
    Finstr()
    Finstrnz()
    Autostr()
    Autostrnz()
