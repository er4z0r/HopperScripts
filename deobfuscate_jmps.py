

class Simplifier(object):

    def __init__(self):
        self.doc = Document.getCurrentDocument()
        self.ea = self.doc.getCurrentAddress()
        self.errorStatus = 'Good'
        currseg =self.doc.getCurrentSegment()
        self.funcStartAddr = currseg.getNextAddressWithType(currseg.getStartingAddress(),Segment.TYPE_PROCEDURE)
        self.checkFunctionStart()
        self.buffer = []
        self.count = 0
        self.registers = ['eax', 'ax', 'ah', 'al', 'ebx', 'bx', 'bh', 'bl', 'ecx', 'cx', 'ch', 'cl', 'edx', 'dx', 'dh', 'dl','ebp','esp','bp','sp','edi','di','esi','si']
        self.condJmps = ['jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jz', \
                                'je', 'jnz', 'jne', 'jbe', 'jna', 'jnbe', 'ja', 'js', 'jns', \
                                'jp', 'jpe', 'jnp', 'jpo', 'jl', 'jnge', 'jnl', 'jge', 'jle', \
                                'jng', 'jnle', 'jg']
        self.condJmpsAddr = set([])
        self.retn = ['retn', 'ret', 'retf']
        self.callAddr = set([])
        self.call = 'call'
        self.callByte = 0xe8
        self.jmp = 'jmp'
        self.visitedAddr = set([])
        self.target = set([])


    def formatInstruction(self, instruction):
        retval = instruction.getInstructionString()+", "
        if instruction.getArgumentCount():
            for i in range(instruction.getArgumentCount()):
                retval += instruction.getFormattedArgument(i) + " "
        return retval

    def formatLine(self,addr):
        'format the line to mimic IDA layout'
        inst =  self.doc.getCurrentSegment().getInstructionAtAddress(addr)
        return "%s : %s " % (hex(addr),self.formatInstruction(inst))


    def checkAddr(self,addr):
        'checks if the address is valid'
        if addr == Segment.BAD_ADDRESS or not addr:
            print "Could not find find function start address"
            self.errorStatus = 'Bad!'
            return False
        return True

    def checkFunctionStart(self):
        'checks if the address is valid'
        if self.funcStartAddr is Segment.BAD_ADDRESS:
            print "Could not find find function start address"
            self.errorStatus = 'Bad!'
            return False
        return True

    def getCur(self, addr):
        "returns address, dissasembly, the mnemoic and byte"
        if self.checkAddr(addr):
            print "GetCur: %s (%s )" % (addr,type(addr))
            seg = self.doc.getSegmentAtAddress(addr)
            return self.doc.getCurrentAddress(), seg.getInstructionAtAddress(addr), seg.getInstructionAtAddress(addr), seg.readByte(addr)

    def getNext(self, addr):
        "returns the next address and instructions"
        seg = self.doc.getSegmentAtAddress(addr)
        inst_len = seg.getInstructionAtAddress(addr).getInstructionLength()
        next_addr = addr+inst_len
        print "Next addr: %s (%s) " % (next_addr,type(next_addr))
        return next_addr, seg.getInstructionAtAddress(next_addr), seg.getInstructionAtAddress(next_addr), seg.readByte(next_addr)

    def getJmpAddress(self, jmp_addr):
        "returns the address the JMP instruction jumps to"
        seg = self.doc.getSegmentAtAddress(jmp_addr)
        jmp_instr = seg.getInstructionAtAddress(jmp_addr)
        target = jmp_instr.getRawArgument(0)
        print "%s: %s --> %s (%s)" % (jmp_addr, jmp_instr.getInstructionString(),target,type(target))
        if target not in self.registers:
            return int(target,16)
        else:
            return Segment.BAD_ADDRESS

    def getCallAddress(self, call_addr):
        "return the address the CALL instruction calls"
        call_instr.getRawArgument(0)

    def printBuffer(self):
        'print the buffer that contains the instructions minus jmps'
        print "=== Simplified Code ==="
        for l in self.buffer:
            print l
        print "======================="

    def simplify(self, addr, target = list([]) ):
        # check if valid addresss
        if addr in self.visitedAddr:
            return
        else:
            current_addr, current_inst, current_mnem, byte = self.getCur(addr)
            temp = current_addr
            self.buffer.append('__start: %s' % hex(temp))
            while(1):
                self.checkAddr(current_addr)
                if self.errorStatus != 'Good':
                    return
                if current_mnem.isAnInconditionalJump(): #if unconditional jmp
                    print "Found a JMP @%s" % (hex(current_addr))
                    # uncomment if you want to see the jmp instruction in the output
                    #self.buffer.append(self.formatLine(current_addr))
                    jmpAddr = self.getJmpAddress(current_addr)
                    self.visitedAddr.add(current_addr)
                    current_addr, current_inst, current_mnem, byte = self.getCur(jmpAddr)
                    continue
                # check for conditonal jmps, if so add to the target aka come back to list
                elif current_mnem.isAConditionalJump():
                    print "Found a Jcc @%s" % (hex(current_addr))
                    self.buffer.append(self.formatLine(current_addr))
                    jmpAddr = self.getJmpAddress(current_addr)
                    target.append(jmpAddr)
                # if call, we will need the call address
                elif current_mnem.getInstructionString() in self.call and byte == self.callByte:
                    print "Found a CALL @%s" % (hex(current_addr))
                    self.buffer.append(self.formatLine(current_addr))
                    target.append(self.getCallAddress(current_addr))
                else:
                    self.buffer.append(self.formatLine(current_addr))

                if current_mnem.getInstructionString() in self.retn or current_addr in self.visitedAddr:
                    break
                self.visitedAddr.add(current_addr)
                current_addr, current_inst, current_mnem, byte = self.getNext(current_addr)

            self.buffer.append('__end: %s ' % hex(temp))
            self.buffer.append('')
            for revisit in target:
                if revisit in self.visitedAddr:
                    continue
                else:
                    self.simplify(revisit, target)

        return

simp = Simplifier()
simp.simplify(Document.getCurrentDocument().getCurrentAddress())
simp.printBuffer()
