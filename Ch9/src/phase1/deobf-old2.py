import traceback;

from capstone import *;
from capstone.x86 import *;

def readUIntLE(buf, offset, bsize):
  return int.from_bytes(buf[offset : (offset + bsize)], 'little', signed = False);
#end-def

def readUInt16LE(buf, offset):
  return readUIntLE(buf, offset, 2);
#end-def

def readUInt32LE(buf, offset):
  return readUIntLE(buf, offset, 4);
#end-def

def readUInt64LE(buf, offset):
  return readUIntLE(buf, offset, 8);
#end-def

def readIntLE(buf, offset, bsize):
  return int.from_bytes(buf[offset : (offset + bsize)], 'little', signed = True);
#end-def

def readInt32LE(buf, offset):
  return readIntLE(buf, offset, 4);
#end-def

def readUIntBE(buf, offset, bsize):
  return int.from_bytes(buf[offset : (offset + bsize)], 'big', signed = False);
#end-def

def readUInt16BE(buf, offset):
  return readUIntBE(buf, offset, 2);
#end-def

def readUInt32BE(buf, offset):
  return readUIntBE(buf, offset, 4);
#end-def

def readUInt64BE(buf, offset):
  return readUIntBE(buf, offset, 8);
#end-def

def writeUIntLE(buf, val, offset, size):
  while size > 0:
    buf[offset] = val & 0xFF;

    offset += 1;
    val >>= 8;
    size -= 1;
  #end-while
#end-def

def writeUInt32LE(buf, val, offset):
  writeUIntLE(buf, val, offset, 4);
#end-def

def writeUInt64LE(buf, val, offset):
  writeUIntLE(buf, val, offset, 8);
#end-def

def writeUIntBE(buf, val, offset, size):
  while size > 0:
    size -= 1;
    buf[offset + size] = val & 0xFF;
    val >>= 8;
  #end-while
#end-def

def writeUInt16BE(buf, val, offset):
  writeUIntBE(buf, val, offset, 2);
#end-def

def writeUInt32BE(buf, val, offset):
  writeUIntBE(buf, val, offset, 4);
#end-def

class Parser:
  #constants
  UNWIND_REG_IDS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
  # UNWIND_REG_IDS_32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'];

  private_cache_buf = bytearray(0x10); # Cache writable bytes, thread unsafe.

  def __init__(self, sc, base_addr):
    self.shellcode = bytearray(sc);
    self.base = base_addr;

    self.engine = Cs(CS_ARCH_X86, CS_MODE_64);
    self.engine.detail = True;
    self.rip = 0;

    self.cached_instructions = [];
    self.trimmed = [];
    
    self.r9_is_unwind = False;
    self.ctx_regs = [];
    self.was_rax_ctx = False; # RAX is used a lot in obfuscation, so a special detection is required.
  #end-def

  def step_single(self):
    pseudo_rip = self.base + self.rip;
    ins = next(self.engine.disasm(self.shellcode[self.rip:], pseudo_rip, 1), None);
    if not ins:
      raise Exception('Cannot disassemble anything at RIP 0x%08X! Abort!' % (pseudo_rip));
    #end-if
    opc = ins.mnemonic;
    self.cached_instructions.append(ins);
    self.trimmed.append(ins);
    self.rip += ins.size;
    pseudo_rip = self.base + self.rip;

    print(' 0x%08X: %s %s' % (ins.address, opc, ins.op_str));

    (regs_r, regs_w) = ins.regs_access();

    ctx_retrieval_mark = None;
    match opc:
      case 'hlt':
        del self.trimmed[-1:];
        self.r9_is_unwind = True;
        self.ctx_regs.clear();
        self.was_rax_ctx = False;

        print('Found HLT at RIP = 0x%08X' % (pseudo_rip - ins.size));

        # Exception function entry returned from the callback
        unwind_info_offset = self.rip + self.shellcode[self.rip] + 1;
        if (unwind_info_offset & 1):
          unwind_info_offset += 1;
        #end-if
        print('  Jumper target descriptor addr: 0x%08X' % (self.base + unwind_info_offset));

        # Sanity check against the UNWIND_CODE object
        check = readUInt32LE(self.shellcode, unwind_info_offset) & 0xFF00FFFF;
        if check != 0x9:
          check &= 0xF000FFFF;
          if check != 0x9:
            raise Exception('Found unexpected UNWIND_CODE member values! Abort!');
          #end-if
          print('Notice: found non-zero unwind frame registers count: %d' % (self.shellcode[unwind_info_offset + 3] & 0x0F));
        #end-if

        unwind_count = self.shellcode[unwind_info_offset + 2];

        # These aholes modify the context registers! Ouch!
        unwind_parser_offset = unwind_info_offset + 4;
        remainings = unwind_count;
        
        unwind_scheme = 0xF; # Mark the starting point.
        unwind_essence = [];

        while remainings > 0:
          node_type = self.shellcode[unwind_parser_offset + 1] & 0xF;
          unwind_scheme = (unwind_scheme << 4) | node_type; # Used to lift the obfuscation
          node_info = self.shellcode[unwind_parser_offset + 1] >> 4;

          # I assume that only certain info is important to lift the instructions.
          # I'll use the scheme proxy-type with this to reconstruct instructions without nuking the stack.

          match node_type:
            case 0: # UWOP_PUSH_NONVOL, unwind stuff like prologue pushes.
              reg_name = Parser.UNWIND_REG_IDS[node_info];

              i = 0;
              if (node_info >> 3): # R8 to R15
                self.private_cache_buf[i] = 0x41;
                i += 1;
              #end-if
              self.private_cache_buf[i] = 0x58 | (node_info & 0x7);
              self.cached_instructions.append(next(self.engine.disasm(self.private_cache_buf, 0, 1), None));

              unwind_essence.append(reg_name);

              print('[UNWIND EQUIV] pop %s' % reg_name);
            case 1: # UWOP_ALLOC_LARGE, unwind stack allocations like `sub rsp, 0x50`
              unwind_parser_offset += 2;
              remainings -= 1;
              match node_info:
                case 0:
                  unwind_size = readUInt16LE(self.shellcode, unwind_parser_offset) << 3;
                case 1:
                  unwind_size = readUInt32LE(self.shellcode, unwind_parser_offset);

                  unwind_parser_offset += 2; # See that UInt32 above?
                  remainings -= 1;
                case _:
                  raise Exception('Invalid stack deallocation code (at offset 0x%08X)! Abort!' % unwind_parser_offset);
                #end-cases
              #end-match

              if unwind_size < 0x80:
                writeUInt32BE(self.private_cache_buf, 0x4883C400, 0);
                self.private_cache_buf[3] = unwind_size;
              else:
                writeUInt32BE(self.private_cache_buf, 0x4881C400, 0);
                writeUInt32LE(self.private_cache_buf, unwind_size, 3);
              #end-if
              self.cached_instructions.append(next(self.engine.disasm(self.private_cache_buf, 0, 1), None));

              unwind_essence.append(unwind_size);

              print('[UNWIND EQUIV] add rsp, 0x%X' % unwind_size);
            case 2:
              unwind_size = (node_info << 3) + 8;

              if unwind_size < 0x80:
                writeUInt32BE(self.private_cache_buf, 0x4883C400, 0);
                self.private_cache_buf[3] = unwind_size;
              else:
                writeUInt32BE(self.private_cache_buf, 0x4881C400, 0);
                writeUInt32LE(self.private_cache_buf, unwind_size, 3);
              #end-if
              self.cached_instructions.append(next(self.engine.disasm(self.private_cache_buf, 0, 1), None));

              unwind_essence.append(unwind_size);

              print('[UNWIND EQUIV] add rsp, 0x%X' % unwind_size);
            case 3:
              node_info = self.shellcode[unwind_info_offset + 3];
              reg_name = Parser.UNWIND_REG_IDS[node_info & 0xF];
              stack_offset = node_info & 0xF0;
              if stack_offset:
                print('[UNWIND EQUIV] lea rsp, [%s - 0x%X]' % (reg_name, stack_offset));

                raise Exception('Unexpected offset in type-3 unwind opcode at offset 0x%08X! Abort!' % unwind_info_offset);
              else:
                if (node_info >> 3): # R8 to R15
                  writeUInt16BE(self.private_cache_buf, 0x4C89, 0);
                else: # RAX to RDI
                  writeUInt16BE(self.private_cache_buf, 0x4889, 0);
                #end-if
                self.private_cache_buf[2] = 0xC4 | ((node_info & 0x7) << 3);
                self.cached_instructions.append(next(self.engine.disasm(self.private_cache_buf, 0, 1), None));

                unwind_essence.append(reg_name);

                print('[UNWIND EQUIV] mov rsp, %s' % reg_name);
              #end-if
            case 4: # Like type 0 but it was a mov like `mov [rsp + 0x40], r8` instead of a push
              unwind_parser_offset += 2;
              remainings -= 1;

              stack_offset = readUInt16LE(self.shellcode, unwind_parser_offset) << 3;
              reg_name = Parser.UNWIND_REG_IDS[node_info];
              print('[UNWIND EQUIV] mov %s, qword [rsp + 0x%X]' % (reg_name, stack_offset));

              raise Exception('Unexpected type-4 unwind opcode at offset 0x%08X! Abort!' % unwind_info_offset);
            case 5: # Like type 0 but the offset cannot be simplified.
              unwind_parser_offset += 2;
              remainings -= 1;

              stack_offset = readUInt32LE(self.shellcode, unwind_parser_offset);
              reg_name = Parser.UNWIND_REG_IDS[node_info];
              print('[UNWIND EQUIV] mov %s, qword [rsp + 0x%X]' % (reg_name, stack_offset));

              unwind_parser_offset += 2; # See that UInt32 above?
              remainings -= 1;

              raise Exception('Unexpected type-5 unwind opcode at offset 0x%08X! Abort!' % unwind_info_offset);
            case 8: # XMM stuff. I don't like it.
              raise Exception('Not implemented unwind type (8).');
            case 9: # XMM stuff. I don't like it.
              raise Exception('Not implemented unwind type (9).');
            case 10:
              # unwind_scheme |= (node_info << 4);

              writeUInt32BE(self.private_cache_buf, 0x488B6424, 0);

              match node_info:
                case 0:
                  self.private_cache_buf[4] = 0x18;

                  print('[UNWIND EQUIV] # mov ss, [rsp + 0x20]');
                  print('[UNWIND EQUIV] # mov eflags, [rsp + 0x10]');
                  print('[UNWIND EQUIV] # mov cs, [rsp + 0x8]');
                  print('[UNWIND EQUIV] # mov rip, qword [rsp]');
                  print('[UNWIND EQUIV] mov rsp, qword [rsp + 0x18]');
                case 1:
                  self.private_cache_buf[4] = 0x20;

                  print('[UNWIND EQUIV] # mov ss, [rsp + 0x28]');
                  print('[UNWIND EQUIV] # mov eflags, [rsp + 0x18]');
                  print('[UNWIND EQUIV] # mov cs, [rsp + 0x10]');
                  print('[UNWIND EQUIV] # mov rip, qword [rsp + 8]');
                  print('[UNWIND EQUIV] # mov error, qword [rsp]');
                  print('[UNWIND EQUIV] mov rsp, qword [rsp + 0x20]');
                case _:
                  raise Exception('Invalid special stack frame type code (at offset 0x%08X)! Abort!' % unwind_parser_offset);
                #end-cases
              #end-match

              self.cached_instructions.append(next(self.engine.disasm(self.private_cache_buf, 0, 1), None));

              unwind_essence.append(self.private_cache_buf[4]);
            case _:
              raise Exception('Unknown unwind OP code (at offset 0x%08X)! Abort!' % unwind_parser_offset);
            #end-cases
          #end-match
          unwind_parser_offset += 2;
          remainings -= 1;
        #end-while

        match unwind_scheme:
          case 0xF:
            pass;
          case 0xFA10:
            s = 'mov %s, qword ptr [rsp + 0x%x]' % (unwind_essence[2], unwind_essence[0]);
            self.trimmed.append(s);
            print('[UNWIND-LIFTED] %s' % s);

            s = 'mov %s, qword ptr [%s + 0x%x]' % (unwind_essence[2], unwind_essence[2], unwind_essence[1]);
            self.trimmed.append(s);
            print('[UNWIND-LIFTED] %s' % s);
          case 0xFA0:
            s = 'mov %s, qword ptr [rsp + 0x%x]' % (unwind_essence[1], unwind_essence[0]);
            self.trimmed.append(s);
            print('[UNWIND-LIFTED] %s' % s);

            s = 'mov %s, qword ptr [%s]' % (unwind_essence[1], unwind_essence[1]);
            self.trimmed.append(s);
            print('[UNWIND-LIFTED] %s' % s);
          case 0xF320:
            s = 'mov %s, qword ptr [%s + 0x%x]' % (unwind_essence[2], unwind_essence[0], unwind_essence[1]);
            self.trimmed.append(s);
            print('[UNWIND-LIFTED] %s' % s);
          case 0xF310:
            s = 'mov %s, qword ptr [%s + 0x%x]' % (unwind_essence[2], unwind_essence[0], unwind_essence[1]);
            self.trimmed.append(s);
            print('[UNWIND-LIFTED] %s' % s);
          case 0xF30:
            s = 'mov %s, qword ptr [%s]' % (unwind_essence[1], unwind_essence[0]);
            self.trimmed.append(s);
            print('[UNWIND-LIFTED] %s' % s);
          case _:
            raise Exception('Unexpected unwind operation sequence %x at offset %08X! Abort!' % unwind_info_offset);
          #end-cases
        #end-match

        # Now store all registers in the dedicated PCONTEXT emulation memory!
        self.trimmed.append('movd dword [ctx_mxcsr], xmm0');
        for i in Parser.UNWIND_REG_IDS:
          self.trimmed.append('mov qword [ctx_%s], %s' % (i, i));
        #end-for

        if (unwind_count & 0x1):
          unwind_count += 1;
        #end-if
        jmp_dest_offset = readUInt32LE(self.shellcode, unwind_info_offset + 4 + (unwind_count << 1));

        print('  Unwind jumper destination: 0x%08x' % (self.base + jmp_dest_offset));
        self.rip = jmp_dest_offset; # Jump to the new RIP from the unwind handler!
      case 'call':
        if ins.bytes[0] == 0xE8: # Direct relative call
          call_dst = ins.operands[0].value.imm;
          self.rip = call_dst - self.base;

          print('Updated RIP to the CALL to 0x%08x' % call_dst);
        else:
          raise Exception('Found a CALL to unknown address! Abort!');
        #end-if
      case 'jmp':
        if ins.bytes[0] == 0xE9: # Direct relative call
          jmp_dst = ins.operands[0].value.imm;
          self.rip = jmp_dst - self.base;

          del self.trimmed[-1:];

          print('Updated RIP to the JMP to 0x%08x' % jmp_dst);
        else:
          raise Exception('Found a JMP to unknown address! Abort!');
        #end-if
      case 'ret':
        cache = self.cached_instructions[-5:-1];
        # push RAX
        # mov RAX, IMM-64
        # lea RAX, [RAX + IMM-8] # Assume that the IMM-8 here MUST be between 0 and 0x7F
        # xchg qword [RSP], RAX # (Setup the return addr)
        if (cache[0].mnemonic == 'push') and (cache[0].bytes[0] == 0x50) and \
           (cache[1].mnemonic == 'movabs') and (readUInt16BE(cache[1].bytes, 0) == 0x48B8) and \
           (cache[2].mnemonic == 'lea') and (cache[2].bytes[0] == 0x48) and (readUInt16BE(cache[2].bytes, 1) == 0x8D40) and \
           (cache[3].mnemonic == 'xchg') and (readUInt32BE(cache[3].bytes, 0) == 0x48870424):
          # Here let's only follow the RET for now. Later I may replace the `push RAX ...` "epilogue" with a single JMP to the resolved address.
          dist = cache[2].bytes[3];
          if dist >= 0x80:
            raise Exception('Found a RET epilogue with anomalous offset distance! Abort!');
          #end-if
          jmp_dst = readUInt64LE(cache[1].bytes, 2) - self.base + dist;
          self.rip = jmp_dst;

          del self.trimmed[-5:];
          # Remove the leading `mov dword [rip-0xXY], <IMM-32>` since it's an obfuscation artifact too.
          cache = self.cached_instructions[-6];
          if (readUInt16BE(cache.bytes, 0) == 0xC705) and ((tmp := readInt32LE(cache.bytes, 2)) < 0) and (tmp > -0x100):
            del self.trimmed[-1:];
          #end

          print('Updated RIP to the RET to 0x%08x' % jmp_dst);

          # Also restore the PCONTEXT history when needed. It comes from the 'xchg' instruction above!
          if self.was_rax_ctx:
            self.was_rax_ctx = False;
            self.ctx_regs.append(X86_REG_RAX);
            ctx_retrieval_mark = X86_REG_RAX;
          #end-if
        else:
          raise Exception('Found a RET to unknown address! Abort!');
        #end-if
      case 'pop':
        last_ins = self.cached_instructions[-2];
        # call REL-IMM-32<a>
        # pop [REL-IMM-32<b>] with `REL-IMM-32<b> < 0x100` (Supposedly the ret instruction is not far away)
        if (last_ins.mnemonic == 'call') and (last_ins.bytes[0] == 0xE8) and \
           (readUInt16BE(ins.bytes, 0) == 0x8F05) and ((write_offset := readUInt32LE(ins.bytes, 2)) < 0x100):
          # Supposedly the return address decryption info.
          write_dst = self.rip + write_offset;

          # [** NOTICE! **] self.base is NOT subtracted! Make sure the deobfuscated shellcode is loaded with the specified offset in IDA!
          write_val64 = last_ins.address + last_ins.size;

          # Addresses are 64-bit!
          writeUInt64LE(self.shellcode, write_val64, write_dst);

          del self.trimmed[-2:];

          print('Written address 0x%08X to offset 0x%08X in shellcode.' % (write_val64, write_dst));
        elif ins.bytes[0] == 0x58: # pop RAX
          # Note: here I assume that the paired pop RAX is ALWAYS NOT encrypted!

          cache = self.cached_instructions[-6:-1];
          # push RAX
          # mov RAX, 0
          # mov AH, [REL-IMM-32]
          # lea EAX, [EAX + IMM-32]
          # mov dword [RIP + 1], EAX # Assume that this offset is FIXED to 0x1!
          if (cache[0].mnemonic == 'push') and (cache[0].bytes[0] == 0x50) and \
             (cache[1].mnemonic == 'mov') and (cache[1].bytes[0] == 0x48) and (readUInt16BE(cache[1].bytes, 1) == 0xC7C0) and (readUInt32LE(cache[1].bytes, 3) == 0) and \
             (cache[2].mnemonic == 'mov') and (readUInt16BE(cache[2].bytes, 0) == 0x8A25) and \
             (cache[3].mnemonic == 'lea') and (cache[3].bytes[0] == 0x67) and (readUInt16BE(cache[3].bytes, 1) == 0x8D80) and \
             (cache[4].mnemonic == 'mov') and (readUInt16BE(cache[4].bytes, 0) == 0x8905) and ((write_offset := readUInt32LE(cache[4].bytes, 2)) == 0x1):
            # Immediate opcode mutation stuff.
            read_offset = cache[2].address - self.base + cache[2].size + readInt32LE(cache[2].bytes, 2);

            write_val32 = self.shellcode[read_offset] << 8; # It's a mov to AH.
            write_val32 += readInt32LE(cache[3].bytes, 3); # LEA is just another form of add/sub

            write_offset += cache[4].address - self.base + cache[4].size;
            writeUInt32LE(self.shellcode, write_val32, write_offset);

            del self.trimmed[-6:];

            print('Written value 0x%08X to offset 0x%08X in shellcode.' % (write_val32 & 0xFFFFFFFF, write_offset));

            # Also restore the PCONTEXT history when needed.
            if self.was_rax_ctx:
              self.was_rax_ctx = False;
              self.ctx_regs.append(X86_REG_RAX);
              ctx_retrieval_mark = X86_REG_RAX;
            #end-if
          #end-if
        #end-if
      case 'mov':
        # I treat it as `mov LHS, RHS`. It's shitty. I know. I just don't have a better expression.
        lhs = ins.operands[0];
        rhs = ins.operands[1];
        if self.r9_is_unwind and (rhs.type == X86_OP_MEM) and (rhs.mem.base == X86_REG_R9) and (rhs.mem.scale == 1) and (rhs.mem.disp == 0x28):
          if lhs.type != X86_OP_REG:
            raise Exception('Unexpected destination of the PCONTEXT retrieval instruction!');
          #end-if
          self.ctx_regs.append(lhs.reg);
          print('[UNWIND PCONTEXT DETECTION] %s' % self.engine.reg_name(lhs.reg));

          ctx_retrieval_mark = lhs.reg;

          # Lifted!
          del self.trimmed[-1:];
        else:
          self.lift_ctx_reg(opc, lhs, rhs);
        #end-if
      case 'add' | 'sub' | 'xor':
        lhs = ins.operands[0];
        rhs = ins.operands[1];
        self.lift_ctx_reg(opc, lhs, rhs);
      case 'push':
        # Detect push RAX when RAX stores a PCONTEXT.
        if ins.bytes[0] == 0x50:
          self.was_rax_ctx = (X86_REG_RAX in self.ctx_regs);
        #end-if
      case 'lea':
        # Will be used to detect chunk transition jumps later.
        pass;
      case 'ldmxcsr':
        operand = ins.operands[0];
        if (operand.type == X86_OP_MEM) and (operand.mem.base in self.ctx_regs) and (operand.mem.scale == 1):
          mem_off = operand.mem.disp;
          if mem_off == 0x34:
            # Loaded itself from previous PCONTEXT frame.
            self.trimmed[-1] = 'movd xmm0, dword [ctx_mxcsr]';
          elif (mem_off >= 0x78) and (mem_off < 0xF8) and ((mem_off & 0x7) == 0):
            # Replace the unreachable MxCsr register with XMM0. MxCsr is only 32-bit long, so I use `movd`!
            self.trimmed[-1] = ('movd xmm0, dword [ctx_%s]' % Parser.UNWIND_REG_IDS[(mem_off - 0x78) >> 3]);
          else:
            raise Exception('Unexpected source in PCONTEXT of special instruction "ldmxcsr"!');
          #end-if
        else:
          raise Exception('Unexpected source of special instruction "ldmxcsr"!');
        #end-if
      case _:
        pass;
      #end-cases
    #end-match

    if self.r9_is_unwind and (X86_REG_R9 in regs_w) and (len(ins.operands) >= 1) and (ins.operands[0].type == X86_OP_REG):
      self.r9_is_unwind = False;
    #end-if

    for item in self.ctx_regs:
      if (item != ctx_retrieval_mark) and (item in regs_w) and (len(ins.operands) >= 1) and (ins.operands[0].type == X86_OP_REG):
        print('[UNWIND DEBUG] CTX reg %s has been overwritten.' % self.engine.reg_name(item));
        self.ctx_regs.remove(item);
      #end-if
    #end-for
  #end-def

  def lift_ctx_reg(self, opc, lhs, rhs):
    if (lhs.type == X86_OP_REG) and (rhs.type == X86_OP_MEM) and (rhs.mem.base in self.ctx_regs) and (rhs.mem.scale == 1):
      mem_off = rhs.mem.disp;
      if (opc == 'mov') and (mem_off == 0x34):
        # This means the instruction is trying to retrieve the MxCsr register!
        # Somehow NASM only takes `mov` and shot on my face when I use `movd` here. Wtf.
        self.trimmed[-1] = ('mov %s, dword [ctx_mxcsr]' % self.engine.reg_name(lhs.reg));

        print('[UNWIND PCONTEXT LIFTER] MxCsr');
      else:
        if (mem_off < 0x78) or (mem_off >= 0xF8) or (mem_off & 0x7):
          raise Exception('Unexpected PCONTEXT struct entry!');
        #end-if
        reg_name = Parser.UNWIND_REG_IDS[(mem_off - 0x78) >> 3];

        print('[UNWIND PCONTEXT LIFTER] %s' % reg_name);

        # The obfuscated sometimes use a register before retrieving stuff from the old context, thus we must store them separately! Oof!
        self.trimmed[-1] = ('%s %s, qword [ctx_%s]' % (opc, self.engine.reg_name(lhs.reg), reg_name));
      #end-if
    elif ((opc == 'add') or (opc == 'sub')) and (lhs.type == X86_OP_MEM) and (rhs.type == X86_OP_REG) and (lhs.mem.base in self.ctx_regs) and (lhs.mem.scale == 1):
      # Somehow their obfuscator was good enough to include this. Oof.
      mem_off = lhs.mem.disp;
      if (mem_off < 0x78) or (mem_off >= 0xF8) or (mem_off & 0x7):
        raise Exception('Unexpected PCONTEXT struct entry!');
      #end-if
      reg_name = Parser.UNWIND_REG_IDS[(mem_off - 0x78) >> 3];

      print('[UNWIND PCONTEXT LIFTER (LHS)] %s' % reg_name);

      # The obfuscated sometimes use a register before retrieving stuff from the old context, thus we must store them separately! Oof!
      self.trimmed[-1] = ('%s qword [ctx_%s], %s' % (opc, reg_name, self.engine.reg_name(rhs.reg)));
    #end-if
  #end-def
#end-class

def __main__():
  fp = open('shellcode.bin', 'rb');
  sc = fp.read();
  fp.close();

  parser = Parser(sc, 0x1000000);

  try:
    while True:
      parser.step_single();
    #end-while
  except Exception as err:
    print(err);
    traceback.print_tb(err.__traceback__);
  #end-try

  fp = open('deobf02a.txt', 'w');

  # NASM headers
  fp.write('BITS 64\n');
  fp.write('DEFAULT REL\n');
  fp.write('\n');

  for item in parser.trimmed:
    if (type(item) == str):
      line = item;
    else:
      line = ('%s %s' % (item.mnemonic, item.op_str));
    #end-if

    # NASM syntax stuff.
    fp.write(' %s\n' % line.replace(' ptr ', ' ').replace('movabs', 'mov'));
  #end-for

  fp.write('\n');
  fp.write(' align 0x4\n');
  fp.write('ctx_mxcsr:\n');
  fp.write(' dd 0x0\n');
  fp.write(' align 0x8\n');
  for item in Parser.UNWIND_REG_IDS:
    fp.write('ctx_%s:\n' % item);
    fp.write(' dq 0x0\n');
  #end-for

  fp.close();

  fp = open('shellcode-deobf01.bin', 'wb');
  fp.write(parser.shellcode);
  fp.close();
#end-def

if __name__ == '__main__':
  __main__();
#end-if
