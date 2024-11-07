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

class Parser:
  def __init__(self, sc, base_addr):
    self.shellcode = bytearray(sc);
    self.base = base_addr;

    self.engine = Cs(CS_ARCH_X86, CS_MODE_64);
    self.engine.detail = True;
    self.rip = 0;

    self.cached_instructions = [];
    self.writes = []; # not used for now
  #end-def

  def step_single(self):
    #constants
    UNWIND_REG_IDS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];

    pseudo_rip = self.base + self.rip;
    ins = next(self.engine.disasm(self.shellcode[self.rip:], pseudo_rip, 1), None);
    if not ins:
      raise Exception('Cannot disassemble anything at RIP 0x%08X! Abort!' % (pseudo_rip));
    #end-if
    opc = ins.mnemonic;
    self.cached_instructions.append(ins);
    self.rip += ins.size;
    pseudo_rip = self.base + self.rip;

    print(' 0x%08X: %s %s' % (ins.address, opc, ins.op_str));

    match opc:
      case 'hlt':
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
        while remainings > 0:
          node_type = self.shellcode[unwind_parser_offset + 1] & 0xF;
          node_info = self.shellcode[unwind_parser_offset + 1] >> 4;
          # Currently I just skip all the info here. Maybe the stack would be important but I assume it's not as of now.
          match node_type:
            case 0: # UWOP_PUSH_NONVOL, unwind stuff like prologue pushes.
              reg_name = UNWIND_REG_IDS[node_info];
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

              print('[UNWIND EQUIV] add rsp, 0x%X' % unwind_size);
            case 2:
              unwind_size = (node_info << 3) + 8;
              print('[UNWIND EQUIV] add rsp, 0x%X' % unwind_size);
            case 3:
              node_info = self.shellcode[unwind_info_offset + 3];
              reg_name = UNWIND_REG_IDS[node_info & 0xF];
              stack_offset = node_info & 0xF0;
              if stack_offset:
                print('[UNWIND EQUIV] lea rsp, [%s - 0x%X]' % (reg_name, stack_offset));
              else:
                print('[UNWIND EQUIV] mov rsp, %s' % reg_name);
              #end-if
            case 4: # Like type 0 but it was a mov like `mov [rsp + 0x40], r8` instead of a push
              unwind_parser_offset += 2;
              remainings -= 1;

              stack_offset = readUInt16LE(self.shellcode, unwind_parser_offset) << 3;
              reg_name = UNWIND_REG_IDS[node_info];
              print('[UNWIND EQUIV] mov %s, qword [rsp + 0x%X]' % (reg_name, stack_offset));
            case 5: # Like type 0 but the offset cannot be simplified.
              unwind_parser_offset += 2;
              remainings -= 1;

              stack_offset = readUInt32LE(self.shellcode, unwind_parser_offset);
              reg_name = UNWIND_REG_IDS[node_info];
              print('[UNWIND EQUIV] mov %s, qword [rsp + 0x%X]' % (reg_name, stack_offset));

              unwind_parser_offset += 2; # See that UInt32 above?
              remainings -= 1;
            case 8: # XMM stuff. I don't like it.
              raise Exception('Not implemented unwind type (8).');
            case 9: # XMM stuff. I don't like it.
              raise Exception('Not implemented unwind type (9).');
            case 10:
              match node_info:
                case 0:
                  print('[UNWIND EQUIV] # mov ss, [rsp + 0x20]');
                  print('[UNWIND EQUIV] # mov eflags, [rsp + 0x10]');
                  print('[UNWIND EQUIV] # mov cs, [rsp + 0x8]');
                  print('[UNWIND EQUIV] # mov rip, qword [rsp]');
                  print('[UNWIND EQUIV] mov rsp, qword [rsp + 0x18]');
                case 1:
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
            case _:
              raise Exception('Unknown unwind OP code (at offset 0x%08X)! Abort!' % unwind_parser_offset);
            #end-cases
          #end-match
          unwind_parser_offset += 2;
          remainings -= 1;
        #end-while

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

          print('Updated RIP to the RET to 0x%08x' % jmp_dst);
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

            print('Written value 0x%08X to offset 0x%08X in shellcode.' % (write_val32 & 0xFFFFFFFF, write_offset));
          #end-if
        #end-if
      case _:
        pass;
      #end-cases
    #end-match
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
  #end-try

  fp = open('shellcode-deobf01.bin', 'wb');
  fp.write(parser.shellcode);
  fp.close();
#end-def

if __name__ == '__main__':
  __main__();
#end-if
