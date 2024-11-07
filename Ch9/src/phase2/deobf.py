from capstone import *
from capstone.x86 import *

def readUIntLE(buf, offset, size):
  ret = 0;
  while size > 0:
    size -= 1;
    ret <<= 8;
    ret |= buf[offset + size];
  #end-while
  return ret;
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

def readUIntBE(buf, offset, size):
  ret = 0;
  for i in range(size):
    ret <<= 8;
    ret |= buf[offset + i];
  #end-for
  return ret;
#end-def

def readUInt16BE(buf, offset):
  return readUIntBE(buf, offset, 2);
#end-def

def readUInt24BE(buf, offset):
  return readUIntBE(buf, offset, 3);
#end-def

def readUInt32BE(buf, offset):
  return readUIntBE(buf, offset, 4);
#end-def

class Block:
  # Yep capstone is trash.
  REG_IDS_MAP = {
    X86_REG_EAX: X86_REG_RAX,
    X86_REG_AX: X86_REG_RAX,
    X86_REG_AL: X86_REG_RAX,

    X86_REG_EBX: X86_REG_RBX,
    X86_REG_BX: X86_REG_RBX,
    X86_REG_BL: X86_REG_RBX,

    X86_REG_ECX: X86_REG_RCX,
    X86_REG_CX: X86_REG_RCX,
    X86_REG_CL: X86_REG_RCX,

    X86_REG_EDX: X86_REG_RDX,
    X86_REG_DX: X86_REG_RDX,
    X86_REG_DL: X86_REG_RDX,

    X86_REG_ESI: X86_REG_RSI,
    X86_REG_SI: X86_REG_RSI,
    X86_REG_SIL: X86_REG_RSI,

    X86_REG_EDI: X86_REG_RDI,
    X86_REG_DI: X86_REG_RDI,
    X86_REG_DIL: X86_REG_RDI,

    X86_REG_EBP: X86_REG_RBP,
    X86_REG_BP: X86_REG_RBP,
    X86_REG_BPL: X86_REG_RBP,

    X86_REG_ESP: X86_REG_RSP,
    X86_REG_SP: X86_REG_RSP,
    X86_REG_SPL: X86_REG_RSP,

    X86_REG_R8D: X86_REG_R8,
    X86_REG_R8W: X86_REG_R8,
    X86_REG_R8B: X86_REG_R8,

    X86_REG_R9D: X86_REG_R9,
    X86_REG_R9W: X86_REG_R9,
    X86_REG_R9B: X86_REG_R9,

    X86_REG_R10D: X86_REG_R10,
    X86_REG_R10W: X86_REG_R10,
    X86_REG_R10B: X86_REG_R10,

    X86_REG_R11D: X86_REG_R11,
    X86_REG_R11W: X86_REG_R11,
    X86_REG_R11B: X86_REG_R11,

    X86_REG_R12D: X86_REG_R12,
    X86_REG_R12W: X86_REG_R12,
    X86_REG_R12B: X86_REG_R12,

    X86_REG_R13D: X86_REG_R13,
    X86_REG_R13W: X86_REG_R13,
    X86_REG_R13B: X86_REG_R13,

    X86_REG_R14D: X86_REG_R14,
    X86_REG_R14W: X86_REG_R14,
    X86_REG_R14B: X86_REG_R14,

    X86_REG_R15D: X86_REG_R15,
    X86_REG_R15W: X86_REG_R15,
    X86_REG_R15B: X86_REG_R15,
  };
  
  REG_BITS_MAP = {
    X86_REG_RAX: 64,
    X86_REG_EAX: 32,
    X86_REG_AX: 16,
    X86_REG_AL: 8,
    
    X86_REG_RBX: 64,
    X86_REG_EBX: 32,
    X86_REG_BX: 16,
    X86_REG_BL: 8,

    X86_REG_RCX: 64,
    X86_REG_ECX: 32,
    X86_REG_CX: 16,
    X86_REG_CL: 8,

    X86_REG_RDX: 64,
    X86_REG_EDX: 32,
    X86_REG_DX: 16,
    X86_REG_DL: 8,

    X86_REG_RSI: 64,
    X86_REG_ESI: 32,
    X86_REG_SI: 16,
    X86_REG_SIL: 8,

    X86_REG_RDI: 64,
    X86_REG_EDI: 32,
    X86_REG_DI: 16,
    X86_REG_DIL: 8,

    X86_REG_RBP: 64,
    X86_REG_EBP: 32,
    X86_REG_BP: 16,
    X86_REG_BPL: 8,

    X86_REG_RSP: 64,
    X86_REG_ESP: 32,
    X86_REG_SP: 16,
    X86_REG_SPL: 8,

    X86_REG_R8: 64,
    X86_REG_R8D: 32,
    X86_REG_R8W: 16,
    X86_REG_R8B: 8,

    X86_REG_R9: 64,
    X86_REG_R9D: 32,
    X86_REG_R9W: 16,
    X86_REG_R9B: 8,

    X86_REG_R10: 64,
    X86_REG_R10D: 32,
    X86_REG_R10W: 16,
    X86_REG_R10B: 8,

    X86_REG_R11: 64,
    X86_REG_R11D: 32,
    X86_REG_R11W: 16,
    X86_REG_R11B: 8,

    X86_REG_R12: 64,
    X86_REG_R12D: 32,
    X86_REG_R12W: 16,
    X86_REG_R12B: 8,

    X86_REG_R13: 64,
    X86_REG_R13D: 32,
    X86_REG_R13W: 16,
    X86_REG_R13B: 8,

    X86_REG_R14: 64,
    X86_REG_R14D: 32,
    X86_REG_R14W: 16,
    X86_REG_R14B: 8,

    X86_REG_R15: 64,
    X86_REG_R15D: 32,
    X86_REG_R15W: 16,
    X86_REG_R15B: 8,
  };

  REG_BITS_REVERSE_MAP = {
    X86_REG_RAX: {
      64: X86_REG_RAX,
      32: X86_REG_EAX,
      16: X86_REG_AX,
      8: X86_REG_AL
    },
    X86_REG_RBX: {
      64: X86_REG_RBX,
      32: X86_REG_EBX,
      16: X86_REG_BX,
      8: X86_REG_BL
    },
    X86_REG_RCX: {
      64: X86_REG_RCX,
      32: X86_REG_ECX,
      16: X86_REG_CX,
      8: X86_REG_CL
    },
    X86_REG_RDX: {
      64: X86_REG_RDX,
      32: X86_REG_EDX,
      16: X86_REG_DX,
      8: X86_REG_DL
    },
    X86_REG_RSI: {
      64: X86_REG_RSI,
      32: X86_REG_ESI,
      16: X86_REG_SI,
      8: X86_REG_SIL
    },
    X86_REG_RDI: {
      64: X86_REG_RDI,
      32: X86_REG_EDI,
      16: X86_REG_DI,
      8: X86_REG_DIL
    },
    X86_REG_RBP: {
      64: X86_REG_RBP,
      32: X86_REG_EBP,
      16: X86_REG_BP,
      8: X86_REG_BPL
    },
    X86_REG_RSP: {
      64: X86_REG_RSP,
      32: X86_REG_ESP,
      16: X86_REG_SP,
      8: X86_REG_SPL
    },
    X86_REG_R8: {
      64: X86_REG_R8,
      32: X86_REG_R8D,
      16: X86_REG_R8W,
      8: X86_REG_R8B
    },
    X86_REG_R9: {
      64: X86_REG_R9,
      32: X86_REG_R9D,
      16: X86_REG_R9W,
      8: X86_REG_R9B
    },
    X86_REG_R10: {
      64: X86_REG_R10,
      32: X86_REG_R10D,
      16: X86_REG_R10W,
      8: X86_REG_R10B
    },
    X86_REG_R11: {
      64: X86_REG_R11,
      32: X86_REG_R11D,
      16: X86_REG_R11W,
      8: X86_REG_R11B
    },
    X86_REG_R12: {
      64: X86_REG_R12,
      32: X86_REG_R12D,
      16: X86_REG_R12W,
      8: X86_REG_R12B
    },
    X86_REG_R13: {
      64: X86_REG_R13,
      32: X86_REG_R13D,
      16: X86_REG_R13W,
      8: X86_REG_R13B
    },
    X86_REG_R14: {
      64: X86_REG_R14,
      32: X86_REG_R14D,
      16: X86_REG_R14W,
      8: X86_REG_R14B
    },
    X86_REG_R15: {
      64: X86_REG_R15,
      32: X86_REG_R15D,
      16: X86_REG_R15W,
      8: X86_REG_R15B
    },
    X86_REG_XMM0: { # This register is only used to substitute CxMsr 32-bit reg.
      32: X86_REG_XMM0
    }
  };
  
  OFFSET_TO_REG64_ARR = [
    X86_REG_XMM0, # Note: this is a replacement of CxMsr and is always 32-bit!
    X86_REG_RAX,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RBX,
    X86_REG_RSP,
    X86_REG_RBP,
    X86_REG_RSI,
    X86_REG_RDI,
    X86_REG_R8,
    X86_REG_R9,
    X86_REG_R10,
    X86_REG_R11,
    X86_REG_R12,
    X86_REG_R13,
    X86_REG_R14,
    X86_REG_R15
  ];

  def __init__(self, parser):
    self.rip = parser.rip;
    self.instructions = [];
    
    # For CTX-REG RW conflicts, I will add an intermediate register to store the read value. This requires extra mov instructions.
    self.inserted_prologue = [];
    
    self.ctx_last_read_dict = {};
    self.reg_first_write_dict = {};
    
    self.unused_regs = [
      X86_REG_RAX,
      X86_REG_RCX,
      X86_REG_RDX,
      X86_REG_RBX,
      X86_REG_RBP,
      X86_REG_RSI,
      X86_REG_RDI,
      X86_REG_R8,
      X86_REG_R9,
      X86_REG_R10,
      X86_REG_R11,
      X86_REG_R12,
      X86_REG_R13,
      X86_REG_R14,
      X86_REG_R15
    ];
    
    self.data_addr = parser.data_offset;

    self.chunk_transition_found = False;
  #end-def
  
  def update(self, ins):
    (r, w) = ins.regs_access();
    # Writes must occur first for any register, since the exception obfuscation destroyes all the registers and reads are only meaningful form the context.
    for id in w:
      if id in Block.REG_IDS_MAP:
        id64 = Block.REG_IDS_MAP[id];
      else:
        id64 = id;
      #end-if

      if (id64 not in self.reg_first_write_dict) and \
         ((ins.mnemonic != 'mov') or ((rhs := ins.operands[1]).type != X86_OP_MEM) or (rhs.mem.base != X86_REG_RIP) or (Block.OFFSET_TO_REG64_ARR[(ins.address + ins.size + rhs.mem.disp - self.data_addr) >> 3] != id64)):
        # The 2nd line detects if the move is actually a self-move.
        self.reg_first_write_dict[id64] = len(self.instructions);
      #end-if
      
      if id64 in self.unused_regs:
        self.unused_regs.remove(id64);
      #end-if
    #end-for
    
    for id in r:
      if id in Block.REG_IDS_MAP:
        id64 = Block.REG_IDS_MAP[id];
      else:
        id64 = id;
      #end-if

      if id64 in self.unused_regs:
        self.unused_regs.remove(id64);
      #end-if
    #end-for
    
    # Get corresponding register ID for last CTX read/write instructions in the block.
    match ins.mnemonic:
      case 'mov' | 'movd' | 'add' | 'sub' | 'xor':
        lhs = ins.operands[0];
        rhs = ins.operands[1];
        if (lhs.type == X86_OP_REG) and (rhs.type == X86_OP_MEM) and (rhs.mem.base == X86_REG_RIP):
          data_pos = (ins.address + ins.size + rhs.mem.disp - self.data_addr) >> 3;
          ctx_reg = Block.OFFSET_TO_REG64_ARR[data_pos];
          
          self.ctx_last_read_dict[ctx_reg] = len(self.instructions);
          
          if ctx_reg in self.unused_regs:
            self.unused_regs.remove(ctx_reg);
          #end-if
        elif (rhs.type == X86_OP_REG) and (lhs.type == X86_OP_MEM) and (lhs.mem.base == X86_REG_RIP):
          data_pos = (ins.address + ins.size + lhs.mem.disp - self.data_addr) >> 3;
          ctx_reg = Block.OFFSET_TO_REG64_ARR[data_pos];
          
          self.ctx_last_read_dict[ctx_reg] = len(self.instructions);
          
          if ctx_reg in self.unused_regs:
            self.unused_regs.remove(ctx_reg);
          #end-if
        #end-if
      #end-cases
    #end-match

    self.instructions.append(ins);
  #end-def
  
  def transform(self, engine, chunk_id):
    conflicts = [];
    for k in self.ctx_last_read_dict.keys():
      if (k in self.reg_first_write_dict) and (self.reg_first_write_dict[k] < self.ctx_last_read_dict[k]):
        conflicts.append(k);
      #end-if
    #end-for
    
    substitutes = {};
    for item in conflicts:
      substitute = self.unused_regs[0];
      self.unused_regs.remove(substitute);

      substitutes[item] = substitute;

      self.inserted_prologue.append('mov %s, %s' % (engine.reg_name(substitute), engine.reg_name(item)));
    #end-for
    
    for i in range(len(self.instructions)):
      ins = self.instructions[i];
      if type(ins) == str: # Special next-chunk pre-jmp address LEA
        continue;
      #end-if
      
      match ins.mnemonic:
        case 'mov' | 'movd' | 'add' | 'sub' | 'xor':
          lhs = ins.operands[0];
          rhs = ins.operands[1];

          if (lhs.type == X86_OP_REG) and (rhs.type == X86_OP_MEM) and (rhs.mem.base == X86_REG_RIP):
            data_pos = (ins.address + ins.size + rhs.mem.disp - self.data_addr) >> 3;
            ctx_reg = Block.OFFSET_TO_REG64_ARR[data_pos];

            out_reg = ctx_reg;
            if ctx_reg in substitutes:
              out_reg = substitutes[ctx_reg];
              
              print('Substituted %s with %s' % (engine.reg_name(ctx_reg), engine.reg_name(out_reg)));
            #end-if

            mnemonic = ins.mnemonic;
            val_size = rhs.size;
            if mnemonic.startswith('mov'):
              if (out_reg == lhs.reg) and ((val_size == lhs.size) or (out_reg == X86_REG_XMM0)):
                self.instructions[i] = None; # Dummy.
                continue;
              elif (out_reg == X86_REG_XMM0) and (lhs.size == 4):
                mnemonic = 'movd';
              elif (val_size != 8) and (lhs.reg != X86_REG_XMM0) and (lhs.size != rhs.size):
                mnemonic = 'movzx';
              #end-if
            #end-if

            self.instructions[i] = '%s %s, %s' % (mnemonic, engine.reg_name(lhs.reg), engine.reg_name(Block.REG_BITS_REVERSE_MAP[out_reg][val_size << 3]));

            print(self.instructions[i]);
          elif (rhs.type == X86_OP_REG) and (lhs.type == X86_OP_MEM) and (lhs.mem.base == X86_REG_RIP):
            data_pos = (ins.address + ins.size + lhs.mem.disp - self.data_addr) >> 3;
            ctx_reg = Block.OFFSET_TO_REG64_ARR[data_pos];

            out_reg = ctx_reg;
            if ctx_reg in substitutes:
              out_reg = substitutes[ctx_reg];
              
              print('Substituted %s with %s' % (engine.reg_name(ctx_reg), engine.reg_name(out_reg)));
            #end-if

            mnemonic = ins.mnemonic;
            if mnemonic.startswith('mov'):
              if out_reg == rhs.reg:
                self.instructions[i] = None; # Dummy.
                continue;
              #end-if
            #end-if

            if (rhs.size != 8) or (lhs.size != 8):
              raise Exception('Unexpected write size to CTX registers in block at RIP = 0x%08X!' % self.rip);
            #end-if
              
            self.instructions[i] = '%s %s, %s' % (mnemonic, engine.reg_name(out_reg), engine.reg_name(rhs.reg));
                
            print(self.instructions[i]);
          #end-if
        case 'lea':
          lhs = ins.operands[0];
          rhs = ins.operands[1];
          
          if (lhs.type == X86_OP_REG) and (rhs.type == X86_OP_MEM) and (rhs.mem.base == X86_REG_RIP):
            # Prepare address for a jump to next chunk!
            self.instructions[i] = ('lea %s, [chunk_id_%d]' % (engine.reg_name(lhs.reg), chunk_id + 1));
          #end-if
        case 'jmp':
          operand = ins.operands[0];
            
          if operand.type == X86_OP_REG:
            self.chunk_transition_found = True;
          #end-if
        #end-cases
      #end-match
    #end-for
  #end-def
  
  def debug_print(self, engine):
    print('  REG:');
    for k in self.reg_first_write_dict.keys():
      print('    %s: %d' % (engine.reg_name(k), self.reg_first_write_dict[k]));
    #end-for
    
    print('  CTX:');
    for k in self.ctx_last_read_dict.keys():
      print('    %s: %d' % (engine.reg_name(k), self.ctx_last_read_dict[k]));
    #end-for
    
    print('  Unused:');
    for k in self.unused_regs:
      print('    %s' % engine.reg_name(k));
    #end-for
    
    conflicts = [];
    for k in self.ctx_last_read_dict.keys():
      if (k in self.reg_first_write_dict) and (self.reg_first_write_dict[k] < self.ctx_last_read_dict[k]):
        conflicts.append(k);
      #end-if
    #end-for
    
    if len(conflicts) > 0:
      print('  Conflicts:');
      for k in conflicts:
        print('    %s' % engine.reg_name(k));
      #end-for
    #end-if
  #end-def
#end-class

class Parser:
  def __init__(self, shellcode):
    self.engine = Cs(CS_ARCH_X86, CS_MODE_64);
    self.engine.detail = True;
    
    self.shellcode = bytearray(shellcode);
    self.rip = 0;
    
    self.blocks = [];
    self.curr_block = None;
    
    self.data_offset = None;
  #end-def

  def run(self):
    while True:
      if (self.data_offset and (self.rip >= self.data_offset)) or (self.shellcode[self.rip] == 0x90) or (readUInt32LE(self.shellcode, self.rip) == 0): # nop or end of the code part
        break;
      elif (readUInt32BE(self.shellcode, self.rip) == 0x660F7E05) and ((skip := self.ctx_io_skip()) > 0): # CTX storage operations detection
        self.rip += skip;

        self.curr_block = Block(self);
        self.blocks.append(self.curr_block);
      else:
        self.step();
      #end-if
    #end-def
    
    fp = open('deobf-L2-01.txt', 'w');
    
    fp.write('BITS 64\nDEFAULT REL\n\n');
    
    chunk_id = 1;
    for blk in self.blocks:
      blk.transform(self.engine, chunk_id);
      
      # blk.debug_print(self.engine);
      
      for item in blk.inserted_prologue:
        fp.write(' %s\n' % item);
      #end-for
      
      for item in blk.instructions:
        if not item:
          continue; # Removed dummy.
        #end-if
      
        if type(item) == str:
          line = item;
        else:
          line = ('%s %s' % (item.mnemonic, item.op_str));
        #end-if
        
        fp.write(' %s\n' % line.replace(' ptr ', ' ').replace('movabs ', 'mov '));
      #end-for

      if blk.chunk_transition_found:
        chunk_id += 1;
        fp.write('chunk_id_%d:\n' % chunk_id);
      #end-if
    #end-if
    
    fp.close();
  #end-def
  
  def dis1(self):
    return next(self.engine.disasm(self.shellcode[self.rip:], self.rip, 1));
  #end-def
  
  def ctx_io_skip(self):
    if self.shellcode[self.rip + 7] != 0:
      return 0;
    #end-if
    
    for i in range(0x8): # RAX to RDI
      if (readUInt16BE(self.shellcode, self.rip + 8 + i * 7) != 0x4889) or (((self.shellcode[self.rip + 8 + i * 7 + 2] >> 3) & 0x7) != i) or (self.shellcode[self.rip + 8 + i * 7 + 6] != 0):
        return 0;
      #end-if
    #end-for
    
    for i in range(0x8): # R8 to R15
      if (readUInt16BE(self.shellcode, self.rip + 0x40 + i * 7) != 0x4C89) or (((self.shellcode[self.rip + 0x40 + i * 7 + 2] >> 3) & 0x7) != i) or (self.shellcode[self.rip + 0x40 + i * 7 + 6] != 0):
        return 0;
      #end-if
    #end-for
    
    if not self.data_offset:
      ins = self.dis1();
      
      # It must be `movd [rip + 0xXYZZY], xmm0`.
      self.data_offset = ins.size + ins.operands[0].mem.disp;
    return 0x78;
  #end-def
  
  def step(self):
    ins = self.dis1();
    self.rip += ins.size;
    
    self.curr_block.update(ins);
  #end-def
#end-class

def __main__():
  fp = open('deobf03.bin', 'rb');
  buf = fp.read();
  fp.close();
  
  parser = Parser(buf);
  parser.run();
#end-def

if __name__ == '__main__':
  __main__();
#end-if
