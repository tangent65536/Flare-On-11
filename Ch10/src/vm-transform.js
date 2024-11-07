'use strict';

const fs = require('fs');
const path = require('path');

function __init__()
{
  globalThis.opcodes = [
    null,
    'LDCONST',
    'LDCONSTPTR',
    'ADDCONSTPTR',
    'STCONSTPTR',
    'LDPTR',
    'STPTR',
    'DUP',
    'POP',
    'ADD',
    'ADDCONST',
    'SUB',
    'DIV',
    'MUL',
    'BR',
    'BRTRUE',
    'BRFALSE',
    'EQ',
    'LT',
    'LE',
    'GT',
    'GE',
    'GECONST',
    'MAGIK1',
    'RET',
    'MAGIK2',
    'XOR',
    'OR',
    'AND',
    'MOD',
    'SHL',
    'SHR',
    'ROL32',
    'ROR32',
    'ROL16',
    'ROR16',
    'ROL8',
    'ROR8',
    'SYS_WRITE'
  ];

  globalThis.opcodes_map = {};
  for(let i = 0 ; i < opcodes.length ; i++)
  {
    if(opcodes[i])
      opcodes_map[opcodes[i]] = i;
  }

  globalThis.opcodes_stack_chg = [NaN, 1, 1, 0, -1, 0, -2, 1, -1, -1, 0, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, NaN, NaN, NaN, NaN, NaN, NaN];

  globalThis.opcodes_have_val = new Set([
    opcodes_map.LDCONST,
    opcodes_map.LDCONSTPTR,
    opcodes_map.ADDCONSTPTR,
    opcodes_map.STCONSTPTR,
    opcodes_map.ADDCONST,
    opcodes_map.BR,
    opcodes_map.BRTRUE,
    opcodes_map.BRFALSE,
    opcodes_map.GECONST
  ]);
  globalThis.opcodes_stack_only = new Set([
    opcodes_map.LDPTR,
    opcodes_map.STPTR,
    opcodes_map.DUP,
    opcodes_map.POP,
    opcodes_map.ADD,
    opcodes_map.SUB,
    opcodes_map.DIV,
    opcodes_map.MUL,
    opcodes_map.EQ,
    opcodes_map.LT,
    opcodes_map.LE,
    opcodes_map.GT,
    opcodes_map.GE,
    opcodes_map.MAGIK1,
    opcodes_map.RET,
    opcodes_map.MAGIK2,
    opcodes_map.XOR,
    opcodes_map.OR,
    opcodes_map.AND,
    opcodes_map.MOD,
    opcodes_map.SHL,
    opcodes_map.SHR,
    opcodes_map.ROL32,
    opcodes_map.ROR32,
    opcodes_map.ROL16,
    opcodes_map.ROR16,
    opcodes_map.ROL8,
    opcodes_map.ROR8,
    opcodes_map.SYS_WRITE
  ]);

  globalThis.prologue = [
    'BITS 64',
    '',
    ' push r15',
    ' push r14',
    ' push r13',
    ' push r12',
    ' sub rsp, 0x1000'
  ];

  globalThis.epilogue = [
    ' add rsp, 0x1000',
    ' pop r12',
    ' pop r13',
    ' pop r14',
    ' pop r15'
  ];

  globalThis.placeholders = [0xBBAA, 0xDDCC, 0xFFEE, 0xADDE, 0xEFBE, 0xFECA, 0xBEBA, 0xCDAB, NaN];
}

function __main__(args)
{
  if(args.length !== 1)
  {
    console.log('Usage: %s <path/to/file.c4tb>', path.basename(__filename));
    return;
  }

  let buf0 = fs.readFileSync(args[0]);
  let vm_off = buf0.readUInt32LE(8);
  let vm_buf = buf0.subarray(vm_off, vm_off + buf0.readUInt32LE(12));

  let stack_tracker = 0;
  let stack_max = 0;
  let pos = 0;
  let pos0 = 0;
  let transpiled = Array.from(prologue);
  let placeholder_idx = 0;
  while(pos < vm_buf.length)
  {
    pos0 = pos;
    let opc = vm_buf[pos++];
    let val = null;

    if(opcodes_have_val.has(opc))
    {
      // This vm uses BIG ENDIAN!
      val = vm_buf.readUInt16BE(pos);
      pos += 2;
      console.log('0x%s:\t%s\t0x%s', `000${pos0.toString(16)}`.slice(-3), opcodes[opc], val.toString(16));
    }

    if(opcodes_stack_only.has(opc))
    {
      console.log('0x%s:\t%s', `000${pos0.toString(16)}`.slice(-3), opcodes[opc]);
    }

    transpiled.push(`label_0x${pos0.toString(16)}:`);
    switch(opc)
    {
      case opcodes_map.LDCONST:
      {
        if(val == placeholders[placeholder_idx])
        {
          transpiled.push(` movzx r${8 + stack_tracker}, word [rdi + ${placeholder_idx << 1}]`);
          placeholder_idx++;
        }
        else
        {
          transpiled.push(` mov r${8 + stack_tracker}, ${val}`);
        }
        break;
      }
      case opcodes_map.LDCONSTPTR:
      {
        transpiled.push(` mov r${8 + stack_tracker}, ${val}`);
        transpiled.push(` mov r${8 + stack_tracker}, qword [rsp + r${8 + stack_tracker} * 8]`);
        break;
      }
      case opcodes_map.ADDCONSTPTR:
      {
        transpiled.push(` mov r${8 + stack_tracker}, ${val}`);
        transpiled.push(` add r${8 + stack_tracker - 1}, qword [rsp + r${8 + stack_tracker} * 8]`);
        break;
      }
      case opcodes_map.STCONSTPTR:
      {
        transpiled.push(` mov r${8 + stack_tracker}, ${val}`);
        transpiled.push(` mov qword [rsp + r${8 + stack_tracker} * 8], r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.ADDCONST:
      {
        transpiled.push(` add r${8 + stack_tracker - 1}, ${val}`);
        break;
      }
      case opcodes_map.BR:
      {
        transpiled.push(` jmp label_0x${val.toString(16)}`);
        break;
      }
      case opcodes_map.BRTRUE:
      {
        transpiled.push(` test r${8 + stack_tracker - 1}, r${8 + stack_tracker - 1}`);
        transpiled.push(` jnz label_0x${val.toString(16)}`);
        break;
      }
      case opcodes_map.BRFALSE:
      {
        transpiled.push(` test r${8 + stack_tracker - 1}, r${8 + stack_tracker - 1}`);
        transpiled.push(` jz label_0x${val.toString(16)}`);
        break;
      }
      case opcodes_map.GECONST:
      {
        transpiled.push(` cmp r${8 + stack_tracker - 1}, ${val}`);
        transpiled.push(` setge r${8 + stack_tracker - 1}b`);
        transpiled.push(` movzx r${8 + stack_tracker - 1}, r${8 + stack_tracker - 1}b`);
        break;
      }
      case opcodes_map.LDPTR:
      {
        transpiled.push(` mov r${8 + stack_tracker - 1}, qword [rsp + r${8 + stack_tracker - 1} * 8]`);
        break;
      }
      case opcodes_map.STPTR:
      {
        transpiled.push(` mov qword [rsp + r${8 + stack_tracker - 2} * 8], r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.DUP:
      {
        transpiled.push(` mov r${8 + stack_tracker}, r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.POP:
      {
        transpiled.push(` nop`);
        break;
      }
      case opcodes_map.ADD:
      {
        transpiled.push(` add r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.SUB:
      {
        transpiled.push(` sub r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.DIV:
      {
        transpiled.push(` mov rax, r${8 + stack_tracker - 2}`);
        transpiled.push(` xor rdx, rdx`);
        transpiled.push(` div r${8 + stack_tracker - 1}`);
        transpiled.push(` mov r${8 + stack_tracker - 2}, rax`);
        break;
      }
      case opcodes_map.MUL:
      {
        transpiled.push(` mov rax, r${8 + stack_tracker - 2}`);
        transpiled.push(` imul r${8 + stack_tracker - 1}`);
        transpiled.push(` mov r${8 + stack_tracker - 2}, rax`);
        break;
      }
      case opcodes_map.EQ:
      {
        transpiled.push(` cmp r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        transpiled.push(` sete r${8 + stack_tracker - 2}b`);
        transpiled.push(` movzx r${8 + stack_tracker - 2}, r${8 + stack_tracker - 2}b`);
        break;
      }
      case opcodes_map.LT:
      {
        transpiled.push(` cmp r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        transpiled.push(` setl r${8 + stack_tracker - 2}b`);
        transpiled.push(` movzx r${8 + stack_tracker - 2}, r${8 + stack_tracker - 2}b`);
        break;
      }
      case opcodes_map.LE:
      {
        transpiled.push(` cmp r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        transpiled.push(` setle r${8 + stack_tracker - 2}b`);
        transpiled.push(` movzx r${8 + stack_tracker - 2}, r${8 + stack_tracker - 2}b`);
        break;
      }
      case opcodes_map.GT:
      {
        transpiled.push(` cmp r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        transpiled.push(` setg r${8 + stack_tracker - 2}b`);
        transpiled.push(` movzx r${8 + stack_tracker - 2}, r${8 + stack_tracker - 2}b`);
        break;
      }
      case opcodes_map.GE:
      {
        transpiled.push(` cmp r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        transpiled.push(` setge r${8 + stack_tracker - 2}b`);
        transpiled.push(` movzx r${8 + stack_tracker - 2}, r${8 + stack_tracker - 2}b`);
        break;
      }
      case opcodes_map.RET:
      {
        transpiled.push(` ret`);
        break;
      }
      case opcodes_map.MAGIK1:
      case opcodes_map.MAGIK2:
      {
        transpiled.push(` mov rax, r${8 + stack_tracker - 1}`);
        for(let z = 0 ; z < epilogue.length ; z++)
        {
          transpiled.push(epilogue[z]);
        }
        break;
      }
      case opcodes_map.XOR:
      {
        transpiled.push(` xor r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.OR:
      {
        transpiled.push(` or r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.AND:
      {
        transpiled.push(` and r${8 + stack_tracker - 2}, r${8 + stack_tracker - 1}`);
        break;
      }
      case opcodes_map.MOD:
      {
        transpiled.push(` mov rax, r${8 + stack_tracker - 2}`);
        transpiled.push(` xor rdx, rdx`);
        transpiled.push(` div r${8 + stack_tracker - 1}`);
        transpiled.push(` mov r${8 + stack_tracker - 2}, rdx`);
        break;
      }
      case opcodes_map.SHL:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` shl r${8 + stack_tracker - 2}, cl`);
        break;
      }
      case opcodes_map.SHR:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` shr r${8 + stack_tracker - 2}, cl`);
        break;
      }
      case opcodes_map.ROL32:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` rol r${8 + stack_tracker - 2}d, cl`);
        break;
      }
      case opcodes_map.ROR32:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` ror r${8 + stack_tracker - 2}d, cl`);
        break;
      }
      case opcodes_map.ROL16:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` rol r${8 + stack_tracker - 2}w, cl`);
        break;
      }
      case opcodes_map.ROR16:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` ror r${8 + stack_tracker - 2}w, cl`);
        break;
      }
      case opcodes_map.ROL8:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` rol r${8 + stack_tracker - 2}b, cl`);
        break;
      }
      case opcodes_map.ROR8:
      {
        transpiled.push(` movzx rcx, r${8 + stack_tracker - 1}b`);
        transpiled.push(` ror r${8 + stack_tracker - 2}b, cl`);
        break;
      }
      case opcodes_map.SYS_WRITE:
      {
        transpiled.push(` movzx rdi, r${8 + stack_tracker - 1}b`);
        transpiled.push(` call _syswrite`);
        break;
      }
      default:
      {
        console.error('Unknown opcode 0x%s at position 0x%s! Abort!', opc.toString(16), pos0.toString(16));
        return;
      }
    }
    stack_tracker += opcodes_stack_chg[opc];
    if(stack_tracker > stack_max)
    {
      stack_max = stack_tracker;
    }
    console.log('# Current stack size: %d', stack_tracker);
  }
  console.log('# Max stack size: %d', stack_max);

  fs.writeFileSync(`${args[0]}.asm`, transpiled.join('\n'));
}

if(require.main === module)
{
  __init__();
  __main__(process.argv.slice(2));
}
