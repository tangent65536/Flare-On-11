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
    'SYSWRITE'
  ];

  globalThis.opcodes_map = {};
  for(let i = 0 ; i < opcodes.length ; i++)
  {
    if(opcodes[i])
      opcodes_map[opcodes[i]] = i;
  }

  globalThis.opcodes_stack_chg = [NaN, 1, 1, 1, -1, 0, -2, 1, -1, -1, 0, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, NaN, NaN, NaN, NaN, NaN, NaN];
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
  while(pos < vm_buf.length)
  {
    pos0 = pos;
    let opc = vm_buf[pos++];
    let val = null;
    switch(opc)
    {
      case opcodes_map.LDCONST:
      case opcodes_map.LDCONSTPTR:
      case opcodes_map.ADDCONSTPTR:
      case opcodes_map.STCONSTPTR:
      case opcodes_map.ADDCONST:
      case opcodes_map.BR:
      case opcodes_map.BRTRUE:
      case opcodes_map.BRFALSE:
      case opcodes_map.GECONST:
      {
        // This vm uses BIG ENDIAN!
        val = vm_buf.readUInt16BE(pos);
        pos += 2;
        console.log('0x%s:\t%s\t0x%s', `000${pos0.toString(16)}`.slice(-3), opcodes[opc], val.toString(16));
        break;
      }
      case opcodes_map.LDPTR:
      case opcodes_map.STPTR:
      case opcodes_map.DUP:
      case opcodes_map.POP:
      case opcodes_map.ADD:
      case opcodes_map.SUB:
      case opcodes_map.DIV:
      case opcodes_map.MUL:
      case opcodes_map.EQ:
      case opcodes_map.LT:
      case opcodes_map.LE:
      case opcodes_map.GT:
      case opcodes_map.GE:
      case opcodes_map.MAGIK1:
      case opcodes_map.RET:
      case opcodes_map.MAGIK2:
      case opcodes_map.XOR:
      case opcodes_map.OR:
      case opcodes_map.AND:
      case opcodes_map.MOD:
      case opcodes_map.SHL:
      case opcodes_map.SHR:
      case opcodes_map.ROL32:
      case opcodes_map.ROR32:
      case opcodes_map.ROL16:
      case opcodes_map.ROR16:
      case opcodes_map.ROL8:
      case opcodes_map.ROR8:
      case opcodes_map.SYS_WRITE:
      {
        console.log('0x%s:\t%s', `000${pos0.toString(16)}`.slice(-3), opcodes[opc]);
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
    console.log('Current stack size: %d', stack_tracker);
  }
  console.log('Max stack size: %d', stack_max);
}

if(require.main === module)
{
  __init__();
  __main__(process.argv.slice(2));
}
