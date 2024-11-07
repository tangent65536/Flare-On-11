'use strict';

const fs = require('fs');

class AddressReader
{
  constructor()
  {
    let serpentine = fs.readFileSync('../serpentine.exe').subarray(0x20400, 0x896C00);
    this.serpentine = Buffer.concat([serpentine, Buffer.alloc(0x885000 - serpentine.length)]);
  }

  read_pointer(pointer_in)
  {
    let pos_in = pointer_in - 0x140022000n;
    if(pos_in < 0n || pos_in >= this.serpentine.length)
    {
      throw new Error(`Invalid read address! (0x${pointer_in.toString(16)})`);
    }
    if(pos_in & 0x7n)
    {
      console.warn(`Unaligned pointer! (0x${pointer_in.toString(16)})`);
    }
    return this.serpentine.readBigUInt64LE(parseInt(pos_in));
  }

  read_bytes(pointer_in, size)
  {
    pointer_in -= 0x140022000n;
    if(pointer_in < 0n || pointer_in >= (this.serpentine.length - size))
    {
      throw new Error(`Invalid read address! (0x${pointer_in.toString(16)})`);
    }
    return this.serpentine.subarray(parseInt(pointer_in), parseInt(pointer_in + BigInt(size)));
  }
}

const SboxTypes = {
  // No 0 so we can use boolean override.
  NOP: 1, // Simply 0 to 255
  LINEAR: 2, // Add/minus
  CARRY_ADD: 3,
  CARRY_MINUS: 4,
  XOR: 5,
  ZEROS: 6 // Plain zeros, likely for NOP add carry. Usually sits in uninitialized regions.
};

function detect_sbox_type(sbox)
{
  let ret = SboxTypes.ZEROS;

  let i = 0;
  for(i = 0 ; i < sbox.length ; i++)
  {
    if(sbox[i])
    {
      ret = null;
      break;
    }
  }

  if(ret) // Still valid -> it's good!
  {
    return ret;
  }

  if(!sbox[0])
  {
    ret = SboxTypes.CARRY_ADD;
  }
  else if(sbox[0] == 1)
  {
    ret = SboxTypes.CARRY_MINUS;
  }

  for(i = 0 ; i < sbox.length ; i++)
  {
    if(sbox[i] > 1)
    {
      ret = null;
      break; // NOP, LINEAR or XOR
    }
  }

  if(ret) // Still valid -> it's good!
  {
    return ret;
  }

  ret = SboxTypes.NOP;
  for(i = 0 ; i < sbox.length ; i++)
  {
    if(sbox[i] !== i)
    {
      ret = null;
      break; // LINEAR or XOR
    }
  }

  if(ret) // Still valid -> it's good!
  {
    return ret;
  }

  ret = SboxTypes.LINEAR;
  for(i = 1 ; i < sbox.length ; i++)
  {
    if(((sbox[i] - sbox[i - 1]) & 0xFF) !== 1)
    {
      ret = SboxTypes.XOR; // Not linear -> must be XOR.
      break;
    }
  }

  return ret;
}

// Basically get the position where the 0/1 swaps.
function sbox_carry_get_value(sbox)
{
  for(let i = 1 ; i < sbox.length ; i++)
  {
    if(sbox[i] !== sbox[0])
    {
      return i;
    }
  }
  console.warn('The sbox has a constant value of %d. Is it a sbox?', sbox[0]);
  return sbox.length;
}

let arr = fs.readFileSync(`inputs/test${process.argv[2]}.txt`).toString('ascii').split(/\r?\n/g);

// States
let flag_idx = -1;
let flag_idx_seq = [];
let flag_mult_const = {};
let flag_mult_op = {}; // '+', '-' or '^'

let constants = [];
let const_ops = [];

let cache_dup_sbox_carry = {};
let cache_dup_sbox_data = {};
let cache_const_shard = null;
let cache_const_op = null;
let cache_constant = new Uint32Array(1);
let cache_const_mark = 0;
let cache_force_flush = false;
// End of states

let reader = new AddressReader();

let tokens = [];
for(let i = 0 ; i < arr.length ; i++)
{
  let line = arr[i].replaceAll(/(_mm_cvtsi32_si128|_mm_cvtsi128_si32)/g, '').replaceAll(/[\(\)]/g, ' ').replaceAll(/\s+/g, ' ').trim();
  tokens = tokens.concat(line.split(' '));
}

for(let i = 0 ; i < tokens.length ; i++)
{
  if(const_ops.length >= 9)
  {
    // Assumes that there are only 8 flag-operations and 9 constants per code chunk.
    break;
  }

  let token = tokens[i];
  if(token.indexOf('_140') >= 0)
  {
    if(token.indexOf('flag_14089B8E8') >= 0)
    {
      let idx = parseInt(token.substring(15, token.length - 1));
      if(idx != flag_idx)
      {
        flag_idx = idx;
        flag_idx_seq.push(idx);
      }

      // TODO: Backtrack the multiplication constant and operator.
      let mark_detect_op = false;
      for(let j = 1 ; j <= Math.min(i, 8) ; j++)
      {
        if(mark_detect_op)
        {
          switch(tokens[i - j])
          {
            case '=': // Either a '+' or a '^'
            case '+':
            {
              let mark_xor_detected = false;
              let k = 0;
              for(k = 1 ; k < 12 ; k++)
              {
                // console.log('%s :: %s', token, tokens[i + k])

                if(mark_xor_detected)
                {
                  if(tokens[i + k] == '<<')
                  {
                    switch(tokens[i + k + 1])
                    {
                      case '40':
                      case '48':
                      case '56':
                      {
                        flag_mult_op[flag_idx] = '^';
                        break;
                      }
                    }
                  }
                  else if(tokens[i + k].endsWith(';'))
                  {
                    // Detect if the previous "sum" is just a variable in the line.
                    flag_mult_op[flag_idx] = '^';
                    break;
                  }
                }
                else
                {
                  if(tokens[i + k] == '^')
                  {
                    mark_xor_detected = true;
                  }
                  else if(tokens[i + k].endsWith(';'))
                  {
                    // Line ended, not XOR.
                    break;
                  }
                }
              }
              if(flag_mult_op[flag_idx] == '^')
              {
                // Skip operations involving xoring the previously computed "sum". Disabled due to bug.
                // i += (k - 1);
              }
              else
              {
                flag_mult_op[flag_idx] = '+'; // Assume it's a plus instead.
              }
              break;
            }
            /*
            case '+':
            {
              flag_mult_op[flag_idx] = '+';
              break;
            }
             */
            case '-':
            {
              flag_mult_op[flag_idx] = '-';
              break;
            }
          }
          if(flag_mult_op[flag_idx])
          {
            console.log('Found flag operation %s 0x%s * FLAG[%d]', flag_mult_op[flag_idx], flag_mult_const[flag_idx].toString(16), flag_idx);
            break; // Break out the loop.
          }
        }

        if((tokens[i - j].endsWith('LL')) && (tokens[i - j].indexOf('FFFF') < 0) && (tokens[i - j + 1] == '*'))
        {
          let cache = tokens[i - j];
          let parsed = parseInt(cache.substring(0, cache.length - 2));

          if(flag_mult_const[flag_idx])
          {
            if(parsed != flag_mult_const[flag_idx])
            {
              throw new Error('Multiplication const conflict for flag idx %d!', flag_idx);
            }
            // Constant already set and still holds -> ignore!
            mark_detect_op = true;
            continue;
          }

          mark_detect_op = true;
          flag_mult_const[flag_idx] = parsed;
          // console.log('Found mult constant for flag idx %d: 0x%s', flag_idx, parsed.toString(16));
          continue;
        }
      }
      continue;
    }
    else
    {
      // An sbox operation occurred!

      let addr0 = BigInt(`0x${token.split('_').pop().split(';')[0]}`);
      if(addr0 == 0x1400011F0n) // Jump addr, ignore.
      {
        continue;
      }
      let sbox_addr = reader.read_pointer(addr0);
      let sbox = reader.read_bytes(sbox_addr, 0x100);
      let sbox_type = detect_sbox_type(sbox);

      let order = -1;
      for(let j = 1 ; j < 8 ; j++)
      {
        if(tokens[i + j].endsWith(';'))
        {
          order = 0;
          break;
        }

        if(tokens[i + j] == '<<')
        {
          let _int = parseInt(tokens[i + j + 1]);
          if(!isNaN(_int))
          {
            order = _int;
            break;
          }
        }
      }
      if(order & 0x7)
      {
        throw new Error(`Invalid order (${order}) for SBOX at address 0x${addr0.toString(16)}!`);
      }

      switch(sbox_type)
      {
        case SboxTypes.NOP:
        {
          if(order >= 0x20)
          {
            if(cache_constant[0])
            {
              cache_force_flush = true;
            }
            break;
          }
          // If the order is less than 32-bit, treat it as linear (add 0 or minus 0).
        }
        case SboxTypes.LINEAR:
        {
          if(order >= 0x20)
          {
            // Ignore over-32-bit values, also force flush cache.
            if(cache_constant[0])
            {
              cache_force_flush = true;
            }
            break;
          }

          if(cache_dup_sbox_data[order] == addr0)
          {
            // Likely an IDA hiccup -> ignore.
            break;
          }
          cache_dup_sbox_data[order] = addr0;

          if(cache_const_shard)
          {
            if((cache_const_shard.order == order) && (cache_const_shard.address == addr0))
            {
              // Likely an IDA hiccup -> ignore.
              break;
            }

            if((cache_const_shard.order - 8) !== order)
            {
              throw new Error(`Order (${order}) mismatch for SBOX at address 0x${addr0.toString(16)}!`);
            }

            let carry_offset = sbox_carry_get_value(cache_const_shard.sbox);
            switch(cache_const_shard.type)
            {
              case SboxTypes.CARRY_ADD:
              case SboxTypes.CARRY_MINUS:
              {
                if((carry_offset + sbox[0]) !== 0x100)
                {
                  throw new Error(`SBOX carry/value mismatch for SBOX at address 0x${addr0.toString(16)}!`);
                }
                cache_const_shard.sbox = sbox;
                cache_const_shard.order = order;
                cache_const_shard.flush = true;
                break;
              }
              default:
              {
                throw new Error(`SBOX cache types mismatch for SBOX at address 0x${addr0.toString(16)}!`);
              }
            }
          }
          else
          {
            cache_const_shard = {
              sbox: sbox,
              type: sbox_type,
              order: order,
              address: addr0,
              flush: false
            };
          }
          break;
        }
        case SboxTypes.ZEROS:
        {
          if(order > 0x20)
          {
            break;
          }
          // Maybe corresponding to add/minus 0.
          sbox_type = SboxTypes.CARRY_ADD;
        }
        case SboxTypes.CARRY_ADD:
        case SboxTypes.CARRY_MINUS:
        {
          if(order > 0x20)
          {
            // Ignore over-32-bit values, also force flush cache.
            if(cache_constant[0])
            {
              cache_force_flush = true;
            }
            break;
          }

          if(cache_dup_sbox_carry[order] == addr0)
          {
            // Likely an IDA hiccup -> ignore.
            break;
          }
          cache_dup_sbox_carry[order] = addr0;

          if(cache_const_shard)
          {
            if((cache_const_shard.order == order) && (cache_const_shard.address == addr0))
            {
              // Likely an IDA hiccup -> ignore.
              break;
            }

            if((cache_const_shard.order + 8) !== order)
            {
              console.log(cache_const_shard);
              throw new Error(`Order (${order}) mismatch for SBOX at address 0x${addr0.toString(16)}!`);
            }

            if(cache_const_shard.type !== SboxTypes.LINEAR)
            {
              throw new Error(`SBOX cache types mismatch for SBOX at address 0x${addr0.toString(16)}!`);
            }

            let carry_offset = sbox_carry_get_value(sbox);
            if((carry_offset + cache_const_shard.sbox[0]) !== 0x100)
            {
              throw new Error(`SBOX carry/value mismatch for SBOX at address 0x${addr0.toString(16)}!`);
            }

            cache_const_shard.type = sbox_type;
            cache_const_shard.flush = true;
          }
          else
          {
            cache_const_shard = {
              sbox: sbox,
              type: sbox_type,
              order: order,
              address: addr0,
              flush: false
            };
          }
          break;
        }
        case SboxTypes.XOR:
        {
          if(cache_dup_sbox_data[order] == addr0)
          {
            // Likely an IDA hiccup -> ignore.
            break;
          }
          cache_dup_sbox_data[order] = addr0;

          if(cache_const_shard)
          {
            if((cache_const_shard.type == SboxTypes.LINEAR) && !(cache_const_shard.sbox[0] & 0x7F))
            { // EDGE CASE!
              // For LINEAR boxes starting with 0x00 or 0x80, the XOR operation would be the same.
              // Thus, we just flush the last cached byte and update the operator.
              
              cache_const_op = '^';
              
              cache_constant[0] |= (cache_const_shard.sbox[0] << cache_const_shard.order);
              cache_const_mark++;
              
              cache_const_shard = null;
            }
            else
            {
              throw new Error(`Unexpected cache-conflict SBox at address 0x${addr0.toString(16)}!`);
            }
          }

          cache_const_shard = {
            sbox: sbox,
            type: sbox_type,
            order: order,
            address: addr0,
            flush: true
          };

          break;
        }
        default:
        {
          throw new Error(`Unexpected SBox type at address 0x${addr0.toString(16)}!`);
        }
      }

      if((cache_const_shard && cache_const_shard.flush) || cache_force_flush)
      {
        if(cache_const_shard && cache_const_shard.flush)
        {
          if((cache_constant[0] >>> cache_const_shard.order) & 0xFF)
          {
            throw new Error(`Unexpected cache order duplicate at address 0x${addr0.toString(16)}!`);
          }

          switch(cache_const_shard.type)
          {
            case SboxTypes.XOR:
            {
              if(cache_const_op)
              {
                if(cache_const_op !== '^')
                {
                  throw new Error(`Unexpected cached operator at address 0x${addr0.toString(16)}!`);
                }
              }
              else
              {
                cache_const_op = '^';
              }

              cache_constant[0] |= (cache_const_shard.sbox[0] << cache_const_shard.order);

              break;
            }
            case SboxTypes.CARRY_ADD:
            {
              if(cache_const_op)
              {
                if(cache_const_op !== '+')
                {
                  throw new Error(`Unexpected cached operator at address 0x${addr0.toString(16)}!`);
                }
              }
              else
              {
                cache_const_op = '+';
              }

              cache_constant[0] |= (cache_const_shard.sbox[0] << cache_const_shard.order);

              break;
            }
            case SboxTypes.CARRY_MINUS:
            {
              if(cache_const_op)
              {
                if(cache_const_op !== '-')
                {
                  throw new Error(`Unexpected cached operator at address 0x${addr0.toString(16)}!`);
                }
              }
              else
              {
                cache_const_op = '-';
              }

              cache_constant[0] |= ((0x100 - cache_const_shard.sbox[0]) << cache_const_shard.order);

              break;
            }
            default:
            {
              throw new Error(`Unexpected cached SBox type at address 0x${addr0.toString(16)}!`);
            }
          }

          cache_const_shard = null;
          cache_const_mark++;
        }

        if((cache_const_mark >= 4) || cache_force_flush)
        {
          if(cache_const_shard) // Again, the edge case XOR with 0x00 or 0x80
          {
            cache_constant[0] |= (cache_const_shard.sbox[0] << cache_const_shard.order);
            
            cache_const_shard = null;
          }
          
          if(cache_constant[0])
          {
            constants.push(cache_constant[0]);
            const_ops.push(cache_const_op);

            console.log('Detected new constant operation %s 0x%s', cache_const_op, cache_constant[0].toString(16));

            cache_constant[0] = 0;
            cache_const_op = null;

            cache_const_mark = 0;

            cache_dup_sbox_data = {};
            cache_dup_sbox_carry = {};
          
            cache_force_flush = false;
          }
        }
      }
    }
  }
}

fs.writeFileSync(`outputs/test${process.argv[2]}.json`, JSON.stringify({
  flag_idx_seq: flag_idx_seq,
  flag_mult_const: flag_mult_const,
  flag_mult_op: flag_mult_op,
  constants: constants,
  const_ops: const_ops
}));

/*
console.log(flag_idx_seq);
console.log(flag_mult_const)
console.log(flag_mult_op)

console.log(constants);
console.log(const_ops);
*/
