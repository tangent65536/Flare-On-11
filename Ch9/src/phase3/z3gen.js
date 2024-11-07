'use strict';

const fs = require('fs');

let idx = parseInt(process.argv[2]);

let output = ['from z3 import *;', 'solver = Solver();'];

let var_arr = [];
for(let i = 0 ; i < 8 ; i++)
{
  var_arr.push(`F${idx + (i << 2)}`);
}

output.push(`(${var_arr.join()}) = BitVecs('${var_arr.join(' ')}', 32)`);

for(let i = 0 ; i < 8 ; i++)
{
  let obj = JSON.parse(fs.readFileSync(`constants/test${idx + (i << 2) + 1}.json`));
  let expr = '0';
  for(let j = 0 ; j < obj.flag_idx_seq.length ; j++)
  {
    let char_idx = obj.flag_idx_seq[j];
    expr = `(${expr}) ${obj.flag_mult_op[char_idx]} (${obj.flag_mult_const[char_idx]} * F${char_idx})`;
    expr = `(${expr}) ${obj.const_ops[j]} ${obj.constants[j]}`;
  }
  expr = `(${expr}) ${obj.const_ops[8]} ${obj.constants[8]} == 0`;
  output.push(`solver.add(${expr});`);
}

for(let i = 0 ; i < 8 ; i++)
{
  output.push(`solver.add(ULT(F${idx + (i << 2)}, 0x100));`);
}

output.push('print(solver.check());');
output.push('ans = solver.model();');
output.push('print(ans)');

fs.writeFileSync('test.py', output.join('\n'));
