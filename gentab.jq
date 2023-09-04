[ [(keys | .[])]
, [(.[] | .mnemonic)]
, [(.[] | .length)]
, [(.[] | .operand1 | if . == null then "none" else . end)]
, [(.[] | .operand2 | if . == null then "none" else . end)]
]
| transpose
| .[]
| @tsv
