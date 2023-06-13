#!/bin/sh -e

emitparam() {
    n="$1"
    OP="$2"

    case "$OP" in
        null)
            printf "        .param${n}kind = PARAM_NONE,\n"
            ;;
        \(a16\))
            printf "        .param${n}kind = PARAM_INDIR | PARAM_A16,\n"
            ;;
        a16)
            printf "        .param${n}kind = PARAM_A16,\n"
            ;;
        d16)
            printf "        .param${n}kind = PARAM_D16,\n"
            ;;
        d8)
            printf "        .param${n}kind = PARAM_D8,\n"
            ;;
        r8)
            printf "        .param${n}kind = PARAM_R8,\n"
            ;;
        \(a8\))
            printf "        .param${n}kind = PARAM_INDIR | PARAM_A8,\n"
            ;;
        SP\+r8)
            printf "        .param${n}kind = PARAM_SPPLUSR8,\n"
            ;;
        *)
            printf "        .param${n}kind = PARAM_STR,\n"
            printf "        .param${n}.str = \"%s\",\n" $OP
            ;;
    esac
}

echo "INFO: Building unprefixed instruction table..." >&2
printf "struct instdef unprefixed_instructions[256] = {\n"

for code in $(jq -r '.unprefixed | keys | .[]' < opcodes.json);
do
    printf "    [%s] = {\n" $code
    printf "        .mnem = \"%s\",\n" $(jq -r ".unprefixed.\"${code}\".mnemonic" < opcodes.json)
    printf "        .len = %s,\n" $(jq -r ".unprefixed.\"${code}\".length" < opcodes.json)
    OP1=$(jq -r ".unprefixed.\"${code}\".operand1" < opcodes.json)
    OP2=$(jq -r ".unprefixed.\"${code}\".operand2" < opcodes.json)
    emitparam 0 "${OP1}"
    emitparam 1 "${OP2}"
    printf "    },\n"
done

printf "};\n"


echo "INFO: Building CB prefixed instruction table..." >&2
printf "struct instdef cbprefixed_instructions[256] = {\n"

for code in $(jq -r '.cbprefixed | keys | .[]' < opcodes.json);
do
    printf "    [%s] = {\n" $code
    printf "        .mnem = \"%s\",\n" $(jq -r ".cbprefixed.\"${code}\".mnemonic" < opcodes.json)
    printf "        .len = %s,\n" $(jq -r ".cbprefixed.\"${code}\".length" < opcodes.json)
    OP1=$(jq -r ".cbprefixed.\"${code}\".operand1" < opcodes.json)
    OP2=$(jq -r ".cbprefixed.\"${code}\".operand2" < opcodes.json)
    emitparam 0 "${OP1}"
    emitparam 1 "${OP2}"
    printf "    },\n"
done

printf "};\n"
