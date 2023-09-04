#!/usr/bin/awk -f

function do_paramkind(n, op) {
	if (op == "(a16)") {
		printf "\t\t.param%dkind = PARAM_INDIR|PARAM_A16,\n", n;
	} else if (op == "a16") {
		printf "\t\t.param%dkind = PARAM_A16,\n", n;
	} else if (op == "d16") {
		printf "\t\t.param%dkind = PARAM_D16,\n", n;
	} else if (op == "d8") {
		printf "\t\t.param%dkind = PARAM_D8,\n", n;
	} else if (op == "r8") {
		printf "\t\t.param%dkind = PARAM_R8,\n", n;
	} else if (op == "(a8)") {
		printf "\t\t.param%dkind = PARAM_R8|PARAM_INDIR,\n", n;
	} else if (op == "SP+r8") {
		printf "\t\t.param%dkind = PARAM_INDIR|PARAM_A8,\n", n;
	} else {
		printf "\t\t.param%dkind = PARAM_STR,\n", n;
		printf "\t\t.param%d.str = \"%s\",\n", n, op
	}
}

{
	printf "\t[0x%x] = {\n", $1
	printf "\t\t.mnem = \"%s\",\n", $2
	printf "\t\t.len = %d,\n", $3
	if ($4 == "none") {
		printf "\t\t.param0kind = PARAM_NONE,\n";
	} else {
		do_paramkind(0, $4);
	}

	if ($5 == "none") {
		printf "\t\t.param1kind = PARAM_NONE,\n";
	} else {
		do_paramkind(1, $5);
	}

	printf "\t},\n"
}

