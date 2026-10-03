#!/usr/bin/env python3
"""Rough lint for the BASIC source: names that are read but never set."""
import re, sys
src = open(sys.argv[1]).read()
lines = []
for l in src.split('\n'):
    s = l.strip()
    if s.startswith('REM') or s.startswith('DATA'):
        continue
    l = re.sub(r'"[^"]*"', '""', l)
    l = re.sub(r'\bREM\b.*', '', l)
    lines.append(l)
code = '\n'.join(lines)
KW = set("""AND DIV EOR MOD OR ERROR LINE OFF STEP SPC TAB ELSE THEN OPENIN PTR PAGE TIME LOMEM HIMEM ABS ACS ADVAL ASC ASN ATN BGET COS COUNT DEG ERL ERR EVAL EXP EXT FALSE FN GET INKEY INSTR INT LEN LN LOG NOT OPENUP OPENOUT PI POINT POS RAD RND SGN SIN SQR TAN TO TRUE USR VAL VPOS CHR GET LEFT MID RIGHT STR STRING EOF WHEN OF ENDCASE ENDIF ENDWHILE SOUND BPUT CALL CHAIN CLEAR CLOSE CLG CLS DATA DEF DIM DRAW END ENDPROC ENVELOPE FOR GOSUB GOTO GCOL IF INPUT LET LOCAL MODE MOVE NEXT ON VDU PLOT PRINT PROC READ REM REPEAT REPORT RESTORE RETURN RUN STOP COLOUR TRACE UNTIL WIDTH OSCLI CASE WHILE SYS QUIT OTHERWISE""".split())
tok = re.compile(r'(?<![A-Za-z0-9_])(?:PROC|FN)?[A-Za-z_][A-Za-z0-9_]*[%$]?\(?')
used, setn = {}, set()
for ln, l in enumerate(code.split('\n'), 1):
    for m in tok.finditer(l):
        t = m.group(0)
        if t.startswith(('PROC', 'FN')):
            continue
        name = t.rstrip('(')
        base = name.rstrip('%$')
        if base in KW or name in KW or base.upper() == base and base in KW:
            continue
        if re.fullmatch(r'[A-Z]+', base) and base in KW:
            continue
        arr = t.endswith('(')
        key = name + ('()' if arr else '')
        rest = l[m.end():]
        # definitions
        before = l[:m.start()]
        if re.match(r'\s*(\+|-)?=', rest) and not re.search(r'(IF|UNTIL|WHILE|WHEN|AND|OR|<|>|=)\s*$', before.rstrip()) :
            setn.add(key)
        if arr and re.match(r'[^)]*\)\s*(\+|-)?=', rest):
            setn.add(key)
        if re.search(r'\b(LOCAL|DIM|FOR|READ|TO)\b[^:]*$', before) or re.search(r'DEF\s*(PROC|FN)\w+\([^)]*$', before):
            setn.add(key)
        if re.search(r';\s*$', before):
            setn.add(key)
        used.setdefault(key, ln)
miss = sorted(k for k in used if k not in setn)
print('\n'.join('%-20s first used near line %d' % (k, used[k]) for k in miss))
