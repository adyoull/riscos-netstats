#!/usr/bin/env python3
"""Tokenise a plain-text BBC BASIC V program (no line numbers) into the
RISC OS tokenised format (filetype &FFB).

Only what this project needs: keywords are matched at the start of an
identifier, longest first; lowercase words, variable names, strings, REM and
DATA tails are copied verbatim. ELSE as the first statement on a line becomes
the block-IF token &CC, as the RISC OS tokeniser does.
"""
import sys

SINGLE = {
    'OTHERWISE': 0x7F, 'AND': 0x80, 'DIV': 0x81, 'EOR': 0x82, 'MOD': 0x83,
    'OR': 0x84, 'ERROR': 0x85, 'LINE': 0x86, 'OFF': 0x87, 'STEP': 0x88,
    'SPC': 0x89, 'TAB(': 0x8A, 'ELSE': 0x8B, 'THEN': 0x8C, 'OPENIN': 0x8E,
    'PTR': 0x8F, 'PAGE': 0x90, 'TIME': 0x91, 'LOMEM': 0x92, 'HIMEM': 0x93,
    'ABS': 0x94, 'ACS': 0x95, 'ADVAL': 0x96, 'ASC': 0x97, 'ASN': 0x98,
    'ATN': 0x99, 'BGET': 0x9A, 'COS': 0x9B, 'COUNT': 0x9C, 'DEG': 0x9D,
    'ERL': 0x9E, 'ERR': 0x9F, 'EVAL': 0xA0, 'EXP': 0xA1, 'EXT': 0xA2,
    'FALSE': 0xA3, 'FN': 0xA4, 'GET': 0xA5, 'INKEY': 0xA6, 'INSTR(': 0xA7,
    'INT': 0xA8, 'LEN': 0xA9, 'LN': 0xAA, 'LOG': 0xAB, 'NOT': 0xAC,
    'OPENUP': 0xAD, 'OPENOUT': 0xAE, 'PI': 0xAF, 'POINT(': 0xB0, 'POS': 0xB1,
    'RAD': 0xB2, 'RND': 0xB3, 'SGN': 0xB4, 'SIN': 0xB5, 'SQR': 0xB6,
    'TAN': 0xB7, 'TO': 0xB8, 'TRUE': 0xB9, 'USR': 0xBA, 'VAL': 0xBB,
    'VPOS': 0xBC, 'CHR$': 0xBD, 'GET$': 0xBE, 'INKEY$': 0xBF,
    'LEFT$(': 0xC0, 'MID$(': 0xC1, 'RIGHT$(': 0xC2, 'STR$': 0xC3,
    'STRING$(': 0xC4, 'EOF': 0xC5, 'WHEN': 0xC9, 'OF': 0xCA,
    'ENDCASE': 0xCB, 'ENDIF': 0xCD, 'ENDWHILE': 0xCE, 'SOUND': 0xD4,
    'BPUT': 0xD5, 'CALL': 0xD6, 'CHAIN': 0xD7, 'CLEAR': 0xD8, 'CLOSE': 0xD9,
    'CLG': 0xDA, 'CLS': 0xDB, 'DATA': 0xDC, 'DEF': 0xDD, 'DIM': 0xDE,
    'DRAW': 0xDF, 'END': 0xE0, 'ENDPROC': 0xE1, 'ENVELOPE': 0xE2,
    'FOR': 0xE3, 'GOSUB': 0xE4, 'GOTO': 0xE5, 'GCOL': 0xE6, 'IF': 0xE7,
    'INPUT': 0xE8, 'LET': 0xE9, 'LOCAL': 0xEA, 'MODE': 0xEB, 'MOVE': 0xEC,
    'NEXT': 0xED, 'ON': 0xEE, 'VDU': 0xEF, 'PLOT': 0xF0, 'PRINT': 0xF1,
    'PROC': 0xF2, 'READ': 0xF3, 'REM': 0xF4, 'REPEAT': 0xF5, 'REPORT': 0xF6,
    'RESTORE': 0xF7, 'RETURN': 0xF8, 'RUN': 0xF9, 'STOP': 0xFA,
    'COLOUR': 0xFB, 'TRACE': 0xFC, 'UNTIL': 0xFD, 'WIDTH': 0xFE,
    'OSCLI': 0xFF,
}
EXT_FN = {'SUM': 0x8E, 'BEAT': 0x8F}
EXT_ST = {'CASE': 0x8E, 'CIRCLE': 0x8F, 'FILL': 0x90, 'ORIGIN': 0x91,
          'RECTANGLE': 0x93, 'SWAP': 0x94, 'WHILE': 0x95, 'WAIT': 0x96,
          'MOUSE': 0x97, 'QUIT': 0x98, 'SYS': 0x99, 'INSTALL': 0x9A,
          'LIBRARY': 0x9B, 'TINT': 0x9C, 'ELLIPSE': 0x9D}
# pseudo-variables have a separate token at the start of a statement
STMT_FORM = {'PTR': 0xCF, 'PAGE': 0xD0, 'TIME': 0xD1, 'LOMEM': 0xD2, 'HIMEM': 0xD3}

KEYS = {}
for k, v in SINGLE.items():
    KEYS[k] = bytes([v])
for k, v in EXT_FN.items():
    KEYS[k] = bytes([0xC6, v])
for k, v in EXT_ST.items():
    KEYS[k] = bytes([0xC8, v])
ORDER = sorted(KEYS, key=len, reverse=True)

IDCH = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_`')


def tok_line(text):
    out = bytearray()
    i = 0
    n = len(text)
    stmt_start = True      # at the start of a statement
    line_start = True      # nothing but spaces so far on this line
    while i < n:
        c = text[i]
        if c == '"':
            j = text.index('"', i + 1)
            # "" inside strings is an escaped quote
            while j + 1 < n and text[j + 1] == '"':
                j = text.index('"', j + 2)
            out += text[i:j + 1].encode('latin-1')
            i = j + 1
            stmt_start = line_start = False
            continue
        if c == ':':
            out += b':'
            i += 1
            stmt_start = True
            line_start = False
            continue
        if c == ' ':
            out += b' '
            i += 1
            continue
        if c.isalpha() and c.isupper():
            for k in ORDER:
                if text.startswith(k, i):
                    t = KEYS[k]
                    if k == 'ELSE' and line_start:
                        t = bytes([0xCC])
                    if k in STMT_FORM and stmt_start:
                        t = bytes([STMT_FORM[k]])
                    out += t
                    i += len(k)
                    if k in ('REM', 'DATA'):
                        out += text[i:].encode('latin-1')
                        i = n
                    elif k in ('PROC', 'FN'):
                        j = i
                        while j < n and text[j] in IDCH:
                            j += 1
                        out += text[i:j].encode('latin-1')
                        i = j
                    # after these a new statement starts
                    stmt_start = k in ('THEN', 'ELSE', 'REPEAT', 'OTHERWISE')
                    line_start = False
                    break
            else:
                j = i
                while j < n and text[j] in IDCH:
                    j += 1
                out += text[i:j].encode('latin-1')
                i = j
                stmt_start = line_start = False
            continue
        if c in IDCH:
            j = i
            while j < n and text[j] in IDCH:
                j += 1
            out += text[i:j].encode('latin-1')
            i = j
            stmt_start = line_start = False
            continue
        out += c.encode('latin-1')
        i += 1
        stmt_start = line_start = False
    return bytes(out)


def tokenise(src, step=10):
    out = bytearray()
    num = step
    for raw in src.split('\n'):
        line = raw.rstrip()
        body = tok_line(line)
        if len(body) + 4 > 255:
            raise SystemExit('line %d too long (%d bytes): %s' % (num, len(body) + 4, line[:60]))
        out += bytes([0x0D, num >> 8, num & 0xFF, len(body) + 4]) + body
        num += step
    # drop trailing empty lines' worth? keep them: harmless
    out += b'\x0D\xFF'
    return bytes(out)


if __name__ == '__main__':
    src = open(sys.argv[1], encoding='latin-1').read().rstrip('\n')
    data = tokenise(src)
    open(sys.argv[2], 'wb').write(data)
    print('%s: %d lines, %d bytes' % (sys.argv[2], src.count('\n') + 1, len(data)))
