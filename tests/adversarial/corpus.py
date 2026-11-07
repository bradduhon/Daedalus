# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 3.3: the shared adversarial corpus; one test module per bypass class, rows assert a deny.
# pin C1 -> C6: never a row for git grep, git worktree list, git merge-base, git show | sed -n,
# the --test-runner pytest forms or an auditor write under the train's audit folder.
from __future__ import annotations

import shlex
from typing import Any

from lib import jail
from lib.jail import normalize_agent

from tests.conftest import CFG
from tests.hook_chain import CHAINS, decide
from tests.payloads import _cred

CLASSES = (
    "brace_glob",
    "quoting",
    "symlinks",
    "env_expansion",
    "path_traversal",
    "nested_sessions",
    "wrapper_options",
    "operand_grammar",
    "hidden_bodies",
    "chain_state",
)
# spec 3.3: the agents whose Bash grammar is widest; credential reads judge them all.
READERS = ("coder", "auditor", "verifier")
CREDENTIAL = "credential path"
REPLY_KEY = "the train's reply key"
NESTED = "nested session"
OUTSIDE = "outside your unit worktree"
PROTECTED = "protected path"


# issue 80 (unit H1): env -S hides a write inside one word; {repo} is a repository a train marks.
H1_ENV_SPLIT = (
    "env -S 'touch {repo}/x'",
    "env -S'touch {repo}/x'",
    "env --split-string='touch {repo}/x'",
    "env --split-string 'touch {repo}/x'",
    "env --spl='touch {repo}/x'",
    "env -iS 'touch {repo}/x'",
    "env -u HOME -S 'touch {repo}/x'",
    "nice -n 5 env -S 'rm -rf {repo}/x'",
)
# issue 81 (unit H1): a shell -c body, flock's included, hides its write targets.
H1_SHELL_BODY = (
    "bash -c 'touch {repo}/x'",
    "sh -c 'touch {repo}/x'",
    "bash -lc 'touch {repo}/x'",
    "sh -ec 'rm -rf {repo}/x'",
    "bash --norc -c 'touch {repo}/x'",
    "bash --frobnicate -c 'touch {repo}/x'",
    "dash -c 'touch {repo}/x'",
    "setsid sh -c 'touch {repo}/x'",
    "flock /tmp/l -c 'touch {repo}/x'",
    "flock /tmp/l --command 'touch {repo}/x'",
)


def nest_bodies(command: str, levels: int, shell: str = "sh") -> str:
    # issue 81: the command inside `levels` shell -c bodies, each level quoted once more.
    for _ in range(levels):
        command = f"{shell} -c {shlex.quote(command)}"
    return command


# issue 81 (unit H1): bodies nested past the walk's depth cap of three fail closed.
H1_DEEP_BODY = (
    nest_bodies("touch {repo}/x", 4),
    nest_bodies("touch {repo}/x", 6, "bash"),
    "env -S " + shlex.quote(nest_bodies("touch {repo}/x", 3)),
)
# issue 82 (unit H1): one row per runner wrapper row, then options kept off a row.
H1_WRAPPERS = (
    "setsid -f touch {repo}/x",
    "chroot / touch {repo}/x",
    "ionice -c 3 touch {repo}/x",
    "taskset -c 0 touch {repo}/x",
    "flock -w 5 /tmp/l touch {repo}/x",
    "unshare --fork touch {repo}/x",
    "chrt -o 0 touch {repo}/x",
    "nsenter -t 1 -m touch {repo}/x",
)
H1_WRAPPERS_OFF_ROW = (
    "chroot {repo} touch /x",
    "unshare --root {repo} touch /x",
    "unshare -w {repo} touch x",
    "nsenter --wd={repo} touch x",
    "ionice --frobnicate touch {repo}/x",
    "taskset touch {repo}/x",
)
# issue 204 (unit A1): the reproduction rows, verbatim.
A1_ISSUE_204 = ("uniq - out", "uniq in out", "uniq -c in out")
# issue 107 (unit A1): the reproduction row, verbatim; <file> lies in a repository a train marks.
A1_ISSUE_107 = "flock <file> <command>"
# P1 to P4, P9 (unit A1): read verbs that write through an option or an operand, per rule.
A1_READ_P1 = ("uniq -c *", "uniq in a*", "sort $O in", "sort * in", "file -b $X", "find . $P out")
A1_READ_P2 = (
    "sort -o out in",
    "sort -oout in",
    "sort -uo out in",
    "sort -uoout in",
    "sort --output=out in",
    "sort --output out in",
    "sort --out out in",
    "sort -T /tmp in",
    "sort --temporary-directory=/tmp in",
    "sort --temp /tmp in",
    "sort --compress-program=gzip in",
    "sort --compress gzip in",
    "sort --frobnicate in",
    "find . -fprint out",
    "find . -fprint0 out",
    "find . -fprintf out %p",
    "find . -fls out",
    "find . -fprint=out",
    "file -C -m x",
    "file -bC x",
    "file --compile x",
    "file --comp x",
    "uniq -f 1 in out",
    "uniq -f1 in out",
    "uniq -cf1 in out",
    "uniq --skip-fields=1 in out",
    "uniq --skip-f 1 in out",
    "uniq --frobnicate in",
    "uniq -Q in",
)
A1_READ_P3 = ("uniq -- in out", "uniq -- -c out", "uniq -c - out")
A1_READ_P4 = (
    "uniq in out -c",
    "uniq in -f 1 out",
    "sort in -o out",
    "sort in --output=out",
    "sort in -uo out",
    "file x -C",
)
A1_READ_P9 = ("flock l cat x", "time -o t cat x")
A1_READ_ADMITTED = ("uniq -c in", "uniq -f 1 in", "sort -u in", "sort -t, -k2,2n in", "file -b x")
# P1 (unit A1, fix round 1): an unquoted word the shell splits or turns into an option.
A1_EXPANSION = (
    "uniq {in,out}",
    "uniq x{a,b}",
    "uniq {1..3}",
    "sort {-o,out} in",
    "sort -{o,x}out in",
    "file {-C,-m,x}",
    "find . {-fprint,out}",
    "find . -name *.py",
    "uniq *",
    "uniq ~/in",
    "sort ~ in",
    "uniq in <(cat x)",
    "sort -m <(cat x) in",
    "uniq $X",
    'sort "$O" in',
    "sort `x` in",
    "{u,}niq in out",
    '"$V" in out',
)
A1_EXPANSION_ADMITTED = (
    "grep -n sort src/*.py",
    "rg file src/*",
    'grep -rn "find" *.md',
    "uniq '{a,b}'",
    'uniq "{a,b}"',
    "sort '{-o,out}' in",
    "find . -name '*.py'",
    "find . -name '{a,b}.py'",
    "uniq '~/in'",
)
# P1 to P4, P9 (unit A1): wrapper files named in {repo}, a repository a train marks.
A1_WRAPPER_ROWS = (
    "flock {repo}/* true",
    "flock {repo}/l? true",
    "flock -w 5 {repo}/l true",
    "flock -w5 {repo}/l true",
    "flock -xw 5 {repo}/l true",
    "flock --wait=5 {repo}/l true",
    "flock --tim 5 {repo}/l true",
    "unshare --mount={repo}/ns true",
    "unshare --net={repo}/ns true",
    "flock -- {repo}/l true",
    "flock -x -- {repo}/l true",
    "flock {repo}/l -c true",
    "flock -n {repo}/l -c 'true'",
    "flock {repo}/l true",
    "flock -x {repo}/l true",
    "flock --timeout=5 -- {repo}/l true",
)
# issue 116 (unit A2): the reproduction rows, verbatim; the first five are the probe's rows.
A2_ISSUE_116 = (
    'rbash -c "touch x"',
    'echo "touch x" | bash',
    'bash <<< "touch x"',
    'python3 -c "import os"',
    'env -a x -S "touch y"',
    'bash -c "touch x"',
)
A2_PROBE = A2_ISSUE_116[:5]
# issue 81 (unit A2): the reproduction rows, verbatim.
A2_ISSUE_81 = ("bash -c '<body>'", "sh -c")
# P5 to P8 (unit A2): (rule, family, finding, form); {repo} is a repository a train marks.
A2_RULE_ROWS = (
    ("P5", "shell", "shell", "/usr/bin/rbash -c 'touch {repo}/x'"),
    ("P5", "shell", "shell", "A=1 nice -n 5 nohup ./bash -c 'touch {repo}/x'"),
    ("P5", "interpreter", "inline", "nice -n 5 timeout 5 /usr/bin/python3.12 -c 'import os'"),
    ("P5", "interpreter", "inline", "A=1 stdbuf -o L ./perl5.36 -e 1"),
    ("P5", "env", "env", "timeout 5 nice env -a x -S 'touch {repo}/y'"),
    ("P6", "shell", "shell", "echo 'touch {repo}/x' | rbash -s"),
    ("P6", "shell", "shell", "bash -xc 'touch {repo}/x'"),
    ("P6", "shell", "shell", "bash --login -c 'touch {repo}/x'"),
    ("P6", "shell", "shell", "bash <<< 'touch {repo}/x'"),
    ("P6", "shell", "shell", "bash /dev/stdin <<< 'touch {repo}/x'"),
    ("P6", "shell", "shell", "cat x | bash -"),
    ("P6", "shell", "shell", "busybox sh -c 'touch {repo}/x'"),
    ("P6", "shell", "shell", "busybox sh <<< 'touch {repo}/x'"),
    ("P6", "shell", "shell", "bash <(echo touch {repo}/x)"),
    ("P6", "shell", "shell", "sh <<EOF\ntouch {repo}/x\nEOF"),
    ("P6", "shell", "shell", "bash {{-c,x}} 'touch {repo}/x'"),
    ("P6", "shell", "shell", "mksh -ec 'touch {repo}/x'"),
    ("P6", "interpreter", "shell", "python3 scripts/x.py | bash"),
    ("P6", "env", "shell", "env -i bash <<< 'touch {repo}/x'"),
    ("P7", "interpreter", "inline", "python3 -c 'import os'"),
    ("P7", "interpreter", "inline", "python -Bc 'import os'"),
    ("P7", "interpreter", "inline", "python3 -W ignore -c 'import os'"),
    ("P7", "interpreter", "inline", "perl -e 'print 1'"),
    ("P7", "interpreter", "inline", "perl -E 'say 1'"),
    ("P7", "interpreter", "inline", "ruby -e 'p 1'"),
    ("P7", "interpreter", "inline", "node -e 1"),
    ("P7", "interpreter", "inline", "node --eval=1"),
    ("P7", "interpreter", "inline", "node -r x -p 1"),
    ("P7", "interpreter", "inline", "node --print 1"),
    ("P7", "interpreter", "inline", "php -r 'echo 1;'"),
    ("P7", "interpreter", "inline", "echo 'import os' | python3"),
    ("P7", "interpreter", "inline", "python3 - <<< 'import os'"),
    ("P7", "interpreter", "inline", "python3 /dev/stdin"),
    ("P7", "interpreter", "inline", "python3 {{-c,x}} 'import os'"),
    ("P7", "shell", "shell", "bash -c \"python3 -c 'import os'\""),
    ("P7", "env", "inline", "env -i python3 -c 'import os'"),
    ("P8", "env", "env", "env -a x -S 'touch {repo}/y'"),
    ("P8", "env", "env", "env --argv0 x -S 'touch {repo}/y'"),
    ("P8", "env", "env", "env -u A -a x -C /tmp -S'touch {repo}/y'"),
    ("P8", "env", "env", "env A=1 -S 'touch {repo}/y'"),
    ("P8", "env", "env", "env --argv0=x --split-string='touch {repo}/y'"),
    ("P8", "env", "env", "env -ia x -S 'touch {repo}/y'"),
    ("P8", "env", "env", "env {{-S,x}} 'touch {repo}/y'"),
    ("P8", "shell", "shell", "bash -c \"env -a x -S 'touch {repo}/y'\""),
    ("P8", "interpreter", "env", "env -a x -S \"python3 -c 'import os'\""),
)
# fix round 1 (unit A2): (finding, form) per verifier row; refused to a foreign agent in a run.
A2_FIX1_RUN = (
    ("shell", "bash 0<<<'touch {repo}/x'"),
    ("shell", "sh 0<'{repo}/s'"),
    ("shell", "bash {{,-c}} 'touch {repo}/x'"),
    ("shell", "{{,bash}} -c 'touch {repo}/x'"),
    ("shell", "bash ${{E:--c}} 'touch {repo}/x'"),
    ("inline", "node --title t -e 'require(1)'"),
    ("inline", "python3 --frobnicate x -c 'import os'"),
    ("shell", "bash --frobnicate x -c 'touch {repo}/x'"),
    ("shell", "eval 'touch {repo}/x'"),
    ("shell", ". /dev/stdin <<< 'touch {repo}/x'"),
    ("shell", "source /dev/fd/0 <<< 'touch {repo}/x'"),
    ("shell", ". <(echo touch {repo}/x)"),
    ("shell", "source /proc/self/fd/3"),
)
# fix round 1 (unit A2): the readable forms, run from an unmarked folder into {repo}.
A2_FIX1_UNMARKED = (
    "bash 0<<<'touch {repo}/x'",
    "bash {{,-c}} 'touch {repo}/x'",
    "{{,bash}} -c 'touch {repo}/x'",
    "bash ${{E:--c}} 'touch {repo}/x'",
    "bash --frobnicate x -c 'touch {repo}/x'",
    "eval 'touch {repo}/x'",
    ". /dev/stdin <<< 'touch {repo}/x'",
)
# A2 spec correction: an inline flag among the program's own options, off-table ones included.
A2_FIX2_RUN = (
    ("inline", "node --title t -e x"),
    ("inline", "node --title build.js -e x"),
    ("inline", "node --frobnicate t -e x"),
    ("inline", "python3 -I -c x"),
    ("inline", "python3 -Ic x"),
)
# A2 spec correction: words after -m <module> or the script belong to the program.
A2_PROGRAM_ARGS = (
    "python3 -m pytest -c pytest.ini -q",
    "python3 scripts/x.py -c foo",
    "node build.js -e prod",
    "perl script.pl -e x",
    "bash script.sh -c x",
)
# P7 (unit A2): a module or a script run is never an inline body.
A2_ADMITTED = ("python3 -m pytest -q", "python3 scripts/x.py")
# fix round 3 (unit A2): a normalised stdin path, and a -- a valued option consumes.
A2_FIX3_RUN = (
    ("shell", "bash /dev/./stdin <<< 'touch {repo}/x'"),
    ("shell", "source /proc/thread-self/fd/0 <<< 'touch {repo}/x'"),
    ("shell", "sh //dev/stdin <<< 'touch {repo}/x'"),
    ("shell", "bash ../../../../../../../../dev/stdin <<< 'touch {repo}/x'"),
    ("inline", "python3 /dev/./stdin"),
    ("inline", "python3 /proc/thread-self/fd/0 <<< 'import os'"),
    ("inline", "php -f /dev/stdin <<< 'x'"),
    ("inline", "python3 -X -- -c 'import os'"),
    ("inline", "echo 'import os' | node --no-warnings"),
)
# fix round 3 (unit A2): the readable forms, run from an unmarked folder into {repo}.
A2_FIX3_UNMARKED = (
    "bash /dev/./stdin <<< 'touch {repo}/x'",
    "source /proc/thread-self/fd/0 <<< 'touch {repo}/x'",
    "sh //dev/stdin <<< 'touch {repo}/x'",
    "bash -c -- 'touch {repo}/x'",
)
# fix round 4 (unit A2): stdin fed to a group, subshell or bare exec; a script under a cd move.
A2_FIX4_RUN = (
    ("shell", "{{ bash; }} <<< 'touch {repo}/x'"),
    ("shell", "( bash ) <<< 'touch {repo}/x'"),
    ("shell", "exec <<< 'touch {repo}/x'; bash"),
    ("shell", "( exec bash ) <<< 'touch {repo}/x'"),
    ("shell", "( python3 ) <<< 'import os'"),
    ("shell", "{{ python3; }} < {repo}/code.py"),
    ("shell", "cd /dev && bash stdin <<< 'touch {repo}/x'"),
    ("shell", "cd /proc/self/fd && bash 0 <<< 'touch {repo}/x'"),
    ("shell", "pushd /dev && bash ./stdin <<< 'touch {repo}/x'"),
    ("shell", "cd ~/../../dev && bash stdin <<< 'touch {repo}/x'"),
    ("inline", "cd /dev && python3 stdin"),
)
# fix round 4 (unit A2): every here-string and heredoc body is walked, from an unmarked folder.
A2_FIX4_UNMARKED = (
    "{{ bash; }} <<< 'touch {repo}/x'",
    "( bash ) <<< 'touch {repo}/x'",
    "exec <<< 'touch {repo}/x'; bash",
    "( exec bash ) <<< 'touch {repo}/x'",
    "( bash ) <<'E'\ntouch {repo}/x\nE",
    "cd /dev && bash stdin <<< 'touch {repo}/x'",
    "cd /proc/self/fd && bash 0 <<< 'touch {repo}/x'",
    "pushd /dev && bash ./stdin <<< 'touch {repo}/x'",
)
# fix round 4 (unit A2): a here-string or heredoc read by a plain command, with no write.
A2_FIX4_ADMITTED = ('grep foo <<< "bar"', "cat <<'E'\nhello world\nE")
# fix round 3 (unit A2): a script operand, a script named by php -f, or no stdin fed: no body.
A2_FIX3_ADMITTED = (
    "node --no-warnings app.js",
    "node --enable-source-maps dist/app.js",
    "perl -Mstrict script.pl",
    "php -f script.php",
    "python3 -V",
    "node -v",
)
# issue 83 (unit H1): {other}/deep links to {repo}/sub, so deep/.. is {repo} on disk.
H1_SYMLINK = ("touch {other}/deep/../x", "mkdir {other}/deep/../y", "rm -rf {other}/deep/../x")
# issue 97 (unit H1): an icase pathspec names notes/a.md under another case; notes is excluded.
H1_ICASE = (
    "git add ':(icase)NOTES/a.md'",
    "git add ':(top,icase)Notes/a.md'",
    "git add ':(ICASE)nOtes'",
    "git commit -m m -- ':(icase)NOTES/a.md'",
    "git stash push -- ':(icase)notes'",
    "git add ':i:NOTES/a.md'",
    "git add ':/i:NOTES'",
    "git --icase-pathspecs add NOTES/a.md",
    "GIT_ICASE_PATHSPECS=1 git add NOTES/a.md",
    "git add ':(icase)NOTES/a.md' $(true)",
)
# issue 121 (unit A3): the reproduction rows, verbatim; the root is private, git reads Private.
A3_ISSUE_121_ADMITTED = (
    'git log -- ":(icase)README.md"',
    'git grep -n foo -- ":(icase)scripts"',
    "git commit -F - <<EOF\nfix :i: spelling\nEOF",
)
A3_ISSUE_121_REFUSED = (
    "export GIT_ICASE_PATHSPECS=1; git add Private/x",
    "export GIT_ICASE_PATHSPECS=1 && git add Private/x",
    "GIT_ICASE_PATHSPECS=1 git add Private/x",
)
# P10, P11 (unit A3): (rule, form) in the git family; notes is excluded, NOTES names it.
A3_RULE_ROWS = (
    ("P10", "export GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1 && git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1 || git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1 | git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1 & git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1\ngit add NOTES/a.md"),
    ("P10", "(export GIT_ICASE_PATHSPECS=1; git add NOTES/a.md)"),
    ("P10", "{ export GIT_ICASE_PATHSPECS=1; git add NOTES/a.md; }"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; (git add NOTES/a.md)"),
    ("P10", "GIT_ICASE_PATHSPECS=1; export GIT_ICASE_PATHSPECS; git add NOTES/a.md"),
    ("P10", "declare -x GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "typeset -x GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "declare -gx GIT_ICASE_PATHSPECS=1; git commit -m m -- NOTES/a.md"),
    ("P10", "set -a; GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "set -o allexport; GIT_ICASE_PATHSPECS=1; git stash push -- NOTES"),
    ("P10", "env GIT_ICASE_PATHSPECS=1 git add NOTES/a.md"),
    ("P10", "env -- GIT_ICASE_PATHSPECS=1 git add NOTES/a.md"),
    ("P10", "env -u X GIT_ICASE_PATHSPECS=1 git add NOTES/a.md"),
    ("P10", 'GIT_ICASE_PATHSPECS="$X" git add NOTES/a.md'),
    ("P10", "export GIT_ICASE_PATHSPECS=1; unset GIT_ICASE_PATHSPECS; git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; export -n GIT_ICASE_PATHSPECS; git add NOTES/a.md"),
    ("P10", "export {GIT_ICASE_PATHSPECS,X}=1; git add NOTES/a.md"),
    ("P10", 'export "$V"=1; git add NOTES/a.md'),
    ("P10", "declare -x ${N}=1; git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; git -c core.ignorecase=false add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; git -C . stage NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; git update-index --add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; /usr/bin/git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; \\git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; g''it add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; {git,} add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; git {add,x} NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=1; bash -c 'git add NOTES/a.md'"),
    ("P10", "git -c core.ignorecase=false --icase-pathspecs add NOTES/a.md"),
    ("P10", "git --icase-pathspecs add NOTES/a.md"),
    # fix round 1 (R1, design 1): names read after quote and backslash removal, or opaque.
    ("P10", "(export GIT_ICASE_PATH''SPECS=1; git add NOTES/a.md)"),
    ("P10", "export G\\IT_ICASE_PATHSPECS=1\ngit add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATH''SPECS=1; git add NOTES/a.md"),
    ("P10", "G\\IT_ICASE_PATHSPECS=1 git add NOTES/a.md"),
    ("P10", "env ${N}=1 git add NOTES/a.md"),
    ("P10", "readonly ${N}=1; git add NOTES/a.md"),
    ("P10", "local -x GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    # fix round 1 (R2, design 2): option spellings after quote removal, allexport and +=.
    ("P10", 'declare "-x" GIT_ICASE_PATHSPECS=1; git add NOTES/a.md'),
    ("P10", "set '-a'; GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", 'set -o "allexport"; GIT_ICASE_PATHSPECS=1; git add NOTES/a.md'),
    ("P10", "set -ea; GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "shopt -so allexport; GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "shopt -s -o allexport; GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "set -a; GIT_ICASE_PATHSPECS+=1; git add NOTES/a.md"),
    ("P10", "set -a; declare GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS+=1; git add NOTES/a.md"),
    ("P10", "GIT_ICASE_PATHSPECS+=1 git add NOTES/a.md"),
    ("P10", "GIT_ICASE_PATHSPECS[0]=1 git add NOTES/a.md"),
    # fix round 1 (R6, R7, designs 3 to 5): code bash runs inside a read or a message.
    ("P11", "git log `git add ':(icase)NOTES/a.md'`"),
    ("P11", "git log -- \"$(git add ':(icase)NOTES/a.md')\""),
    ("P11", "git status <(git add ':(icase)NOTES/a.md')"),
    ("P11", "git commit -F - <<EOF\n$(git add ':(icase)NOTES/a.md')\nEOF"),
    ("P11", "git commit -F - <<EOF\n`git add ':(icase)NOTES/a.md'`\nEOF"),
    ("P11", "git commit -m \"$(git add ':(icase)NOTES/a.md')\""),
    ("P11", "cat <<EOF | git commit -F -\n$(git add ':(icase)NOTES/a.md')\nEOF"),
    ("P11", "cat <<E\ndon't\nE\ngit log -- \"$(git add ':(icase)NOTES/a.md')\""),
    ("P11", "git add :\\(icase\\)NOTES/a.md $(true)"),
    ("P11", "(git add ':(ic''ase)NOTES/a.md')"),
    ("P11", "git add ':(icase)NOTES/a.md'"),
    ("P11", "git commit -m -- ':(icase)NOTES/a.md'"),
    ("P11", "git commit -F -- ':(icase)NOTES/a.md'"),
    ("P11", "git commit -c HEAD ':(icase)NOTES/a.md'"),
    ("P11", "git -c x.y=1 add ':(icase)NOTES/a.md'"),
    ("P11", "git -C . add ':(icase)NOTES/a.md'"),
    ("P11", "git --git-dir .git add ':(icase)NOTES/a.md'"),
    ("P11", "{git,} add ':(icase)NOTES/a.md'"),
    ("P11", "\"$G\" add ':(icase)NOTES/a.md'"),
    ("P11", "git {add,x} ':(icase)NOTES/a.md'"),
    ("P11", "/usr/bin/git add ':(icase)NOTES/a.md'"),
    ("P11", "\\git add ':(icase)NOTES/a.md'"),
    ("P11", "g''it add ':(icase)NOTES/a.md'"),
    ("P11", "git commit -m note -- ':(icase)NOTES/a.md' $(true)"),
    ("P11", "git commit -F - ':(icase)NOTES/a.md' <<EOF\nnote\nEOF"),
    ("P11", "git add --pathspec-from-file=- <<EOF\n:(icase)NOTES/a.md\nEOF"),
    ("P11", "git commit -F - --pathspec-from-file=- <<EOF\n:(icase)NOTES/a.md\nEOF"),
    ("P11", "git commit -F - $((1<<2))\ngit add ':(icase)NOTES/a.md'\n2"),
    ("P11", "echo '<<E'; git commit -F - x\ngit add ':(icase)NOTES/a.md'\nE"),
    # fix round 3 (G1): the verifier's forms; a text not plainly simple is judged raw.
    ("P11", "git log $'a\\'' \"$(git add ':(icase)NOTES/a.md')\""),
    ("P11", "true # don't\necho 'x; git log -- ' $(git add \":(icase)NOTES/a.md\") ''"),
    ("P11", "(cat <<E\n'\nE\n) ; echo 'x; git log -- ' $(git add \":(icase)NOTES/a.md\") ''"),
    ("P11", "git commit -F - <<\"E\\OF\"\nmsg\nE\\OF\ngit add ':(icase)NOTES/a.md'"),
    ("P10", "eval export GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "set -a; printf -v GIT_ICASE_PATHSPECS 1; git add NOTES/a.md"),
    ("P10", "set -a; : ${GIT_ICASE_PATHSPECS:=1}; git add NOTES/a.md"),
    # fix round 4 (F1, F3): . or source after a control word, a prefix or a wrapper; a trap string.
    ("P11", "! . ./f; git log -- ':(icase)NOTES'"),
    ("P11", "time . ./f; git log -- ':(icase)NOTES'"),
    ("P11", "if false; then :; elif . ./f; then git log -- ':(icase)NOTES'; fi"),
    ("P11", "while . ./f; do git log -- ':(icase)NOTES'; done"),
    ("P11", "X=1 . ./f; git log -- ':(icase)NOTES'"),
    ("P11", "nice -n 1 . ./f; git log -- ':(icase)NOTES'"),
    ("P11", "{ . ./f; }; git log -- ':(icase)NOTES'"),
    ("P11", "(. ./f); git log -- ':(icase)NOTES'"),
    ("P11", "trap \"git add ':(icase)NOTES/a.md'\" EXIT"),
    ("P11", "command_not_found_handle() { git add ':(icase)NOTES/a.md'; }; gti"),
    # fix round 3 (G1 refined): a bare delimiter whose body bash may expand is not plainly simple.
    *(
        ("P11", head + "".join(f"\n{tab}{line}" for line in (body, "EOF")))
        for head, tab in (
            ("git commit -F - <<EOF", ""),
            ("cat <<EOF | git commit -F -", ""),
            ("git commit --file=- <<-EOF", "\t"),
        )
        for body in (
            "fix :i: $(git add ':(icase)NOTES/a.md')",
            "fix :i: `git add ':(icase)NOTES/a.md'`",
            "fix :i: $GIT_X",
            "fix :i: \\x",
        )
    ),
    # fix round 3 (G1, G3): forms the earlier rounds admitted that are not plainly simple.
    ("P11", "git commit -F - <<\\EOF\nfix :i: $(git add ':(icase)NOTES/a.md')\nEOF"),
    ("P11", "git log -- ':(icase)NOTES' $(git add NOTES/a.md)"),
    ("P11", "git commit -m 'fix :(icase) spelling' $(true)"),
    ("P11", "git log -- ':(icase)NOTES' $(true)"),
    ("P11", "git log -- ':(icase)x' `git stash`"),
    ("P10", "export GIT_ICASE_PATHSPECS=0; git add NOTES/a.md"),
    ("P10", "export GIT_ICASE_PATHSPECS=false && git add NOTES/a.md"),
    ("P10", "declare GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "GIT_ICASE_PATHSPECS=1; git add NOTES/a.md"),
    ("P10", "GIT_ICASE_PATHSPECS=1 true; git add NOTES/a.md"),
    ("P10", "GIT_ICASE_PATHSPECS= git add NOTES/a.md"),
    ("P10", "GIT_ICASE_PATHSPECS=1 git log; git add NOTES/a.md"),
    ("P10", "GIT_ICASE_PATH''SPECS=1\ngit log\ngit add NOTES/a.md"),
    ("P10", "unset GIT_ICASE_PATHSPECS; GIT_ICASE_PATHSPECS=0; git add NOTES/a.md"),
    *(
        ("P11", f"{c}\ngit commit -m ':i: fix' -- src/a.md")
        for c in (
            "echo $(true)",
            "echo `true`",
            "echo $'x'",
            'echo $"x"',
            "cat <(true)",
            "echo >(true)",
            "true # c",
            "eval true",
            "source /dev/null",
            ". /dev/null",
            "printf -v V x",
            "read V < /dev/null",
            "mapfile V < /dev/null",
            "readarray V < /dev/null",
            ": ${V=x}",
            ": ${V:=x}",
            "declare V=x",
            "typeset V=x",
            "local V=x",
            "readonly V=x",
            "set -e",
            "shopt -s nullglob",
            "export V=x",
            "env true",
            "alias a=b",
            "f() { true; }",
            "function f { true; }",
            "cat <<< x",
            "(cat <<'E'\nx\nE\n)",
            "{ cat <<'E'\nx\nE\n}",
            "echo $(cat <<'E'\nx\nE\n)",
            "cat <<E\n\\x\nE",
            'cat <<"E\\OF"\nx\nE\\OF',
            "cat <<'E'O\nx\nEO",
            "cat <<E''\nx\nE",
            "cat <<\\E\nx\nE",
        )
    ),
)
# P11 (unit A3): reads, commit messages and unexported or false values; the root is notes.
A3_ADMITTED = (
    'git log -- ":(icase)x"',
    'git grep -n foo -- ":(icase)x"',
    "git commit -F - <<'EOF'\nfix :(icase) spelling\nEOF",
    'git diff -- ":i:NOTES"',
    "git show HEAD -- ':(icase)NOTES'",
    "git status -- ':(icase)NOTES'",
    "git ls-files ':(icase)NOTES'",
    "git stash show -- ':(icase)NOTES'",
    "GIT_ICASE_PATHSPECS=1 git log -- NOTES",
    "git --icase-pathspecs log -- NOTES",
    "export GIT_ICASE_PATHSPECS=1; git log -- NOTES",
    "git commit -m ':i: fix' -- src/a.md",
    "git commit -m GIT_ICASE_PATHSPECS=1",
    "git commit -m GIT_ICASE_PATHSPECS=1; git add NOTES/a.md",
    "git commit -F ':(icase)msg'",
    "export git_icase_pathspecs=1; git add NOTES/a.md",
    "export PATH=/x:/y; git add NOTES/a.md",
    # fix round 1 (designs 4, 5): literal messages, a piped one included.
    "git commit -F - <<'EOF'\nfix :i: spelling\nEOF",
    "cat <<E\ndon't\nE\ngit log -- ':(icase)NOTES'",
    'export "PATH"=/x; git add NOTES/a.md',
    # fix round 3 (G1 refined): a bare plain delimiter with a body bash leaves literal.
    "git commit --file=- <<-EOF\n\tfix :i: spelling\n\tEOF",
    "cat <<EOF | git commit -F -\nfix :i: spelling\nEOF",
    "cat <<EOF | git commit --file=-\nfix :(icase) spelling\nEOF",
    # fix round 3 (G2, G3): quoted plain delimiters, a piped message, and an unset alone.
    "cat <<'E' | git commit -F -\nfix :i: spelling\nE",
    'cat <<"E" | git commit --file=-\nfix :(icase) spelling\nE',
    "git commit -F - <<-'EOF'\n\tfix :i: spelling\n\tEOF",
    "cat <<'E' | git commit -F -\nfix :i: don't # read set\nE",
    "unset GIT_ICASE_PATHSPECS; git add NOTES/a.md",
    "unset GIT_ICASE_PATHSPECS\ngit add NOTES/a.md",
    "git commit -m 'fix :i: spelling' -- src/a.md\ngit log -- ':(icase)NOTES'",
)
# issue 121 (unit A3 fix round 2): an appending or array-element prefix is an env assignment.
A3_APPEND_ENV = (
    "PATH+=:/tmp/x python3 -m pytest -q",
    "LD_PRELOAD+=/tmp/x.so python3 -m pytest -q",
    "GIT_ICASE_PATHSPECS+=1 git add X",
    "A[0]=1 git status",
)
# design 6 (unit A3 fix round 1): a judged git call fed paths the jail cannot see.
A3_UNSEEN = (
    "echo ':(icase)NOTES/a.md' | xargs git add",
    "echo notes/a.md | xargs git add",
    "xargs -a list git add",
    "echo x | xargs {git,} add",
    "git add --pathspec-from-file=list",
    "git stash push --pathspec-from-file list",
    "git commit --pathspec-fr=list",
    "git add --pathspec-from-file=- < list",
    "git update-index --stdin < list",
    "git update-index --index-info < list",
    # fix round 3 (G1, G4): xargs by any spelling, a shell after it included.
    "echo notes/a.md | xargs --max-args=1 git add",
    "echo notes/a.md | xargs -l git add",
    "echo ':(icase)NOTES/a.md' | xargs sh -c 'git add \"$@\"' _",
    "echo x | /usr/bin/xargs git add",
    "echo x | nice x''args git add",
    "echo x | xargs echo\ngit commit -m ':i: fix' -- src/a.md",
    # fix round 4 (F2): an unquoted expansion beside a judged git word or a built command word.
    'G=git; echo notes/a.md | xargs --max-args=1 "$G" add',
    "X=xar; echo notes/a.md | ${X}gs git add",
    'S=SPECS; eval "export GIT_ICASE_PATH${S}=1"; git add NOTES/a.md',
    "S=SPECS; set -a; printf -v GIT_ICASE_PATH$S 1; git add NOTES/a.md",
    "O=icase-pathspecs; git --$O add NOTES/a.md",
    'X=ase; git add ":(ic$X)NOTES/a.md"',
    'git add "$F"',
    "git add $(cat list)",
    "git a{d,}d notes/a.md",
    "git add <(cat list)",
    'C="git add notes/a.md"; $C',
    "git $S notes/a.md",
)
# SC-12 (fix round 1, finding 1): an rg whitelist glob reaches the hidden .claude folder.
FIX1_RG_GLOBS = (
    "rg -g .claude -g '*.key' -l . .",
    "rg --glob=.claude --glob='*.key' -l . .",
    "rg --iglob .claude --iglob '*.KEY' -l . .",
    "rg -g '.claude' -g 'reply-hmac.key' -n . .",
    "rg -g.claude -g'*.key' -l token",
    "rg -ig .claude -g '*.key' token .",
    "rg -g '{.claude,x}' -g '*.key' token .",
    "rg -g '.*' token .",
    "rg -g '**/*.key' token .",
    # SC-12 (fix round 1, verifier): gitignore **/ matches zero folders; a trailing / is a folder.
    "rg -g '**/.claude' -g '**/.claude/**' -l . .",
    "rg -g '.claude/' -g '**/.claude/**/reply-hmac.key' -l . .",
    "rg -g=.claude -g='*.key' -l . .",
    # SC-12 (fix round 1, operator ruling): a glob character the matcher does not model.
    "rg -g '\\.claude' -g '\\.claude/**' -l . .",
    "rg -g '.clau[d]e' -g '*.key' -l . .",
)
# SC-12 (fix round 1, verifier): the same gitignore spellings for the Grep tool's glob.
FIX1_GREP_GLOBS = ("**/.claude/**", "**/.claude", ".claude/", "**/.claude/**/reply-hmac.key")
FIX1_GREP_GLOBS += ("\\.claude/**", ".clau[d]e/**")
# SC-12 (fix round 1, finding 1): positive globs that name no hidden folder or key still pass.
FIX1_RG_GLOBS_ALLOWED = (
    "rg -g '*.tf' -g '*.yml' -l token .",
    "rg -g '!.claude' token .",
    "rg -e -g token .",
    "rg -g '**/*.py' -g '*Dockerfile*' -g '*requirements*.txt' token .",
    "rg -g 'src/' token .",
)

# prepush-2026-10-27 finding 1: a .rgignore or .ignore `!` line outranks the data folder marker.
PREPUSH_IGNORE_FILES = (".rgignore", ".ignore")
PREPUSH_IGNORE_BODIES = ("!.claude\n!.claude/**\n",)
# prepush2-2026-10-27 item 7: rg 14 reads a leading-space `!` as a plain glob, never a
# negation; the jail still refuses it, fail closed, and claims no attack.
PREPUSH_IGNORE_FAIL_CLOSED = ("  !*\n",)
PREPUSH_IGNORE_SEARCHES = ("rg -l token .", "rg -n token", "rg -l token src/..")
# prepush-2026-10-27 finding 1: a coder writing either name anywhere in its unit worktree.
PREPUSH_IGNORE_WRITES = (
    "{wt}/.rgignore",
    "{wt}/.ignore",
    "{wt}/src/.rgignore",
    "{wt}/src/deep/.IGNORE",
)
# 113, prepush-2026-10-27 finding 2: rg flags and config that read hidden or ignored files.
PREPUSH_RG_REACH = (
    "rg --ignore-file /tmp/ig -n . .",
    "rg --ignore-file=/tmp/ig token .",
    "rg -L token .",
    "rg --follow token .",
    "rg -nL token .",
    "RIPGREP_CONFIG_PATH=/tmp/rc rg token .",
    "env RIPGREP_CONFIG_PATH=/tmp/rc rg token .",
)

# prepush2-2026-10-27 item 1: words bash rewrites into a reach flag the jail never reads.
PREPUSH2_RG_OPAQUE = (
    "rg $'-uu' -l token .",
    "rg $'--hidden' -l token .",
    "rg $'--follow' -l token .",
    "rg $'-g' $'.claude/**' -l token .",
    "rg $'--no-ignore' -l token .",
    'rg $"-uu" -l token .',
    "rg {-uu,} -l token .",
    "rg --{hidden,count} token .",
    "rg $X -l token .",
    'rg "$X" -l token .',
    "rg * -l token .",
    "grep $'-r' -l token .",
    'grep $"-r" -l token .',
)
# prepush2-2026-10-27 item 2: rg options that run a program or load one.
PREPUSH2_RG_PROGRAM = (
    "rg --hostname-bin=/tmp/x -n token .",
    "rg --hostname-bin /tmp/x -n token .",
    "rg --hyperlink-format=default --hostname-bin=/tmp/x -n token .",
    "rg --hyperlink-format default --hostname-bin /tmp/x -n token .",
    "rg --pre /tmp/x token .",
    "rg --pre-glob '*' --pre /tmp/x token .",
    "rg --other-bin=/tmp/x token .",
)
# prepush2-2026-10-27 item 3: archive and multi-call writes the coder write check never models.
PREPUSH2_ARCHIVE_WRITES = (
    "unzip -o {wt}/z.zip -d /tmp/out",
    "busybox cp {wt}/a /tmp/out",
    "tar -C {wt} -cf /tmp/out/x.tar a",
    "tar -xPf {wt}/x.tar",
    "tar --transform s/a/.rgignore/ -xf {wt}/x.tar",
    "zip /tmp/out/z.zip {wt}/a",
    "cpio -o -F /tmp/out/x.cpio",
    "7z a /tmp/out/a.7z {wt}/a",
    "ar rc /tmp/out/a.a {wt}/a",
    "bsdtar -xf {wt}/x.tar -C /tmp/out",
)


def assert_denied(hook_input: dict[str, Any], *markers: str) -> None:
    # pin C1 -> C6: a deny through tests/hook_chain.py, never a warning; a marker names the finding.
    # issue 107: an agent with no hook chain is one Daedalus did not start, judged by lib.jail.
    agent = normalize_agent(str(hook_input.get("agent_type") or "main"))
    chained = agent in CHAINS or any(key.startswith(f"{agent} (") for key in CHAINS)
    d = decide(hook_input, CFG) if chained else jail.decide(hook_input, CFG)
    reason = str(d.reason)
    assert not d.allow and not d.warn, (hook_input, reason)
    assert not markers or any(m in reason for m in markers), (hook_input, reason)


# H2, issue 91: coder runners the confine check sends through the kernel wrapper.
CONFINE_RUNNERS = (
    "make",
    "make test",
    "tox -e py312",
    "nox -s tests",
    "just test",
    "uv run pytest -q",
    "uv run python -m unittest",
    "npx jest",
    "go test ./...",
    "cargo test",
    "timeout 60 cargo test",
    "nice -n 5 just test",
    "cargo -q test",
    "cargo +nightly test",
    "go -C . test ./...",
    "uv --quiet run pytest",
)
# 0164: the game stack runner rows; must-admit under the wrapper, refused bare.
GAME_RUNNERS = (
    "node --test",
    "node --test tests/a.test.js",
    "pnpm test",
    "pnpm run test",
    "pnpm exec vitest run",
    "pnpm exec tsc --noEmit",
    "pnpm -C . test",
    "vitest run",
    "vitest run src/a.test.ts",
    "tsc --noEmit",
    "tsc -p tsconfig.json --noEmit",
    "vite build",
    "npx --no-install vitest run",
    "timeout 120 pnpm test",
    # 0164 fix round: pnpm wraps like npm; terraform's allowlisted fmt forms.
    "pnpm run build",
    "pnpm build:dev",
    "pnpm run build:dev",
    "pnpm lint",
    "pnpm exec eslint .",
    "pnpm exec node --test",
    "pnpm run install",
    "npm run build:dev",
    "terraform fmt -check",
    "terraform fmt -check -recursive",
    "terraform fmt -recursive -check",
    # 0164 last fix: yarn and bun wrap like pnpm.
    "yarn test",
    "yarn run build",
    "yarn build:dev",
    "bun test",
    "bun run x.ts",
    "bun run build",
)
CONFINE_RUNNERS = CONFINE_RUNNERS + GAME_RUNNERS
# 0164, 0158: dev servers, watch modes and terraform state changes; refused bare and wrapped.
DEV_SERVERS = (
    "vite",
    "vite dev",
    "vite serve",
    "vite preview",
    "vite --port 5173",
    "vite build --watch",
    "pnpm dev",
    "pnpm run dev",
    "pnpm start",
    "pnpm preview",
    "pnpm exec vite",
    "pnpm vite serve",
    "npx --no-install vite",
    "npm run dev",
    "npm start",
    "timeout 60 vite dev",
    "pnpm run -- dev",
    "pnpm -- dev",
    "npm run -- dev",
    "pnpm run -- start",
    "npm run -- preview",
    "yarn run dev",
    "yarn dev",
    "yarn run -- dev",
    "bun run dev",
    "bun dev",
    "bun run -- start",
)
WATCH_MODES = (
    "vitest",
    "vitest watch",
    "vitest dev",
    "vitest run --watch",
    "pnpm exec vitest",
    "npx --no-install vitest",
    "tsc --watch",
    "tsc -w",
    "tsc --noEmit --watch",
    "tsc",
    "pnpm exec tsc -w",
    "node --test --watch",
    "node --test --watch-path=.",
    "vitest run --watch=true",
    "tsc --noEmit -watch",
    "tsc --noEmit --Watch",
    "tsc --noEmit false",
    "pnpm test --watch",
    "pnpm test -- --watch",
    "npm test -- --watch",
    "pnpm run test -w",
    "yarn test --watch",
    "yarn test -- --watch",
    "bun test --watch",
    "bun --watch run x.ts",
    "bun --hot run x.ts",
    "tsc --noEmit --noEmit false",
)
# 0164: what each watch row is refused with.
WATCH_REASONS = {"tsc": "R_TSC", "vitest": "R_VITEST_WATCH"}
TERRAFORM_MUTATIONS = (
    "terraform apply",
    "terraform apply -auto-approve",
    "terraform -chdir=. destroy",
    "terraform import aws_s3_bucket.a a",
    "terraform state rm a.b",
    "terraform taint a.b",
    "terraform untaint a.b",
    "terraform force-unlock 1",
    "terraform refresh",
)
# 0158, 0164: the coder's terraform is an allowlist; every other form names the operator.
TERRAFORM_OPERATOR_FORMS = (
    "terraform plan",
    "terraform init",
    "terraform console",
    "terraform test",
    "terraform workspace list",
    "terraform login",
    "terraform logout",
    "terraform output",
    "terraform graph",
    "terraform providers",
    "terraform fmt",
    "terraform fmt -recursive",
    "terraform fmt -write=true",
    "terraform fmt -check=false",
    "terraform fmt -check -write=true",
    "terraform fmt -check -recursive /tmp",
    "terraform fmt -check -check",
    "terraform version",
    "terraform",
    # 184: near misses of the one init form fail its shape, bare and wrapped.
    "terraform init -backend=false -input=false -lockfile=readonly",
    "terraform -chdir=. init -backend=false -input=false",
    "terraform -chdir=. init -backend=false -input=false -lockfile=readonly x",
    "terraform -chdir=. init -input=false -backend=false -lockfile=readonly",
    "terraform -chdir=. init -backend=true -input=false -lockfile=readonly",
)
# 184: the one init form, admitted wrapped with features.terraform_validate on; {module} is a
# module folder inside the project; the near misses stay refused bare and wrapped.
TERRAFORM_INIT_FORM = (
    "terraform -chdir={module} init -backend=false -input=false -lockfile=readonly"
)
TERRAFORM_INIT_MISSES = (
    "terraform -chdir={module} init -backend=false -input=false -lockfile=readonly -upgrade",
    "terraform -chdir={module} init -backend=false -input=false -upgrade",
    "terraform -chdir={module} init -backend=false -input=false",
    "terraform -chdir={module} init -backend=false -input=false -lockfile=readonly x",
    "terraform -chdir={module} init",
    "terraform init -backend=false -input=false -lockfile=readonly",
)
# 0164: a package manager running an interpreter meets the interpreter rule.
INTERPRETER_BINS = (
    "pnpm exec node -e 1",
    "pnpm exec node t.js",
    "pnpm exec -- node t.js",
    "pnpm node t.js",
    "npx node t.js",
    "pnpm exec bash -c ls",
    "pnpm exec python3 -c 1",
    "yarn node -e 1",
    "bun -e 1",
    "bun --eval=1",
    "bun -p 1",
    "bun x.js",
    "bun ./scripts/x.ts",
    "bun repl",
    "yarn bun x.js",
    "pnpm exec bun -e 1",
)
# 0164: download-and-run forms stay with the operator.
PACKAGE_DOWNLOADS = (
    "pnpm dlx cowsay",
    "yarn dlx cowsay",
    "bunx cowsay",
    "bun x cowsay",
    "npm exec cowsay",
    "npm x cowsay",
    "npx -y cowsay",
    "npx --yes cowsay",
    "npx --yes=true vitest run",
    "npx vitest run",
    "npx --no-install --yes cowsay",
    "uvx ruff",
    "uv tool run ruff",
    "pipx run black",
    "deno run https://deno.land/std/x.ts",
)
# 0164: package installs stay with the operator, through any wrapper.
PACKAGE_INSTALL_CMDS = (
    "pnpm install",
    "pnpm i",
    "pnpm add vite",
    "pnpm update",
    "pnpm --filter web install",
    "npm install",
    "npm i -D vitest",
    "npm ci",
    "npm update",
    "yarn",
    "yarn add three",
    "yarn install --frozen-lockfile",
    "bun install",
    "bun add rapier",
    "timeout 60 pnpm install",
    "pnpm exec pnpm install",
    "pnpm exec npm install",
    "pnpm exec -- yarn add three",
    "corepack pnpm install",
    "corepack install",
    "corepack enable",
    "npm install-test",
    "npm it",
    "npm cit",
    "npm clean-install",
    "npm in",
    "npm isntall",
    "npm ins",
    "npm inst",
    "npm up",
    "npm upgrade",
    "pnpm up",
    "pnpm upgrade",
    "yarn up",
    "yarn upgrade",
    "pnpm fetch",
    "pnpm import",
)
# 0196: installs of the other managers; refused bare and wrapped for every agent.
INSTALL_GATE_CMDS = (
    "pip install requests",
    "python3 -m pip install -r requirements.txt",
    "uv add httpx",
    "uv sync",
    "poetry install",
    "cargo add serde",
    "go get golang.org/x/text",
    "gem install rails",
    "bundle install",
    "composer require monolog/monolog",
    "terraform init -upgrade",
)
# H2, issue 87: Python run inside the wrapper; each opens an AF_UNIX socket() the filter refuses.
UNIX_SOCKETS = (
    "import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
    "import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)",
    "import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)",
    "import socket\nsocket.socket(1, socket.SOCK_STREAM)",
    "import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\n"
    "assert libc.socket(1, 1, 0) == -1\nraise PermissionError(ctypes.get_errno(), 'socket')",
)
# H2, issue 86: test commands refused, wrapped or bare, on a kernel that cannot hold the rules.
UNUSABLE_KERNEL = (
    "python3 -m pytest -q",
    "pytest -q",
    "make test",
    "{wrap} python3 -m pytest -q",
)


def assert_store_read_denied(agent: str, template: str, **fields: object) -> None:
    # W1.4: the one body of every "Bash read into a credential store is denied" row.
    assert_denied(_cred(agent, "Bash", command=template.format(**fields)), CREDENTIAL)
