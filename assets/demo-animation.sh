#!/bin/bash
# mcp-redteam v0.4.1 terminal demo animation
# Simulates: mcp-redteam scan ./demo-server --no-llm --no-config
# Record with VHS: vhs assets/demo.tape

RESET="\033[0m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
DIM="\033[2m"
BOLD="\033[1m"
WHITE="\033[1;37m"

clear

sleep 0.3

# Show the command prompt
echo -ne "${DIM}\$${RESET} "
sleep 0.3

# Type the command character by character
cmd="mcp-redteam scan ./demo-server --no-llm"
for (( i=0; i<${#cmd}; i++ )); do
  echo -ne "${cmd:$i:1}"
  sleep 0.03
done
echo ""
sleep 0.4

# Phase 0: Config validation
echo -e "${BOLD}${CYAN}Phase 0:${RESET} Config validation..."
sleep 0.3
echo -e "  3 config issues found"
sleep 0.2

# Phase 1: Semgrep
echo -e "${BOLD}${CYAN}Phase 1:${RESET} Semgrep analysis..."
sleep 0.6
echo -e "  25 rules, 1 file scanned"
sleep 0.2
echo -e "  ${WHITE}7 code findings${RESET}"
sleep 0.3

# Audit history delta
echo -e "  ${GREEN}fixed: 2${RESET}  ${RED}new: 3${RESET}  confirmed: 4  risk: 75 -> ${RED}100${RESET}"
sleep 0.4

# Header
echo ""
echo -e "${BOLD}mcp-redteam${RESET} v0.4.1  ${DIM}./demo-server${RESET}"
echo ""
sleep 0.3

# Table header
echo -e "${DIM}┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${RESET}"
echo -e "${DIM}┃${RESET}${BOLD} Severity   ${DIM}┃${RESET}${BOLD} Rule     ${DIM}┃${RESET}${BOLD} File:Line                        ${DIM}┃${RESET}${BOLD} Title                                      ${DIM}┃${RESET}"
echo -e "${DIM}┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩${RESET}"

# Findings — each row appears with a small delay
rows=(
  "${RED}CRITICAL   ${DIM}│${RESET} MRT001   ${DIM}│${RESET} server.py:19                     ${DIM}│${RESET} Shell Injection                     "
  "${YELLOW}HIGH       ${DIM}│${RESET} MRT003   ${DIM}│${RESET} server.py:31                     ${DIM}│${RESET} SSRF                                "
  "${YELLOW}HIGH       ${DIM}│${RESET} MRT002   ${DIM}│${RESET} server.py:25                     ${DIM}│${RESET} Path Traversal                      "
  "${YELLOW}HIGH       ${DIM}│${RESET} MRT005   ${DIM}│${RESET} server.py:12                     ${DIM}│${RESET} Hardcoded Secret                    "
  "${CYAN}MEDIUM     ${DIM}│${RESET} MRT023   ${DIM}│${RESET} server.py:19                     ${DIM}│${RESET} No Timeout Subprocess               "
  "${CYAN}MEDIUM     ${DIM}│${RESET} MRT022   ${DIM}│${RESET} server.py:31                     ${DIM}│${RESET} No Timeout HTTP                     "
  "${DIM}INFO       ${DIM}│${RESET} MRT006   ${DIM}│${RESET} server.py:35                     ${DIM}│${RESET} Stdout Pollution                    "
)

for row in "${rows[@]}"; do
  echo -e "${DIM}│${RESET} ${row}${DIM}│${RESET}"
  sleep 0.15
done

echo -e "${DIM}└────────────┴──────────┴──────────────────────────────────┴────────────────────────────────────────────┘${RESET}"
sleep 0.3

# Summary
echo ""
echo -e "${BOLD}7 findings${RESET} (${RED}1 critical${RESET}, ${YELLOW}3 high${RESET}, ${CYAN}2 medium${RESET}, ${DIM}1 info${RESET})"
echo -e "Risk score: ${RED}${BOLD}100/100${RESET}"
echo ""
sleep 1.5
