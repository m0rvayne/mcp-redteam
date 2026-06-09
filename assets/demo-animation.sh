#!/bin/bash
# mcp-redteam terminal demo animation
# Record with: asciinema rec demo.cast / or Kap for GIF

RESET="\033[0m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
DIM="\033[2m"
BOLD="\033[1m"
WHITE="\033[1;37m"

clear

sleep 0.5

# Phase 0 — Config scan
echo -e "${DIM}$ /mcp-redteam${RESET}"
sleep 0.8
echo ""
echo -e "${CYAN}[Phase 0] Config Validation${RESET}"
sleep 0.4

configs=(
  "claude mcp list              ...10 servers found"
  "scope conflicts              ...1 duplicate detected"
  "credential exposure          ...0 secrets in git"
  "supply chain                 ...2 unpinned packages"
  "orphaned processes           ...0 zombies"
)

for line in "${configs[@]}"; do
  echo -ne "  checking ${line%%...*}"
  sleep 0.3
  echo -e " ${GREEN}${line##*...}${RESET}"
  sleep 0.15
done

sleep 0.3
echo -e "  ${YELLOW}[!] 2 HIGH: unpinned npx packages${RESET}"
echo -e "  ${YELLOW}[!] 1 MEDIUM: scope conflict in fathom${RESET}"
sleep 0.6

# Discovery
echo ""
echo -e "${CYAN}[Discovery] Locating source code...${RESET}"
sleep 0.4

servers=("youtube" "trello" "google-drive" "fathom" "instagram" "mindnode" "telegram" "apple-reminders" "google-sheets" "notebooklm" "meeting-transcript")

for s in "${servers[@]}"; do
  echo -ne "  ${DIM}found${RESET} ${WHITE}${s}${RESET}"
  sleep 0.12
  echo ""
done

sleep 0.3
echo -e "  ${BOLD}11 servers, 287 tools${RESET}"
sleep 0.5

# Phase 1 — Agents spawn
echo ""
echo -e "${CYAN}[Phase 1] Spawning agents...${RESET}"
sleep 0.3

echo -e "  ${DIM}11 agents launched in parallel${RESET}"
sleep 0.4

# ASCII art - agent breaking servers
echo ""
echo -e "    ${WHITE}O${RESET}"
echo -e "   ${WHITE}/|\\${RESET}${RED}>${RESET} ═══╗"
echo -e "   ${WHITE}/ \\${RESET}    ╠═══ ${DIM}[${RESET}${WHITE} trello    ${RESET}${DIM}]${RESET} ${RED}<< CRITICAL >>${RESET} API key in .env"
echo -e "          ╠═══ ${DIM}[${RESET}${WHITE} instagram ${RESET}${DIM}]${RESET} ${RED}<< CRITICAL >>${RESET} cookies plaintext"
echo -e "          ╠═══ ${DIM}[${RESET}${WHITE} youtube   ${RESET}${DIM}]${RESET} ${GREEN}<< OK >>${RESET}"
echo -e "          ╠═══ ${DIM}[${RESET}${WHITE} mindnode  ${RESET}${DIM}]${RESET} ${RED}<< CRITICAL >>${RESET} AppleScript injection"
echo -e "          ╚═══ ${DIM}[${RESET}${WHITE} fathom    ${RESET}${DIM}]${RESET} ${YELLOW}<< HIGH >>${RESET} blocking calls"
sleep 0.8

# Findings appear
echo ""
echo -e "  ${DIM}agents reporting...${RESET}"
sleep 0.3

findings=(
  "${RED}[CRITICAL]${RESET} trello: API key in plaintext .env file"
  "${RED}[CRITICAL]${RESET} instagram: session cookie stored world-readable (644)"
  "${RED}[CRITICAL]${RESET} mindnode: AppleScript injection via unescaped clipboard"
  "${RED}[CRITICAL]${RESET} google-sheets: OAuth token path traversal"
  "${RED}[CRITICAL]${RESET} google-drive: credential leak in error handler"
  "${YELLOW}[HIGH]${RESET}     fathom: blocking sync calls freeze event loop"
  "${YELLOW}[HIGH]${RESET}     trello: 55 tools — over-privileged server"
  "${YELLOW}[HIGH]${RESET}     youtube: no signal handling (SIGTERM ignored)"
  "${YELLOW}[HIGH]${RESET}     instagram: no .gitignore for cookies.txt"
)

for f in "${findings[@]}"; do
  echo -e "  $f"
  sleep 0.25
done

echo -e "  ${DIM}...and 152 more findings${RESET}"
sleep 0.6

# Phase 2 — Chain analysis
echo ""
echo -e "${CYAN}[Phase 2] Cross-server chain analysis${RESET}"
sleep 0.4
echo -e "  ${RED}Chain 1:${RESET} trello API key -> google-drive credential relay"
sleep 0.3
echo -e "  ${RED}Chain 2:${RESET} instagram cookie -> path disclosure -> targeted access"
sleep 0.3
echo -e "  ${GREEN}3 chains validated, 2 rejected as false positives${RESET}"
sleep 0.6

# Report
echo ""
echo -e "${CYAN}[Report] Generating...${RESET}"
sleep 0.5
echo -e "  ${GREEN}saved: reports/mcp-redteam-2026-06-09.html${RESET}"
sleep 0.3

# Summary box
echo ""
echo -e "  ${DIM}┌──────────────────────────────────────────┐${RESET}"
echo -e "  ${DIM}│${RESET}  ${BOLD}11 servers${RESET} audited, ${BOLD}287 tools${RESET} tested     ${DIM}│${RESET}"
echo -e "  ${DIM}│${RESET}                                          ${DIM}│${RESET}"
echo -e "  ${DIM}│${RESET}  ${RED}CRITICAL  5${RESET}   ${YELLOW}HIGH  12${RESET}   MEDIUM  41    ${DIM}│${RESET}"
echo -e "  ${DIM}│${RESET}                                          ${DIM}│${RESET}"
echo -e "  ${DIM}│${RESET}  ${GREEN}\"fix it\" to apply remediations${RESET}          ${DIM}│${RESET}"
echo -e "  ${DIM}└──────────────────────────────────────────┘${RESET}"
echo ""
