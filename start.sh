#!/bin/bash
# start.sh - launches the proxy, API server, and HUD together.
# Requires ./setup.sh to have been run first.
set -e
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "No venv found - run ./setup.sh first."
    exit 1
fi

if ! command -v tmux &> /dev/null; then
    echo "tmux is not installed. Install it for a one-command launch:"
    echo "    sudo apt install tmux"
    echo ""
    echo "Or start each piece manually in its own terminal:"
    echo "  1) cd proxy && ../venv/bin/mitmdump -s addon.py -p 8081"
    echo "  2) cd api   && ../venv/bin/uvicorn server:app --port 8090"
    echo "  3) cd hud   && npm start"
    exit 1
fi

SESSION="glacier"

# Kill any previous session with the same name so re-running this script
# doesn't stack up duplicate panes.
tmux kill-session -t "$SESSION" 2>/dev/null || true

tmux new-session -d -s "$SESSION" -n main
tmux send-keys -t "$SESSION:main" "cd $(pwd)/proxy && ../venv/bin/mitmdump -s addon.py -p 8081" Enter

tmux split-window -h -t "$SESSION:main"
tmux send-keys -t "$SESSION:main" "cd $(pwd)/api && ../venv/bin/uvicorn server:app --port 8090" Enter

tmux split-window -v -t "$SESSION:main"
tmux send-keys -t "$SESSION:main" "cd $(pwd)/hud && npm start" Enter

echo "Started proxy, API, and HUD in tmux session '$SESSION'."
echo "Attaching now - use Ctrl+B then D to detach without stopping anything."
sleep 1
tmux attach -t "$SESSION"
