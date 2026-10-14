#!/bin/bash

# Apne project ka naam yahan likhein
SESSION_NAME="static_scanner"

# 1. Check karein agar session pehle se active hai toh seedha wahan chale jayein
tmux has-session -t $SESSION_NAME 2>/dev/null

if [ $? -eq 0 ]; then
    echo "Session pehle se chal raha hai. Attach ho rahe hain..."
    tmux attach-session -t $SESSION_NAME
    exit 0
fi

# 2. Agar session nahi hai, toh naya background session banayein
tmux new-session -d -s $SESSION_NAME

# 3. Pehle pane mein khud hi venv activate ho aur server chal jaye
tmux send-keys -t $SESSION_NAME "source .venv/bin/activate && uvicorn main:app --reload" C-m

# 4. Screen ko Right/Left split karein
tmux split-window -h -t $SESSION_NAME

# 5. Doosre pane mein bhi venv activate karke ready rakhein (Git ya DB ke liye)
tmux send-keys -t $SESSION_NAME "source .venv/bin/activate" C-m

# 6. Poora setup screen par samne le aayein
tmux attach-session -t $SESSION_NAME