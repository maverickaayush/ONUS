#!/bin/bash

REPO="/home/aayush-yadav/vapt-tool"
cd "$REPO" || exit 1

echo "Watching $REPO..."

while true; do
inotifywait -qq -r -e modify,create,delete,move "$REPO"

```
sleep 10

# Skip if nothing changed
[[ -z $(git status --porcelain) ]] && continue

git add .
git commit -m "Auto update: $(date '+%F %T')" || continue
git push origin main
```

done
