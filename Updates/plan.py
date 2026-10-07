import json
import os
import sys
plan = json.load(open(sys.argv[1]))
for record in plan["packages"]:
    sys.stdout.buffer.write(os.fsencode(record["path"]) + b"\0")
